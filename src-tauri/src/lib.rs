use std::sync::Mutex;

use domain::{
    Collection, CurlBundle, Draft, Exchange, ProxyConfig, ProxyStatus, ReplayProxyMode,
    ReplayResult, ResponseDiff, SavedFilter, Session, UpstreamProxy,
};
use serde::{Deserialize, Serialize};
use storage::Store;
use tauri::{AppHandle, Emitter, Manager, State};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfigView {
    pub host: String,
    pub port: u16,
    pub ca_loaded: bool,
    pub ca_source: String,
    pub upstream_url: Option<String>,
    pub upstream_username: Option<String>,
    pub upstream_has_password: bool,
    pub lan_ip: Option<String>,
    pub system_proxy: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub status: ProxyStatus,
    pub config: AppConfigView,
    pub sessions: Vec<Session>,
    pub current_session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayOutcome {
    pub result: ReplayResult,
    pub diff: ResponseDiff,
}

struct Inner {
    store: Store,
    config: AppConfigView,
    ca_cert: Option<String>,
    ca_key: Option<String>,
    upstream: Option<UpstreamProxy>,
    proxy: Option<proxy::ProxyHandle>,
    current_session: Option<Session>,
}

pub struct AppState {
    inner: Mutex<Inner>,
    events: tokio::sync::broadcast::Sender<Exchange>,
    lifecycle: tokio::sync::Mutex<()>,
}

impl AppState {
    fn status(inner: &Inner) -> ProxyStatus {
        match &inner.proxy {
            Some(handle) => handle.status(),
            None => ProxyStatus {
                running: false,
                host: inner.config.host.clone(),
                port: inner.config.port,
                captured: 0,
                last_error: None,
            },
        }
    }

    fn snapshot(&self) -> Result<Snapshot, String> {
        let inner = self.inner.lock().map_err(|_| "state lock poisoned")?;
        let sessions = inner.store.list_sessions().map_err(|e| e.to_string())?;
        Ok(Snapshot {
            status: Self::status(&inner),
            config: inner.config.clone(),
            sessions,
            current_session_id: inner.current_session.as_ref().map(|s| s.id.clone()),
        })
    }

    fn persist_config(&self, inner: &Inner) -> Result<(), String> {
        inner
            .store
            .set_setting("proxy.host", &inner.config.host)
            .map_err(|e| e.to_string())?;
        inner
            .store
            .set_setting("proxy.port", &inner.config.port.to_string())
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[tauri::command]
fn get_snapshot(state: State<'_, AppState>) -> Result<Snapshot, String> {
    state.snapshot()
}

fn candidate_ca_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    if let Ok(explicit) = std::env::var("MITM_PROXY_CA") {
        if !explicit.trim().is_empty() {
            paths.push(std::path::PathBuf::from(explicit));
        }
    }
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        paths.push(
            std::path::Path::new(&home)
                .join(".mitmproxy")
                .join("mitmproxy-ca.pem"),
        );
    }
    paths
}

fn load_ca_bundle(path: &std::path::Path) -> Result<(String, String), String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let material = security::split_pem_bundle(&raw).map_err(|e| e.to_string())?;
    let cert = security::normalize_pem(&material.cert_pem);
    let key = security::normalize_private_key_pem(&material.key_pem).map_err(|e| e.to_string())?;
    security::validate_ca_material(&cert, &key).map_err(|e| e.to_string())?;
    proxy::CertificateAuthority::from_pem(&cert, &key).map_err(|e| e.to_string())?;
    Ok((cert, key))
}

fn discover_mitmproxy_ca() -> Option<(String, String, String)> {
    for path in candidate_ca_paths() {
        if !path.is_file() {
            continue;
        }
        match load_ca_bundle(&path) {
            Ok((cert, key)) => {
                return Some((cert, key, "mitmproxy CA".to_string()));
            }
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "CA candidate rejected")
            }
        }
    }
    None
}

#[tauri::command]
async fn import_ca(
    state: State<'_, AppState>,
    cert_pem: String,
    key_pem: String,
) -> Result<Snapshot, String> {
    let _lifecycle = state.lifecycle.lock().await;
    let cert = security::normalize_pem(&cert_pem);
    let key = security::normalize_private_key_pem(&key_pem).map_err(|e| e.to_string())?;
    security::validate_ca_material(&cert, &key).map_err(|e| e.to_string())?;
    proxy::CertificateAuthority::from_pem(&cert, &key).map_err(|e| e.to_string())?;

    {
        let mut inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        if inner.proxy.is_some() {
            return Err("Stop the proxy before changing the CA".into());
        }
        inner
            .store
            .set_setting("ca.cert", &cert)
            .map_err(|e| e.to_string())?;
        inner
            .store
            .set_setting("ca.key", &key)
            .map_err(|e| e.to_string())?;
        inner
            .store
            .set_setting("ca.source", "imported CA")
            .map_err(|e| e.to_string())?;
        inner.ca_cert = Some(cert);
        inner.ca_key = Some(key);
        inner.config.ca_loaded = true;
        inner.config.ca_source = "imported CA".into();
    }
    state.snapshot()
}

#[tauri::command]
async fn discover_ca(state: State<'_, AppState>) -> Result<Snapshot, String> {
    let _lifecycle = state.lifecycle.lock().await;
    let discovered = discover_mitmproxy_ca().ok_or_else(|| {
        "No mitmproxy CA found. Set MITM_PROXY_CA or place mitmproxy-ca.pem in ~/.mitmproxy."
            .to_string()
    })?;
    let (cert, key, source) = discovered;
    {
        let mut inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        if inner.proxy.is_some() {
            return Err("Stop the proxy before changing the CA".into());
        }
        inner
            .store
            .set_setting("ca.cert", &cert)
            .map_err(|e| e.to_string())?;
        inner
            .store
            .set_setting("ca.key", &key)
            .map_err(|e| e.to_string())?;
        inner
            .store
            .set_setting("ca.source", &source)
            .map_err(|e| e.to_string())?;
        inner.ca_cert = Some(cert);
        inner.ca_key = Some(key);
        inner.config.ca_loaded = true;
        inner.config.ca_source = source;
    }
    state.snapshot()
}

fn primary_lan_ip() -> Option<String> {
    let mut candidates: Vec<(u8, std::net::Ipv4Addr)> = Vec::new();
    if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in interfaces {
            let lower = name.to_ascii_lowercase();
            if lower.contains("vethernet")
                || lower.contains("wsl")
                || lower.contains("hyper-v")
                || lower.contains("virtualbox")
                || lower.contains("vmware")
                || lower.contains("tailscale")
                || lower.contains("zerotier")
            {
                continue;
            }
            if let std::net::IpAddr::V4(v4) = ip {
                if v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
                    continue;
                }
                let octets = v4.octets();
                let rank = if octets[0] == 192 && octets[1] == 168 {
                    0
                } else if octets[0] == 10 {
                    1
                } else if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                    2
                } else {
                    3
                };
                candidates.push((rank, v4));
            }
        }
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    candidates.first().map(|(_, ip)| ip.to_string())
}

#[tauri::command]
fn install_ca_on_pc(state: State<'_, AppState>) -> Result<String, String> {
    let cert = {
        let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        inner
            .ca_cert
            .clone()
            .ok_or_else(|| "CA is not ready yet".to_string())?
    };
    #[cfg(windows)]
    {
        use std::io::Write;

        let der = proxy::ca_der(&cert).map_err(|e| e.to_string())?;
        let path = std::env::temp_dir().join(format!("relay-ca-{}.cer", uuid::Uuid::new_v4()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("cannot create temporary certificate file: {e}"))?;
        if let Err(err) = file.write_all(&der) {
            let _ = std::fs::remove_file(&path);
            return Err(format!("cannot write temporary certificate file: {err}"));
        }
        drop(file);
        let output = match std::process::Command::new("certutil")
            .args(["-user", "-addstore", "-f", "Root"])
            .arg(&path)
            .output()
        {
            Ok(output) => output,
            Err(err) => {
                let _ = std::fs::remove_file(&path);
                return Err(err.to_string());
            }
        };
        let _ = std::fs::remove_file(&path);
        if output.status.success() {
            Ok("Certificate installed for the current Windows user".into())
        } else {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let detail = if !stderr.is_empty() { stderr } else { stdout };
            Err(if detail.is_empty() {
                "Windows cancelled or blocked the certificate installation".into()
            } else {
                detail
            })
        }
    }
    #[cfg(not(windows))]
    {
        let _ = cert;
        Err("Automatic installation is only wired for Windows".into())
    }
}

#[tauri::command]
fn open_mitm_it() -> Result<(), String> {
    #[cfg(windows)]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", "http://mitm.it"])
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err("Opening mitm.it is only wired for Windows".into())
    }
}

#[cfg(windows)]
fn notify_system_proxy_changed() {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    unsafe {
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }
}

#[cfg(not(windows))]
fn notify_system_proxy_changed() {}

#[cfg(windows)]
fn internet_settings_key() -> Result<winreg::RegKey, String> {
    use winreg::enums::HKEY_CURRENT_USER;
    winreg::RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
        .map(|(key, _)| key)
        .map_err(|e| e.to_string())
}

fn enable_system_proxy(store: &Store, port: u16) -> Result<(), String> {
    #[cfg(windows)]
    {
        let key = internet_settings_key()?;
        let active = store
            .get_setting("system_proxy.active")
            .ok()
            .flatten()
            .unwrap_or_default();
        if active != "1" {
            let enabled = key.get_value::<u32, _>("ProxyEnable").unwrap_or(0);
            let server = key.get_value::<String, _>("ProxyServer").ok();
            let override_rules = key.get_value::<String, _>("ProxyOverride").ok();
            let auto_config = key.get_value::<String, _>("AutoConfigURL").ok();
            store
                .set_setting("system_proxy.original_enable", &enabled.to_string())
                .map_err(|e| e.to_string())?;
            store
                .set_setting(
                    "system_proxy.original_auto_config_present",
                    if auto_config.is_some() { "1" } else { "0" },
                )
                .map_err(|e| e.to_string())?;
            store
                .set_setting(
                    "system_proxy.original_auto_config",
                    auto_config.as_deref().unwrap_or_default(),
                )
                .map_err(|e| e.to_string())?;
            store
                .set_setting(
                    "system_proxy.original_server_present",
                    if server.is_some() { "1" } else { "0" },
                )
                .map_err(|e| e.to_string())?;
            store
                .set_setting(
                    "system_proxy.original_server",
                    server.as_deref().unwrap_or_default(),
                )
                .map_err(|e| e.to_string())?;
            store
                .set_setting(
                    "system_proxy.original_override_present",
                    if override_rules.is_some() { "1" } else { "0" },
                )
                .map_err(|e| e.to_string())?;
            store
                .set_setting(
                    "system_proxy.original_override",
                    override_rules.as_deref().unwrap_or_default(),
                )
                .map_err(|e| e.to_string())?;
            store
                .set_setting("system_proxy.active", "1")
                .map_err(|e| e.to_string())?;
        }
        key.set_value("ProxyEnable", &1u32)
            .map_err(|e| e.to_string())?;
        key.set_value("ProxyServer", &format!("127.0.0.1:{port}"))
            .map_err(|e| e.to_string())?;
        key.set_value("ProxyOverride", &"<local>")
            .map_err(|e| e.to_string())?;
        // A PAC file would otherwise take precedence over ProxyServer.
        let _ = key.delete_value("AutoConfigURL");
        notify_system_proxy_changed();
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (store, port);
        Err("System proxy is only wired for Windows".into())
    }
}

fn restore_system_proxy(store: &Store) -> Result<(), String> {
    #[cfg(windows)]
    {
        let active = store
            .get_setting("system_proxy.active")
            .ok()
            .flatten()
            .unwrap_or_default();
        if active != "1" {
            return Ok(());
        }
        let key = internet_settings_key()?;
        let enabled = store
            .get_setting("system_proxy.original_enable")
            .ok()
            .flatten()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        key.set_value("ProxyEnable", &enabled)
            .map_err(|e| e.to_string())?;
        let server_present = store
            .get_setting("system_proxy.original_server_present")
            .ok()
            .flatten()
            .unwrap_or_default()
            == "1";
        if server_present {
            let server = store
                .get_setting("system_proxy.original_server")
                .ok()
                .flatten()
                .unwrap_or_default();
            key.set_value("ProxyServer", &server)
                .map_err(|e| e.to_string())?;
        } else {
            let _ = key.delete_value("ProxyServer");
        }
        let override_present = store
            .get_setting("system_proxy.original_override_present")
            .ok()
            .flatten()
            .unwrap_or_default()
            == "1";
        if override_present {
            let rules = store
                .get_setting("system_proxy.original_override")
                .ok()
                .flatten()
                .unwrap_or_default();
            key.set_value("ProxyOverride", &rules)
                .map_err(|e| e.to_string())?;
        } else {
            let _ = key.delete_value("ProxyOverride");
        }
        let auto_config_present = store
            .get_setting("system_proxy.original_auto_config_present")
            .ok()
            .flatten()
            .unwrap_or_default()
            == "1";
        if auto_config_present {
            let value = store
                .get_setting("system_proxy.original_auto_config")
                .ok()
                .flatten()
                .unwrap_or_default();
            key.set_value("AutoConfigURL", &value)
                .map_err(|e| e.to_string())?;
        } else {
            let _ = key.delete_value("AutoConfigURL");
        }
        store
            .set_setting("system_proxy.active", "0")
            .map_err(|e| e.to_string())?;
        notify_system_proxy_changed();
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = store;
        Err("System proxy is only wired for Windows".into())
    }
}

#[tauri::command]
fn set_system_proxy(state: State<'_, AppState>, enabled: bool) -> Result<Snapshot, String> {
    {
        let mut inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        if enabled {
            let port = inner
                .proxy
                .as_ref()
                .map(|handle| handle.status().port)
                .ok_or_else(|| "Start the proxy before enabling the system proxy".to_string())?;
            enable_system_proxy(&inner.store, port)?;
            inner.config.system_proxy = true;
        } else {
            restore_system_proxy(&inner.store)?;
            inner.config.system_proxy = false;
        }
    }
    state.snapshot()
}

#[tauri::command]
async fn set_upstream(
    state: State<'_, AppState>,
    url: String,
    username: String,
    password: String,
) -> Result<Snapshot, String> {
    let _lifecycle = state.lifecycle.lock().await;
    let url = url.trim().to_string();
    let mut inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    if inner.proxy.is_some() {
        return Err("Stop the proxy before changing the upstream proxy".into());
    }
    if url.is_empty() {
        inner.upstream = None;
        let _ = inner.store.set_setting("upstream.url", "");
        let _ = inner.store.set_setting("upstream.username", "");
        let _ = inner.store.set_setting("upstream.password", "");
        inner.config.upstream_url = None;
        inner.config.upstream_username = None;
        inner.config.upstream_has_password = false;
        drop(inner);
        return state.snapshot();
    }
    proxy::validate_upstream_url(&url).map_err(|e| e.to_string())?;
    let username = {
        let trimmed = username.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    };
    let password = if password.is_empty() {
        inner
            .upstream
            .as_ref()
            .filter(|existing| existing.username == username)
            .and_then(|existing| existing.password.clone())
    } else {
        Some(password)
    };
    let upstream = UpstreamProxy {
        url: url.clone(),
        username: username.clone(),
        password: password.clone(),
    };
    inner
        .store
        .set_setting("upstream.url", &url)
        .map_err(|e| e.to_string())?;
    inner
        .store
        .set_setting("upstream.username", username.as_deref().unwrap_or(""))
        .map_err(|e| e.to_string())?;
    inner
        .store
        .set_setting("upstream.password", password.as_deref().unwrap_or(""))
        .map_err(|e| e.to_string())?;
    inner.upstream = Some(upstream);
    inner.config.upstream_url = Some(url);
    inner.config.upstream_username = username;
    inner.config.upstream_has_password = password.is_some();
    drop(inner);
    state.snapshot()
}

#[tauri::command]
async fn check_upstream(state: State<'_, AppState>) -> Result<proxy::UpstreamCheck, String> {
    let upstream = {
        let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        inner
            .upstream
            .clone()
            .ok_or_else(|| "No upstream proxy configured".to_string())?
    };
    proxy::check_upstream(&upstream)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_config(
    state: State<'_, AppState>,
    host: String,
    port: u16,
) -> Result<Snapshot, String> {
    let _lifecycle = state.lifecycle.lock().await;
    {
        let mut inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        if inner.proxy.is_some() {
            return Err("Stop the proxy before changing host or port".into());
        }
        if host.trim().is_empty() {
            return Err("Host cannot be empty".into());
        }
        if port == 0 {
            return Err("Port must be between 1 and 65535".into());
        }
        inner.config.host = host;
        inner.config.port = port;
        state.persist_config(&inner)?;
    }
    state.snapshot()
}

#[tauri::command]
async fn start_proxy(
    app: AppHandle,
    state: State<'_, AppState>,
    host: String,
    port: u16,
) -> Result<Snapshot, String> {
    let _lifecycle = state.lifecycle.lock().await;
    let (cert, key, session, upstream) = {
        let mut inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        if inner.proxy.is_some() {
            return Err("Proxy is already running".into());
        }
        let cert = inner.ca_cert.clone().ok_or_else(|| {
            "Import a CA certificate and key before starting the proxy".to_string()
        })?;
        let key = inner.ca_key.clone().ok_or_else(|| {
            "Import a CA certificate and key before starting the proxy".to_string()
        })?;
        if host.trim().is_empty() {
            return Err("Host cannot be empty".into());
        }
        if port == 0 {
            return Err("Port must be between 1 and 65535".into());
        }
        inner.config.host = host.clone();
        inner.config.port = port;

        let now = chrono::Utc::now();
        let name = format!("Capture · {}", chrono::Local::now().format("%b %d, %H:%M"));
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            started_at: now.to_rfc3339(),
            ended_at: None,
            exchange_count: 0,
        };
        inner
            .store
            .upsert_session(&session)
            .map_err(|e| e.to_string())?;
        inner
            .store
            .set_setting("last.session", &session.id)
            .map_err(|e| e.to_string())?;
        inner.current_session = Some(session.clone());
        state.persist_config(&inner)?;
        (cert, key, session, inner.upstream.clone())
    };

    let config = ProxyConfig {
        host,
        port,
        ca_cert_pem: cert,
        ca_key_pem: key,
        upstream,
    };
    let handle =
        match proxy::ProxyHandle::start(config, session.id.clone(), state.events.clone()).await {
            Ok(handle) => handle,
            Err(err) => {
                // A failed bind must not leave an empty "live" session behind.
                if let Ok(mut inner) = state.inner.lock() {
                    let _ = inner.store.delete_session(&session.id);
                    let _ = inner.store.set_setting("last.session", "");
                    inner.current_session = None;
                }
                return Err(err.to_string());
            }
        };
    {
        let mut inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        inner.proxy = Some(handle);
    }
    let _ = app.emit("proxy-status", "running");
    state.snapshot()
}

#[tauri::command]
async fn stop_proxy(app: AppHandle, state: State<'_, AppState>) -> Result<Snapshot, String> {
    let _lifecycle = state.lifecycle.lock().await;
    let handle = {
        let mut inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        let handle = inner.proxy.take();
        if let Some(mut session) = inner.current_session.take() {
            session.ended_at = Some(chrono::Utc::now().to_rfc3339());
            if let Ok(count) = inner.store.count_exchanges(&session.id) {
                session.exchange_count = count;
            }
            let _ = inner.store.upsert_session(&session);
            inner.current_session = Some(session);
        }
        handle
    };
    if let Some(handle) = handle {
        handle.shutdown().await;
    }
    {
        let mut inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        if inner.config.system_proxy {
            if let Err(err) = restore_system_proxy(&inner.store) {
                tracing::warn!(error = %err, "failed to restore system proxy");
            }
            inner.config.system_proxy = false;
        }
    }
    let _ = app.emit("proxy-status", "stopped");
    state.snapshot()
}

#[tauri::command]
fn list_exchanges(state: State<'_, AppState>, session_id: String) -> Result<Vec<Exchange>, String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    inner
        .store
        .list_exchanges(&session_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn list_sessions(state: State<'_, AppState>) -> Result<Vec<Session>, String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    inner.store.list_sessions().map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_exchanges(state: State<'_, AppState>, ids: Vec<String>) -> Result<usize, String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    inner
        .store
        .delete_exchanges(&ids)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_sessions(state: State<'_, AppState>) -> Result<Snapshot, String> {
    {
        let mut inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        if inner.proxy.is_some() {
            return Err("Stop the proxy before clearing history".into());
        }
        inner
            .store
            .delete_all_sessions()
            .map_err(|e| e.to_string())?;
        inner.current_session = None;
    }
    state.snapshot()
}

#[tauri::command]
fn delete_session(state: State<'_, AppState>, session_id: String) -> Result<Snapshot, String> {
    {
        let mut inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        let is_live = inner.proxy.is_some()
            && inner
                .current_session
                .as_ref()
                .map(|session| session.id == session_id)
                .unwrap_or(false);
        if is_live {
            return Err("Stop the proxy before deleting the live session".into());
        }
        inner
            .store
            .delete_session(&session_id)
            .map_err(|e| e.to_string())?;
        if inner
            .current_session
            .as_ref()
            .map(|session| session.id == session_id)
            .unwrap_or(false)
        {
            inner.current_session = None;
        }
    }
    state.snapshot()
}

#[tauri::command]
fn get_exchanges(state: State<'_, AppState>, ids: Vec<String>) -> Result<Vec<Exchange>, String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(exchange) = inner.store.get_exchange(&id).map_err(|e| e.to_string())? {
            out.push(exchange);
        }
    }
    Ok(out)
}

#[tauri::command]
fn save_draft(state: State<'_, AppState>, draft: Draft) -> Result<(), String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    inner.store.save_draft(&draft).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_drafts(state: State<'_, AppState>) -> Result<Vec<Draft>, String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    inner.store.list_drafts().map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_draft(state: State<'_, AppState>, draft_id: String) -> Result<(), String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    inner
        .store
        .delete_draft(&draft_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn replay_draft(
    state: State<'_, AppState>,
    original: Exchange,
    draft: Draft,
) -> Result<ReplayOutcome, String> {
    let (proxy_url, ca_cert) = {
        let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
        if inner.config.ca_loaded {
            if let Some(handle) = inner.proxy.as_ref() {
                let status = handle.status();
                let connect_host = match status.host.as_str() {
                    "0.0.0.0" | "::" | "[::]" => "127.0.0.1".to_string(),
                    other if other.contains(':') && !other.starts_with('[') => {
                        format!("[{other}]")
                    }
                    other => other.to_string(),
                };
                (
                    Some(format!("http://{connect_host}:{}", status.port)),
                    inner.ca_cert.clone(),
                )
            } else {
                (None, None)
            }
        } else {
            (None, None)
        }
    };
    let proxy_url = if draft.options.proxy_mode == ReplayProxyMode::AppProxy {
        Some(proxy_url.ok_or_else(|| "Start the proxy before replaying through it".to_string())?)
    } else {
        None
    };
    let result = replay::replay_with_proxy_ca(&draft, proxy_url, ca_cert.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    let diff = replay::diff_responses(&original, &result);
    Ok(ReplayOutcome { result, diff })
}

#[tauri::command]
fn generate_curl(exchange: Exchange, redact: bool) -> CurlBundle {
    curl_export::generate(&exchange, redact)
}

#[tauri::command]
fn generate_curl_draft(draft: Draft, redact: bool) -> CurlBundle {
    curl_export::generate_from_draft(&draft, redact)
}

#[tauri::command]
fn export_har(exchanges: Vec<Exchange>) -> Result<String, String> {
    let masked: Vec<Exchange> = exchanges.iter().map(security::mask_exchange).collect();
    storage::export_har(&masked, &format!("Relay {}", env!("CARGO_PKG_VERSION")))
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn export_har_to_path(exchanges: Vec<Exchange>, path: String) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("No file path selected".into());
    }
    let mut target = std::path::PathBuf::from(trimmed);
    if target.extension().is_none() {
        target.set_extension("har");
    }
    let masked: Vec<Exchange> = exchanges.iter().map(security::mask_exchange).collect();
    let har = storage::export_har(&masked, &format!("Relay {}", env!("CARGO_PKG_VERSION")))
        .map_err(|e| e.to_string())?;
    std::fs::write(&target, har).map_err(|e| format!("Could not write HAR: {e}"))?;
    Ok(target.to_string_lossy().to_string())
}

#[tauri::command]
fn save_collection(state: State<'_, AppState>, collection: Collection) -> Result<(), String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    inner
        .store
        .save_collection(&collection)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn list_collections(state: State<'_, AppState>) -> Result<Vec<Collection>, String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    inner.store.list_collections().map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_collection(state: State<'_, AppState>, collection_id: String) -> Result<(), String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    inner
        .store
        .delete_collection(&collection_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn save_filter(state: State<'_, AppState>, filter: SavedFilter) -> Result<(), String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    inner.store.save_filter(&filter).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_filters(state: State<'_, AppState>) -> Result<Vec<SavedFilter>, String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    inner.store.list_filters().map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_filter(state: State<'_, AppState>, filter_id: String) -> Result<(), String> {
    let inner = state.inner.lock().map_err(|_| "state lock poisoned")?;
    inner
        .store
        .delete_filter(&filter_id)
        .map_err(|e| e.to_string())
}

pub fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "relay=info,proxy=info,warn".into()),
        )
        .try_init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let store = Store::open(data_dir.join("relay.db"))
                .map_err(|e| format!("Failed to open database: {e}"))?;

            let host = store
                .get_setting("proxy.host")
                .ok()
                .flatten()
                .unwrap_or_else(|| "0.0.0.0".into());
            let port = store
                .get_setting("proxy.port")
                .ok()
                .flatten()
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(8888);
            let mut ca_cert = store.get_setting("ca.cert").ok().flatten();
            let mut ca_key = store.get_setting("ca.key").ok().flatten();
            let mut ca_source = store
                .get_setting("ca.source")
                .ok()
                .flatten()
                .unwrap_or_else(|| {
                    if ca_cert.is_some() {
                        "saved CA".to_string()
                    } else {
                        "missing".to_string()
                    }
                });
            if ca_source.starts_with("mitmproxy CA") {
                ca_source = "mitmproxy CA".to_string();
            }
            if ca_cert.is_none() || ca_key.is_none() {
                if let Some((cert, key, source)) = discover_mitmproxy_ca() {
                    let _ = store.set_setting("ca.cert", &cert);
                    let _ = store.set_setting("ca.key", &key);
                    let _ = store.set_setting("ca.source", &source);
                    ca_cert = Some(cert);
                    ca_key = Some(key);
                    ca_source = source;
                }
            }
            if ca_cert.is_none() || ca_key.is_none() {
                match proxy::generate_ca() {
                    Ok((cert, key)) => {
                        let _ = store.set_setting("ca.cert", &cert);
                        let _ = store.set_setting("ca.key", &key);
                        let _ = store.set_setting("ca.source", "Relay generated CA");
                        ca_cert = Some(cert);
                        ca_key = Some(key);
                        ca_source = "Relay generated CA".to_string();
                    }
                    Err(err) => tracing::error!(error = %err, "failed to generate local CA"),
                }
            }
            let ca_loaded = ca_cert.is_some() && ca_key.is_some();

            let upstream_url = store
                .get_setting("upstream.url")
                .ok()
                .flatten()
                .filter(|url| !url.trim().is_empty());
            let upstream_username = store
                .get_setting("upstream.username")
                .ok()
                .flatten()
                .filter(|name| !name.trim().is_empty());
            let upstream_password = store
                .get_setting("upstream.password")
                .ok()
                .flatten()
                .filter(|password| !password.is_empty());
            let upstream = upstream_url.clone().map(|url| UpstreamProxy {
                url,
                username: upstream_username.clone(),
                password: upstream_password.clone(),
            });

            let lan_ip = primary_lan_ip();
            if let Err(err) = restore_system_proxy(&store) {
                tracing::warn!(error = %err, "failed to restore system proxy state");
            }

            let (events, _) = tokio::sync::broadcast::channel::<Exchange>(512);
            let state = AppState {
                inner: Mutex::new(Inner {
                    store,
                    config: AppConfigView {
                        host,
                        port,
                        ca_loaded,
                        ca_source,
                        upstream_url,
                        upstream_username,
                        upstream_has_password: upstream_password.is_some(),
                        lan_ip,
                        system_proxy: false,
                    },
                    ca_cert,
                    ca_key,
                    upstream,
                    proxy: None,
                    current_session: None,
                }),
                events: events.clone(),
                lifecycle: tokio::sync::Mutex::new(()),
            };
            app.manage(state);

            let handle = app.handle().clone();
            let mut receiver = events.subscribe();
            tauri::async_runtime::spawn(async move {
                loop {
                    match receiver.recv().await {
                        Ok(exchange) => {
                            {
                                let state = handle.state::<AppState>();
                                let guard = state.inner.lock();
                                if let Ok(inner) = guard {
                                    let _ = inner.store.insert_exchange(&exchange);
                                }
                            }
                            let _ = handle.emit("exchange", &exchange);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(skipped, "exchange event stream lagged");
                        }
                        Err(_) => break,
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            import_ca,
            discover_ca,
            install_ca_on_pc,
            set_system_proxy,
            open_mitm_it,
            set_upstream,
            check_upstream,
            update_config,
            start_proxy,
            stop_proxy,
            list_exchanges,
            get_exchanges,
            list_sessions,
            clear_sessions,
            delete_session,
            delete_exchanges,
            save_draft,
            list_drafts,
            delete_draft,
            replay_draft,
            generate_curl,
            generate_curl_draft,
            export_har,
            export_har_to_path,
            save_collection,
            list_collections,
            delete_collection,
            save_filter,
            list_filters,
            delete_filter
        ])
        .build(tauri::generate_context!())
        .expect("error while building Relay")
        .run(|app_handle, event| {
            // Restore the Windows proxy on both graceful exit and the earlier
            // exit request, so a cancelled shutdown cannot leave the PC
            // pointing at a dead port.
            if matches!(
                event,
                tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
            ) {
                let state = app_handle.state::<AppState>();
                let guard = state.inner.lock();
                if let Ok(inner) = guard {
                    if inner.config.system_proxy {
                        if let Err(err) = restore_system_proxy(&inner.store) {
                            tracing::warn!(error = %err, "failed to restore system proxy");
                        }
                    }
                }
            }
        });
}
