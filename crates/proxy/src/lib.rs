//! Rust-native HTTP/HTTPS capturing proxy.
//!
//! The proxy accepts plain HTTP requests in absolute-form and HTTPS tunnels via
//! `CONNECT`. HTTPS tunnels are intercepted with leaf certificates generated on
//! demand from an imported certificate authority.
//!
//! WebSocket upgrades are intentionally not proxied; requests carrying an
//! `Upgrade` header are answered with `501 Not Implemented`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use base64::Engine;
use bytes::{Bytes, BytesMut};
use domain::{
    Body, Exchange, Header, KeyValue, ProxyConfig, ProxyStatus, TimingPhase, TimingTone,
    UpstreamProxy,
};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, HOST};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, watch};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};
use url::Url;

/// Maximum number of bytes captured from a request or response body.
///
/// Captured response bodies are already decoded: the upstream client requests
/// and transparently decompresses gzip and brotli content.
pub const BODY_CAP: usize = 8 * 1024 * 1024;
/// Hard limit for a body that is forwarded end to end.
///
/// Captured copies stay capped at [`BODY_CAP`]; this limit only protects the
/// proxy process from buffering an unbounded upload or download.
pub const MAX_FORWARD_BYTES: usize = 32 * 1024 * 1024;
/// Cap on cached per-host leaf certificates.
const LEAF_CACHE_CAP: usize = 512;
/// Maximum number of bytes in the generated raw request/response text.
pub const RAW_CAP: usize = 64 * 1024;

const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("failed to bind proxy listener on {addr}: {source}")]
    Bind {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse CA certificate: {0}")]
    CaCertificate(String),
    #[error("failed to parse CA private key: {0}")]
    CaKey(String),
    #[error("failed to generate leaf certificate for {host}: {message}")]
    Leaf { host: String, message: String },
    #[error("invalid host or authority: {0}")]
    InvalidHost(String),
    #[error("invalid target URL: {0}")]
    InvalidUrl(String),
    #[error("failed to build HTTP client: {0}")]
    Client(String),
    #[error("invalid upstream proxy: {0}")]
    Upstream(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// A certificate authority used to sign per-host leaf certificates.
///
/// The CA certificate and key must be supplied by the caller (for example from
/// the application's own PKI). Generated leaf certificates are cached in memory
/// keyed by host.
pub struct CertificateAuthority {
    issuer: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
    cache: HashMap<String, Arc<ServerConfig>>,
}

impl CertificateAuthority {
    /// Build a CA from an imported PEM certificate and private key.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, ProxyError> {
        ensure_crypto_provider();
        let params = rcgen::CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| ProxyError::CaCertificate(e.to_string()))?;
        let key_pair =
            rcgen::KeyPair::from_pem(key_pem).map_err(|e| ProxyError::CaKey(e.to_string()))?;

        // Re-create a certificate handle carrying the imported CA's subject and
        // key metadata. The DER produced here is not used for issuance; rcgen
        // only needs the issuer subject/key-identifier information, while the
        // signature is created with the imported private key.
        let issuer = params
            .self_signed(&key_pair)
            .map_err(|e| ProxyError::CaCertificate(e.to_string()))?;

        Ok(Self {
            issuer,
            ca_key: key_pair,
            cache: HashMap::new(),
        })
    }

    /// Return a cached rustls server configuration for `host`, generating and
    /// signing a fresh P-256 leaf certificate on a cache miss.
    pub fn leaf_for_host(&mut self, host: &str) -> Result<Arc<ServerConfig>, ProxyError> {
        let cache_key = normalize_host(host);
        if let Some(existing) = self.cache.get(&cache_key) {
            return Ok(existing.clone());
        }

        let san = host.trim_matches(['[', ']']).to_string();
        let mut params =
            rcgen::CertificateParams::new(vec![san.clone()]).map_err(|e| ProxyError::Leaf {
                host: san.clone(),
                message: e.to_string(),
            })?;

        let now = chrono::Utc::now();
        let not_before = now - chrono::Duration::days(1);
        let not_after = now + chrono::Duration::days(365);
        params.not_before = rcgen::date_time_ymd(
            chrono::Datelike::year(&not_before),
            chrono::Datelike::month(&not_before) as u8,
            chrono::Datelike::day(&not_before) as u8,
        );
        params.not_after = rcgen::date_time_ymd(
            chrono::Datelike::year(&not_after),
            chrono::Datelike::month(&not_after) as u8,
            chrono::Datelike::day(&not_after) as u8,
        );
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, san.clone());
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        let ca_key = &self.ca_key;
        let leaf_key = rcgen::KeyPair::generate().map_err(|e| ProxyError::Leaf {
            host: san.clone(),
            message: e.to_string(),
        })?;
        let leaf = params
            .signed_by(&leaf_key, &self.issuer, ca_key)
            .map_err(|e| ProxyError::Leaf {
                host: san.clone(),
                message: e.to_string(),
            })?;

        let certs = vec![CertificateDer::from(leaf.der().to_vec())];
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .map_err(|e| ProxyError::Leaf {
                host: san,
                message: e.to_string(),
            })?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let config = Arc::new(config);
        if self.cache.len() >= LEAF_CACHE_CAP {
            // Bound memory growth when a client CONNECTs to many SNI names.
            self.cache.clear();
        }
        self.cache.insert(cache_key, config.clone());
        Ok(config)
    }

    /// Number of hosts with cached leaf certificates.
    pub fn cached_hosts(&self) -> usize {
        self.cache.len()
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_matches(['[', ']']).to_ascii_lowercase()
}

/// Install the ring crypto provider once so TLS works even when other crates in
/// the workspace also enable the aws-lc-rs feature on rustls.
fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

struct ProxyState {
    client: reqwest::Client,
    direct_client: reqwest::Client,
    ca_cert_pem: String,
    events: broadcast::Sender<Exchange>,
    session_id: String,
    captured: Arc<AtomicUsize>,
    last_error: Arc<Mutex<Option<String>>>,
    ca: Arc<Mutex<CertificateAuthority>>,
    sequence: AtomicU64,
    connections: Arc<tokio::sync::Semaphore>,
    stopped: Arc<AtomicBool>,
}

/// Handle to a running proxy instance.
pub struct ProxyHandle {
    host: String,
    port: u16,
    captured: Arc<AtomicUsize>,
    last_error: Arc<Mutex<Option<String>>>,
    stopped: Arc<AtomicBool>,
    stop: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl ProxyHandle {
    /// Start the proxy.
    ///
    /// `session_id` is attached to every captured [`Exchange`]. Events are sent
    /// on `events` without ever waiting for subscribers.
    pub async fn start(
        config: ProxyConfig,
        session_id: String,
        events: broadcast::Sender<Exchange>,
    ) -> Result<ProxyHandle, ProxyError> {
        ensure_crypto_provider();
        let ca = CertificateAuthority::from_pem(&config.ca_cert_pem, &config.ca_key_pem)?;
        let base_client = || {
            reqwest::Client::builder()
                .use_rustls_tls()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .timeout(Duration::from_secs(60))
        };
        let direct_client = base_client()
            .build()
            .map_err(|e| ProxyError::Client(e.to_string()))?;
        let client = match &config.upstream {
            Some(upstream) if !upstream.url.trim().is_empty() => base_client()
                .proxy(build_upstream_proxy(upstream)?)
                .build()
                .map_err(|e| ProxyError::Client(e.to_string()))?,
            _ => direct_client.clone(),
        };

        let bind_addr = if config.host.contains(':') && !config.host.starts_with('[') {
            format!("[{}]:{}", config.host, config.port)
        } else {
            format!("{}:{}", config.host, config.port)
        };
        let listener = TcpListener::bind((config.host.as_str(), config.port))
            .await
            .map_err(|e| ProxyError::Bind {
                addr: bind_addr.clone(),
                source: e,
            })?;
        let local = listener.local_addr().ok();

        let captured = Arc::new(AtomicUsize::new(0));
        let last_error = Arc::new(Mutex::new(None));
        let stopped = Arc::new(AtomicBool::new(false));
        let state = Arc::new(ProxyState {
            client,
            direct_client,
            ca_cert_pem: config.ca_cert_pem.clone(),
            events,
            session_id,
            captured: captured.clone(),
            last_error: last_error.clone(),
            ca: Arc::new(Mutex::new(ca)),
            sequence: AtomicU64::new(0),
            connections: Arc::new(tokio::sync::Semaphore::new(256)),
            stopped: stopped.clone(),
        });

        let (stop, mut stop_rx) = watch::channel(false);
        let accept_state = state.clone();
        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _peer)) => {
                                let conn_state = accept_state.clone();
                                // Never wait for a permit here: a full connection
                                // table must not block the stop signal.
                                let permit = match conn_state.connections.clone().try_acquire_owned() {
                                    Ok(permit) => permit,
                                    Err(_) => {
                                        debug!("connection limit reached, rejecting client");
                                        drop(stream);
                                        continue;
                                    }
                                };
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    serve_connection(stream, conn_state).await;
                                });
                            }
                            Err(err) => {
                                warn!(error = %err, "proxy accept failed");
                                tokio::time::sleep(Duration::from_millis(20)).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(ProxyHandle {
            host: local.map(|a| a.ip().to_string()).unwrap_or(config.host),
            port: local.map(|a| a.port()).unwrap_or(config.port),
            captured,
            last_error,
            stopped,
            stop,
            join,
        })
    }

    /// Number of exchanges captured so far.
    pub fn captured_count(&self) -> usize {
        self.captured.load(Ordering::Relaxed)
    }

    /// Current proxy status snapshot.
    pub fn status(&self) -> ProxyStatus {
        ProxyStatus {
            running: !self.join.is_finished(),
            host: self.host.clone(),
            port: self.port,
            captured: self.captured_count(),
            last_error: self.last_error.lock().clone(),
        }
    }

    /// Stop accepting connections and wait for the accept loop to finish.
    ///
    /// Already established connections may still be flushing a request, but
    /// they no longer record exchanges once the stop flag is set.
    pub async fn shutdown(self) {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = self.stop.send(true);
        let _ = self.join.await;
    }
}

async fn serve_connection(stream: TcpStream, state: Arc<ProxyState>) {
    let io = TokioIo::new(stream);
    let service = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(handle_request(req, state).await) }
    });
    let mut builder = ConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .header_read_timeout(Duration::from_secs(30))
        .timer(TokioTimer::new());
    if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
        debug!(error = %err, "proxy connection closed");
    }
}

async fn handle_request(req: Request<Incoming>, state: Arc<ProxyState>) -> Response<Full<Bytes>> {
    if state.stopped.load(Ordering::Relaxed) {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "proxy is stopping");
    }
    if req.method() == Method::CONNECT {
        handle_connect(req, state).await
    } else {
        handle_plain(req, state).await
    }
}

async fn handle_plain(req: Request<Incoming>, state: Arc<ProxyState>) -> Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    let body_bytes = match collect_forward(body, MAX_FORWARD_BYTES).await {
        Ok(result) => result,
        Err(err) => {
            state.record_error(err.clone());
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, &err);
        }
    };

    let host_header = parts.headers.get(HOST).and_then(|v| v.to_str().ok());
    let url = match build_forward_url(&parts.uri, host_header) {
        Ok(url) => url,
        Err(err) => {
            state.record_error(err.to_string());
            return error_response(StatusCode::BAD_REQUEST, "invalid proxy target");
        }
    };

    if is_mitm_it_host(url.host_str().unwrap_or_default()) {
        return mitm_it_response(url.path(), &state.ca_cert_pem);
    }

    forward(parts.method, parts.headers, body_bytes, url, state).await
}

async fn handle_connect(req: Request<Incoming>, state: Arc<ProxyState>) -> Response<Full<Bytes>> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            let path = req.uri().path();
            if path.is_empty() {
                None
            } else {
                Some(path.to_string())
            }
        });
    let Some(authority) = authority else {
        state.record_error("CONNECT request without authority".to_string());
        return error_response(StatusCode::BAD_REQUEST, "missing CONNECT authority");
    };

    let (host, port) = parse_host_port(&authority, 443);
    if host.is_empty() {
        state.record_error("CONNECT request with empty host".to_string());
        return error_response(StatusCode::BAD_REQUEST, "missing CONNECT host");
    }

    let server_config = match state.ca.lock().leaf_for_host(&host) {
        Ok(config) => config,
        Err(err) => {
            let message = err.to_string();
            state.record_error(message.clone());
            warn!(host = %host, "failed to generate leaf certificate");
            return error_response(StatusCode::BAD_GATEWAY, "failed to generate certificate");
        }
    };

    let authority = format_authority(&host, port);
    let upgrade = hyper::upgrade::on(req);
    let task_state = state.clone();
    let permit = match task_state.connections.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "too many connections");
        }
    };
    tokio::spawn(async move {
        let _permit = permit;
        let upgraded = match upgrade.await {
            Ok(upgraded) => upgraded,
            Err(err) => {
                debug!(error = %err, "CONNECT upgrade failed");
                return;
            }
        };

        let acceptor = TlsAcceptor::from(server_config);
        let tls_stream = match acceptor.accept(TokioIo::new(upgraded)).await {
            Ok(stream) => stream,
            Err(err) => {
                debug!(error = %err, "CONNECT TLS handshake failed");
                return;
            }
        };

        let io = TokioIo::new(tls_stream);
        let service = service_fn(move |req: Request<Incoming>| {
            let state = task_state.clone();
            let authority = authority.clone();
            async move { Ok::<_, Infallible>(handle_tunneled(req, state, authority).await) }
        });
        let mut builder = ConnBuilder::new(TokioExecutor::new());
        builder
            .http1()
            .header_read_timeout(Duration::from_secs(30))
            .timer(TokioTimer::new());
        if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
            debug!(error = %err, "tunneled connection closed");
        }
    });

    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::OK;
    response
}

async fn handle_tunneled(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    authority: String,
) -> Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    let body_bytes = match collect_forward(body, MAX_FORWARD_BYTES).await {
        Ok(result) => result,
        Err(err) => {
            state.record_error(err.clone());
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, &err);
        }
    };

    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let target = format!("https://{authority}{path}");
    let url = match Url::parse(&target) {
        Ok(url) => url,
        Err(err) => {
            state.record_error(format!("invalid tunneled target URL: {err}"));
            return error_response(StatusCode::BAD_REQUEST, "invalid tunneled target");
        }
    };

    forward(parts.method, parts.headers, body_bytes, url, state).await
}

async fn forward(
    method: Method,
    headers: HeaderMap,
    body_bytes: Bytes,
    url: Url,
    state: Arc<ProxyState>,
) -> Response<Full<Bytes>> {
    if has_upgrade(&headers) {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "WebSocket/Upgrade requests are not supported by this proxy",
        );
    }

    let method_text = method.as_str().to_string();
    let url_text = url.to_string();
    let host = url.host_str().unwrap_or_default().to_string();
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };

    let request_content_type = header_text(&headers, CONTENT_TYPE.as_str()).unwrap_or_default();
    let request_bytes_len = body_bytes.len();
    let request_body = capture_body(
        &body_bytes[..body_bytes.len().min(BODY_CAP)],
        &request_content_type,
    );
    let request_headers = headers_to_vec(&headers);
    let query = parse_query(&url);
    let cookies = parse_cookies(&headers);

    let reqwest_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(method) => method,
        Err(err) => {
            state.record_error(format!("invalid method: {err}"));
            return error_response(StatusCode::BAD_REQUEST, "invalid request method");
        }
    };

    let forwarded = forwarded_headers(&headers);
    let client = if is_local_target(&host) {
        &state.direct_client
    } else {
        &state.client
    };
    let mut builder = client.request(reqwest_method, url).headers(forwarded);
    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes);
    }

    let started = Instant::now();
    let result = builder.send().await;
    let total_ms = started.elapsed().as_secs_f64() * 1000.0;
    let timing = build_timing(total_ms);

    let response = match result {
        Ok(response) => response,
        Err(err) => {
            let reason = describe_reqwest_error(&err);
            state.record_error(format!("{host}: {reason}"));
            warn!(host = %host, reason = %reason, "upstream request failed");

            let exchange = Exchange {
                id: uuid::Uuid::new_v4().to_string(),
                session_id: state.session_id.clone(),
                sequence: 0,
                captured_at: chrono::Utc::now().to_rfc3339(),
                method: method_text.clone(),
                url: url_text.clone(),
                host,
                path,
                status: 0,
                duration_ms: round2(total_ms),
                request_bytes: request_bytes_len,
                response_bytes: 0,
                content_type: request_content_type,
                error: Some(reason),
                request_headers: request_headers.clone(),
                response_headers: Vec::new(),
                query,
                cookies,
                request_body: request_body.clone(),
                response_body: Body::empty(),
                raw_request: build_raw_request(
                    &method_text,
                    &url_text,
                    &request_headers,
                    &request_body,
                ),
                raw_response: String::new(),
                timing,
            };
            state.emit(exchange);
            return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    let status = response.status().as_u16();
    let response_headers_map = response.headers().clone();
    let response_content_type =
        header_text(&response_headers_map, CONTENT_TYPE.as_str()).unwrap_or_default();
    let mut response = response;

    let response_bytes = match read_response_forward(&mut response, MAX_FORWARD_BYTES).await {
        Ok(result) => result,
        Err(reason) => {
            state.record_error(format!("{host}: {reason}"));
            let exchange = Exchange {
                id: uuid::Uuid::new_v4().to_string(),
                session_id: state.session_id.clone(),
                sequence: 0,
                captured_at: chrono::Utc::now().to_rfc3339(),
                method: method_text.clone(),
                url: url_text.clone(),
                host,
                path,
                status,
                duration_ms: round2(total_ms),
                request_bytes: request_bytes_len,
                response_bytes: 0,
                content_type: response_content_type,
                error: Some(reason),
                request_headers: request_headers.clone(),
                response_headers: headers_to_vec(&response_headers_map),
                query,
                cookies,
                request_body: request_body.clone(),
                response_body: Body::empty(),
                raw_request: build_raw_request(
                    &method_text,
                    &url_text,
                    &request_headers,
                    &request_body,
                ),
                raw_response: String::new(),
                timing,
            };
            state.emit(exchange);
            return error_response(StatusCode::BAD_GATEWAY, "failed to read upstream response");
        }
    };

    let response_bytes_len = response_bytes.len();
    let response_body = capture_body(
        &response_bytes[..response_bytes.len().min(BODY_CAP)],
        &response_content_type,
    );
    let response_headers = headers_to_vec(&response_headers_map);

    let exchange = Exchange {
        id: uuid::Uuid::new_v4().to_string(),
        session_id: state.session_id.clone(),
        sequence: 0,
        captured_at: chrono::Utc::now().to_rfc3339(),
        method: method_text.clone(),
        url: url_text.clone(),
        host,
        path,
        status,
        duration_ms: round2(total_ms),
        request_bytes: request_bytes_len,
        response_bytes: response_bytes_len,
        content_type: response_content_type,
        error: None,
        request_headers: request_headers.clone(),
        response_headers: response_headers.clone(),
        query,
        cookies,
        request_body: request_body.clone(),
        response_body: response_body.clone(),
        raw_request: build_raw_request(&method_text, &url_text, &request_headers, &request_body),
        raw_response: build_raw_response(status, &response_headers, &response_body),
        timing,
    };
    state.emit(exchange);

    let mut outgoing = Response::new(Full::new(response_bytes));
    *outgoing.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let keep_content_length = method_text.eq_ignore_ascii_case("HEAD") || status == 304;
    *outgoing.headers_mut() =
        forwarded_response_headers(&response_headers_map, keep_content_length);
    outgoing
}

impl ProxyState {
    fn record_error(&self, message: String) {
        *self.last_error.lock() = Some(message);
    }

    fn emit(&self, mut exchange: Exchange) {
        if self.stopped.load(Ordering::SeqCst) {
            return;
        }
        exchange.sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        self.captured.fetch_add(1, Ordering::Relaxed);
        let _ = self.events.send(exchange);
    }
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = Bytes::from(format!("{message}\n"));
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn has_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(hyper::header::UPGRADE)
        || headers
            .get(hyper::header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
            })
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn headers_to_vec(headers: &HeaderMap) -> Vec<Header> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| Header::new(name.as_str(), value))
        })
        .collect()
}

fn forwarded_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    let connection_tokens: Vec<String> = headers
        .get(hyper::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(|part| part.trim().to_ascii_lowercase())
                .filter(|part| !part.is_empty())
                .collect()
        })
        .unwrap_or_default();
    for (name, value) in headers.iter() {
        let name_text = name.as_str();
        if is_hop_by_hop(name_text)
            || name_text.eq_ignore_ascii_case("host")
            // Let reqwest advertise only the encodings it can decode; a
            // forwarded browser value can make it pass compressed bytes
            // through undecoded.
            || name_text.eq_ignore_ascii_case("accept-encoding")
            || connection_tokens
                .iter()
                .any(|token| token.eq_ignore_ascii_case(name_text))
        {
            continue;
        }
        if let Some((name, value)) = header_to_http(name_text, value.as_bytes()) {
            out.append(name, value);
        }
    }
    out
}

fn forwarded_response_headers(headers: &HeaderMap, keep_content_length: bool) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        let name_text = name.as_str();
        let is_length = name_text.eq_ignore_ascii_case("content-length");
        if (is_hop_by_hop(name_text) && !(keep_content_length && is_length))
            || name_text.eq_ignore_ascii_case("content-encoding")
        {
            continue;
        }
        if let Some((name, value)) = header_to_http(name_text, value.as_bytes()) {
            out.append(name, value);
        }
    }
    out
}

fn header_to_http(name: &str, value: &[u8]) -> Option<(HeaderName, HeaderValue)> {
    let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    let value = HeaderValue::from_bytes(value).ok()?;
    Some((name, value))
}

/// Local targets bypass any upstream proxy so LAN devices and install pages stay reachable.
pub fn is_local_target(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".local")
        || host.ends_with(".lan")
        || host.ends_with(".home")
    {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
            }
        };
    }
    false
}

/// Returns true for headers that must not be forwarded between connections.
pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "proxy-connection"
            | "transfer-encoding"
            | "content-length"
            | "upgrade"
            | "keep-alive"
            | "te"
            | "trailer"
            | "proxy-authorization"
    )
}

/// Split an authority into a host and port, supporting bracketed IPv6 literals.
/// Result of an explicit upstream exit-IP check.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamCheck {
    pub ip: String,
    pub latency_ms: f64,
}

fn upstream_scheme(url: &str) -> Option<&str> {
    url.split_once("://").map(|(scheme, _)| scheme)
}

/// Validates an upstream proxy URL and supported schemes.
pub fn validate_upstream_url(url: &str) -> Result<(), ProxyError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::Upstream("URL is empty".into()));
    }
    let parsed = Url::parse(trimmed).map_err(|e| ProxyError::Upstream(e.to_string()))?;
    if parsed.host_str().is_none() {
        return Err(ProxyError::Upstream("URL has no host".into()));
    }
    let scheme = upstream_scheme(trimmed).map(|s| s.to_ascii_lowercase());
    match scheme.as_deref() {
        Some("http") | Some("https") | Some("socks5") | Some("socks5h") => {}
        _ => {
            return Err(ProxyError::Upstream(
                "use http://, https://, socks5:// or socks5h://".into(),
            ))
        }
    }
    reqwest::Proxy::all(trimmed).map_err(|e| ProxyError::Upstream(e.to_string()))?;
    Ok(())
}

fn build_upstream_proxy(upstream: &UpstreamProxy) -> Result<reqwest::Proxy, ProxyError> {
    validate_upstream_url(&upstream.url)?;
    let trimmed = upstream.url.trim();
    let username = upstream.username.as_deref().unwrap_or("").trim();
    let password = upstream.password.as_deref().unwrap_or("");
    let scheme = upstream_scheme(trimmed)
        .unwrap_or("http")
        .to_ascii_lowercase();
    if !username.is_empty() && (scheme == "socks5" || scheme == "socks5h") {
        let mut parsed = Url::parse(trimmed).map_err(|e| ProxyError::Upstream(e.to_string()))?;
        parsed
            .set_username(username)
            .map_err(|_| ProxyError::Upstream("invalid SOCKS username".into()))?;
        parsed
            .set_password(Some(password))
            .map_err(|_| ProxyError::Upstream("invalid SOCKS password".into()))?;
        return reqwest::Proxy::all(parsed.as_str())
            .map_err(|e| ProxyError::Upstream(e.to_string()));
    }
    let mut proxy =
        reqwest::Proxy::all(trimmed).map_err(|e| ProxyError::Upstream(e.to_string()))?;
    if !username.is_empty() {
        proxy = proxy.basic_auth(username, password);
    }
    Ok(proxy)
}

/// Requests a public echo service through the upstream proxy to report its exit IP.
pub async fn check_upstream(upstream: &UpstreamProxy) -> Result<UpstreamCheck, ProxyError> {
    let proxy = build_upstream_proxy(upstream)?;
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .proxy(proxy)
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| ProxyError::Client(e.to_string()))?;
    let started = Instant::now();
    let response = client
        .get("https://api.ipify.org?format=json")
        .send()
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;
    if !response.status().is_success() {
        return Err(ProxyError::Upstream(format!(
            "exit IP service returned {}",
            response.status()
        )));
    }
    let body = response
        .text()
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;
    let ip = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| {
            value
                .get("ip")
                .and_then(|ip| ip.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| body.trim().to_string());
    if ip.is_empty() {
        return Err(ProxyError::Upstream("exit IP response was empty".into()));
    }
    Ok(UpstreamCheck {
        ip,
        latency_ms: round2(started.elapsed().as_secs_f64() * 1000.0),
    })
}

/// Generates a new local CA (ECDSA P-256) suitable for signing captured hosts.
pub fn generate_ca() -> Result<(String, String), ProxyError> {
    ensure_crypto_provider();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(|e| ProxyError::CaCertificate(e.to_string()))?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Relay Local CA");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Relay");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key = rcgen::KeyPair::generate().map_err(|e| ProxyError::CaKey(e.to_string()))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| ProxyError::CaCertificate(e.to_string()))?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Builds an Apple configuration profile that installs the supplied CA.
pub fn ca_mobileconfig(cert_pem: &str, display_name: &str) -> Result<String, ProxyError> {
    let mut cursor = cert_pem.as_bytes();
    let der = rustls_pemfile::certs(&mut cursor)
        .next()
        .transpose()
        .map_err(|e| ProxyError::CaCertificate(e.to_string()))?
        .ok_or_else(|| ProxyError::CaCertificate("no certificate in PEM".into()))?;
    let encoded = BASE64.encode(der.as_ref());
    let safe_name = display_name.replace(['<', '>', '&', '"'], "");
    let profile_uuid = uuid::Uuid::new_v4();
    let cert_uuid = uuid::Uuid::new_v4();
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>relay-ca.cer</string>
      <key>PayloadContent</key>
      <data>{encoded}</data>
      <key>PayloadDescription</key>
      <string>Local certificate authority used by Relay to inspect HTTP/HTTPS traffic.</string>
      <key>PayloadDisplayName</key>
      <string>{safe_name}</string>
      <key>PayloadIdentifier</key>
      <string>app.relay.ca.{cert_uuid}</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>{cert_uuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>Installs the local Relay CA. Only install it on devices you own.</string>
  <key>PayloadDisplayName</key>
  <string>{safe_name}</string>
  <key>PayloadIdentifier</key>
  <string>app.relay.profile.{profile_uuid}</string>
  <key>PayloadOrganization</key>
  <string>Relay</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{profile_uuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"#
    ))
}

pub fn is_mitm_it_host(host: &str) -> bool {
    let host = host
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    matches!(host.as_str(), "mitm.it" | "www.mitm.it")
}

fn mitm_it_page() -> Bytes {
    Bytes::from_static(
        br#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relay certificate</title>
<style>
:root{color-scheme:light dark;font-family:-apple-system,"Segoe UI",system-ui,sans-serif}
body{margin:0;background:#f1f2ef;color:#202420}main{max-width:520px;margin:0 auto;padding:36px 20px 56px}
h1{font-size:26px;letter-spacing:-.6px;margin:0 0 8px}p.lead{color:#6c756c;line-height:1.55;margin:0 0 24px}
.card{background:#f8f9f6;border:1px solid #d9ddd6;border-radius:10px;padding:18px;margin-bottom:14px}
a.primary{display:block;text-align:center;background:#4a684d;color:#fff;text-decoration:none;padding:13px;border-radius:7px;font-weight:600}
a.secondary{display:inline-block;color:#4a684d;text-decoration:none;margin-top:12px;font-size:14px}
ol{padding-left:20px;line-height:1.7;font-size:14px;color:#30352f}
footer{color:#929a92;font-size:12px;margin-top:24px}
</style></head><body><main>
<h1>Relay certificate</h1>
<p class="lead">Install the certificate authority used by Relay on this device. Only install it on a device you own.</p>
<div class="card">
<a class="primary" href="/cert/ios">Install on iOS</a>
<a class="secondary" href="/cert/cer">Download .cer</a>
<a class="secondary" href="/cert/pem">Download .pem</a>
</div>
<div class="card"><ol>
<li>Install the certificate.</li>
<li>iOS: Settings &gt; General &gt; VPN &amp; Device Management, then install the profile.</li>
<li>iOS: Settings &gt; General &gt; About &gt; Certificate Trust Settings, enable full trust.</li>
<li>Android/Windows: install the CA certificate as a trusted root.</li>
</ol></div>
<footer>Served locally by Relay through your proxy. Traffic is not uploaded anywhere.</footer>
</main></body></html>"#,
    )
}

fn mitm_it_response(path: &str, cert_pem: &str) -> Response<Full<Bytes>> {
    let path = path.split('?').next().unwrap_or("/");
    let (status, content_type, body, disposition) = match path {
        "/" | "/index.html" => (
            StatusCode::OK,
            "text/html; charset=utf-8",
            mitm_it_page(),
            None,
        ),
        "/cert/ios" | "/relay-ca.mobileconfig" => match ca_mobileconfig(cert_pem, "Relay CA") {
            Ok(profile) => (
                StatusCode::OK,
                "application/x-apple-aspen-config",
                Bytes::from(profile),
                Some("attachment; filename=\"relay-ca.mobileconfig\""),
            ),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain; charset=utf-8",
                Bytes::from(format!("certificate error: {err}\n")),
                None,
            ),
        },
        "/cert/cer" => match ca_der(cert_pem) {
            Ok(der) => (
                StatusCode::OK,
                "application/x-x509-ca-cert",
                Bytes::from(der),
                Some("attachment; filename=\"relay-ca.cer\""),
            ),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain; charset=utf-8",
                Bytes::from(format!("certificate error: {err}\n")),
                None,
            ),
        },
        "/cert/pem" => (
            StatusCode::OK,
            "application/x-pem-file",
            Bytes::from(cert_pem.to_string()),
            Some("attachment; filename=\"relay-ca.pem\""),
        ),
        _ => (
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"not found\n"),
            None,
        ),
    };
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Some(value) = disposition {
        if let Ok(value) = HeaderValue::from_str(value) {
            response
                .headers_mut()
                .insert(hyper::header::CONTENT_DISPOSITION, value);
        }
    }
    response
}

pub fn ca_der(cert_pem: &str) -> Result<Vec<u8>, ProxyError> {
    let mut cursor = cert_pem.as_bytes();
    let der = rustls_pemfile::certs(&mut cursor)
        .next()
        .transpose()
        .map_err(|e| ProxyError::CaCertificate(e.to_string()))?
        .ok_or_else(|| ProxyError::CaCertificate("no certificate in PEM".into()))?;
    Ok(der.as_ref().to_vec())
}

/// Splits an authority string into host and port, supporting IPv6 literals.
pub fn parse_host_port(authority: &str, default_port: u16) -> (String, u16) {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(default_port);
            return (host.to_string(), port);
        }
    }

    if authority.matches(':').count() == 1 {
        if let Some((host, port)) = authority.rsplit_once(':') {
            if let Ok(port) = port.parse::<u16>() {
                return (host.to_string(), port);
            }
        }
    }

    let host = authority.trim_matches(['[', ']']).to_string();
    (host, default_port)
}

fn format_authority(host: &str, port: u16) -> String {
    let bracketed = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        bracketed
    } else {
        format!("{bracketed}:{port}")
    }
}

fn build_forward_url(uri: &Uri, host_header: Option<&str>) -> Result<Url, ProxyError> {
    if uri.scheme().is_some() {
        return Url::parse(&uri.to_string()).map_err(|e| ProxyError::InvalidUrl(e.to_string()));
    }

    let host = host_header
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .or_else(|| uri.authority().map(|a| a.as_str().to_string()))
        .ok_or_else(|| ProxyError::InvalidHost("missing Host header".to_string()))?;
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    Url::parse(&format!("http://{host}{path}")).map_err(|e| ProxyError::InvalidUrl(e.to_string()))
}

fn parse_query(url: &Url) -> Vec<KeyValue> {
    url.query_pairs()
        .map(|(name, value)| KeyValue {
            name: name.into_owned(),
            value: value.into_owned(),
        })
        .collect()
}

fn parse_cookies(headers: &HeaderMap) -> Vec<KeyValue> {
    let Some(value) = headers
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    else {
        return Vec::new();
    };
    value
        .split(';')
        .filter_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            Some(KeyValue {
                name: name.trim().to_string(),
                value: value.trim().to_string(),
            })
        })
        .collect()
}

fn capture_body(bytes: &[u8], content_type: &str) -> Body {
    if bytes.is_empty() {
        return Body::empty();
    }
    if is_binary_content_type(content_type) {
        return Body::from_base64(BASE64.encode(bytes));
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => Body::from_utf8_text(text.to_string(), content_type),
        Err(_) => Body::from_base64(BASE64.encode(bytes)),
    }
}

fn is_binary_content_type(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    if ct.is_empty() {
        return false;
    }
    if ct.starts_with("text/")
        || ct.contains("json")
        || ct.contains("xml")
        || ct.contains("javascript")
        || ct.contains("x-www-form-urlencoded")
        || ct.contains("html")
    {
        return false;
    }
    ct.starts_with("image/")
        || ct.starts_with("font/")
        || ct.starts_with("audio/")
        || ct.starts_with("video/")
        || ct.contains("octet-stream")
        || ct.contains("pdf")
        || ct.contains("zip")
        || ct.contains("protobuf")
}

async fn collect_forward<B>(body: B, limit: usize) -> Result<Bytes, String>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    let mut body = std::pin::pin!(body);
    let mut buffer = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| format!("failed to read request body: {e}"))?;
        if let Ok(data) = frame.into_data() {
            if buffer.len() + data.len() > limit {
                return Err(format!(
                    "request body exceeds the {} MiB forwarding limit",
                    limit / (1024 * 1024)
                ));
            }
            buffer.extend_from_slice(&data);
        }
    }
    Ok(buffer.freeze())
}

async fn read_response_forward(
    response: &mut reqwest::Response,
    limit: usize,
) -> Result<Bytes, String> {
    let mut buffer = BytesMut::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if buffer.len() + chunk.len() > limit {
                    return Err(format!(
                        "response body exceeds the {} MiB forwarding limit",
                        limit / (1024 * 1024)
                    ));
                }
                buffer.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(err) => return Err(format!("failed to read response: {err}")),
        }
    }
    Ok(buffer.freeze())
}

fn build_raw_request(method: &str, url: &str, headers: &[Header], body: &Body) -> String {
    let mut raw = String::with_capacity(512);
    raw.push_str(method);
    raw.push(' ');
    raw.push_str(url);
    raw.push_str(" HTTP/1.1\r\n");
    for header in headers {
        raw.push_str(&header.name);
        raw.push_str(": ");
        raw.push_str(&header.value);
        raw.push_str("\r\n");
    }
    raw.push_str("\r\n");
    if !body.is_empty() {
        raw.push_str(&truncate_text(body.text.clone(), RAW_CAP));
    }
    truncate_text(raw, RAW_CAP)
}

fn build_raw_response(status: u16, headers: &[Header], body: &Body) -> String {
    let mut raw = String::with_capacity(512);
    raw.push_str("HTTP/1.1 ");
    raw.push_str(&status.to_string());
    if let Some(reason) = StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
    {
        raw.push(' ');
        raw.push_str(reason);
    }
    raw.push_str("\r\n");
    for header in headers {
        raw.push_str(&header.name);
        raw.push_str(": ");
        raw.push_str(&header.value);
        raw.push_str("\r\n");
    }
    raw.push_str("\r\n");
    if !body.is_empty() {
        raw.push_str(&truncate_text(body.text.clone(), RAW_CAP));
    }
    truncate_text(raw, RAW_CAP)
}

fn truncate_text(mut text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push_str("\n...[truncated]");
    text
}

fn build_timing(total_ms: f64) -> Vec<TimingPhase> {
    vec![
        TimingPhase {
            label: "Waiting".to_string(),
            value: round2(total_ms * 0.7),
            tone: TimingTone::Wait,
        },
        TimingPhase {
            label: "Download".to_string(),
            value: round2(total_ms * 0.3),
            tone: TimingTone::Transfer,
        },
        TimingPhase {
            label: "Total".to_string(),
            value: round2(total_ms),
            tone: TimingTone::Base,
        },
    ]
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn describe_reqwest_error(err: &reqwest::Error) -> String {
    if err.is_timeout() {
        "request timed out".to_string()
    } else if err.is_connect() {
        "connection failed".to_string()
    } else if err.is_body() || err.is_decode() {
        "invalid upstream response".to_string()
    } else {
        "upstream request failed".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn parses_domain_authority() {
        assert_eq!(
            parse_host_port("example.com", 443),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn parses_host_and_port() {
        assert_eq!(
            parse_host_port("example.com:8080", 443),
            ("example.com".to_string(), 8080)
        );
    }

    #[test]
    fn parses_ipv6_brackets() {
        assert_eq!(
            parse_host_port("[::1]:8443", 443),
            ("::1".to_string(), 8443)
        );
        assert_eq!(
            parse_host_port("[2001:db8::1]", 443),
            ("2001:db8::1".to_string(), 443)
        );
    }

    #[test]
    fn parses_bare_ipv6_with_default_port() {
        assert_eq!(parse_host_port("::1", 443), ("::1".to_string(), 443));
    }

    #[test]
    fn detects_hop_by_hop_headers() {
        for name in [
            "Host",
            "connection",
            "Proxy-Connection",
            "TRANSFER-ENCODING",
            "content-length",
            "Upgrade",
            "keep-alive",
            "te",
            "trailer",
            "Proxy-Authorization",
        ] {
            assert!(is_hop_by_hop(name), "{name} should be hop-by-hop");
        }
        assert!(!is_hop_by_hop("accept"));
        assert!(!is_hop_by_hop("content-type"));
    }

    #[test]
    fn builds_absolute_http_url() {
        let uri: Uri = "http://example.com/a?b=1".parse().unwrap();
        let url = build_forward_url(&uri, None).unwrap();
        assert_eq!(url.as_str(), "http://example.com/a?b=1");
        assert_eq!(url.scheme(), "http");
    }

    #[test]
    fn builds_https_url_from_connect_target() {
        let url = Url::parse(&format!(
            "https://{}{}",
            format_authority("example.com", 443),
            "/x"
        ))
        .unwrap();
        assert_eq!(url.as_str(), "https://example.com/x");
        let url = Url::parse(&format!(
            "https://{}{}",
            format_authority("example.com", 8443),
            "/x"
        ))
        .unwrap();
        assert_eq!(url.as_str(), "https://example.com:8443/x");
    }

    #[test]
    fn builds_url_from_origin_form_and_host_header() {
        let uri: Uri = "/only/path?q=1".parse().unwrap();
        let url = build_forward_url(&uri, Some("example.test:8080")).unwrap();
        assert_eq!(url.as_str(), "http://example.test:8080/only/path?q=1");
    }

    #[test]
    fn rejects_origin_form_without_host() {
        let uri: Uri = "/only/path".parse().unwrap();
        assert!(build_forward_url(&uri, None).is_err());
    }

    #[test]
    fn header_conversion_skips_invalid_names_and_values() {
        assert!(header_to_http("bad header", b"value").is_none());
        assert!(header_to_http("x-test", b"bad\nvalue").is_none());
        assert!(header_to_http("x-test", b"ok").is_some());
    }

    #[test]
    fn forwarded_headers_drop_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert("connection", HeaderValue::from_static("close"));
        headers.insert("x-keep", HeaderValue::from_static("yes"));
        let forwarded = forwarded_headers(&headers);
        assert!(!forwarded.contains_key("host"));
        assert!(!forwarded.contains_key("connection"));
        assert_eq!(forwarded.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn classifies_json_body() {
        let body = capture_body(&Bytes::from_static(br#"{"a":1}"#), "application/json");
        assert_eq!(body.kind, domain::BodyKindWire::Json);
        assert!(body.encoding == domain::BodyEncoding::Utf8);
        assert_eq!(body.text, r#"{"a":1}"#);
    }

    #[test]
    fn classifies_binary_body_as_base64() {
        let body = capture_body(
            &Bytes::from_static(&[0xff, 0x00, 0x01]),
            "application/octet-stream",
        );
        assert_eq!(body.kind, domain::BodyKindWire::Binary);
        assert!(body.encoding == domain::BodyEncoding::Base64);
    }

    #[test]
    fn classifies_invalid_utf8_as_base64() {
        let body = capture_body(&Bytes::from_static(&[0xff, 0xfe]), "text/plain");
        assert!(body.encoding == domain::BodyEncoding::Base64);
    }

    fn test_ca() -> (String, String) {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Proxy Test CA");
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("self signed");
        (cert.pem(), key.serialize_pem())
    }

    #[tokio::test]
    async fn leaf_certificate_chains_to_imported_ca() {
        let (cert_pem, key_pem) = test_ca();
        let mut ca = CertificateAuthority::from_pem(&cert_pem, &key_pem).expect("ca");
        let server_config = ca.leaf_for_host("localhost").expect("leaf");
        assert_eq!(ca.cached_hosts(), 1);

        let mut roots = rustls::RootCertStore::empty();
        let mut pem = cert_pem.as_bytes();
        for cert in rustls_pemfile::certs(&mut pem) {
            roots.add(cert.expect("cert")).expect("add root");
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(server_config);
            let mut stream = acceptor.accept(server_io).await.expect("accept");
            stream.write_all(b"hello").await.expect("write");
        });

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let mut stream = connector
            .connect(name, client_io)
            .await
            .expect("client handshake");
        let mut buffer = [0u8; 5];
        stream.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"hello");
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn loopback_http_proxy_captures_exchange() {
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream addr");
        tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.expect("accept");
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = socket.read(&mut chunk).await.expect("read");
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let body = br#"{"ok":true}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(head.as_bytes()).await.expect("write head");
            socket.write_all(body).await.expect("write body");
            let _ = socket.shutdown().await;
        });

        let (cert, key) = test_ca();
        let config = ProxyConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            ca_cert_pem: cert,
            ca_key_pem: key,
            upstream: None,
        };
        let (events, mut receiver) = broadcast::channel(16);
        let handle = ProxyHandle::start(config, "test-session".to_string(), events)
            .await
            .expect("start");
        let proxy_addr: SocketAddr = format!("127.0.0.1:{}", handle.port).parse().expect("addr");

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
        let request = format!(
            "GET http://{}/hello?x=1 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            upstream_addr, upstream_addr
        );
        client
            .write_all(request.as_bytes())
            .await
            .expect("write request");

        let mut response = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk))
                .await
                .expect("read timeout")
                .expect("read");
            if read == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..read]);
        }
        let response_text = String::from_utf8_lossy(&response);
        assert!(
            response_text.contains("200 OK"),
            "response: {response_text}"
        );
        assert!(
            response_text.contains(r#"{"ok":true}"#),
            "response: {response_text}"
        );

        let exchange = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("event timeout")
            .expect("event");
        assert_eq!(exchange.session_id, "test-session");
        assert_eq!(exchange.method, "GET");
        assert_eq!(exchange.status, 200);
        assert_eq!(exchange.host, "127.0.0.1");
        assert!(exchange.url.ends_with("/hello?x=1"));
        assert_eq!(exchange.response_body.kind, domain::BodyKindWire::Json);
        assert_eq!(handle.captured_count(), 1);

        handle.shutdown().await;
    }
}

#[cfg(test)]
mod upstream_tests {
    use super::*;

    #[test]
    fn accepts_supported_upstream_schemes() {
        assert!(validate_upstream_url("http://127.0.0.1:3128").is_ok());
        assert!(validate_upstream_url("https://proxy.example:8443").is_ok());
        assert!(validate_upstream_url("socks5://127.0.0.1:1080").is_ok());
        assert!(validate_upstream_url("socks5h://user:pass@127.0.0.1:1080").is_ok());
        assert!(validate_upstream_url("HTTP://127.0.0.1:3128").is_ok());
    }

    #[test]
    fn rejects_invalid_upstreams() {
        assert!(validate_upstream_url("").is_err());
        assert!(validate_upstream_url("ftp://127.0.0.1:21").is_err());
        assert!(validate_upstream_url("not a url").is_err());
    }

    #[test]
    fn detects_local_targets() {
        assert!(is_local_target("127.0.0.1"));
        assert!(is_local_target("192.168.0.78"));
        assert!(is_local_target("10.0.0.2"));
        assert!(is_local_target("localhost"));
        assert!(is_local_target("printer.local"));
        assert!(!is_local_target("example.com"));
        assert!(!is_local_target("8.8.8.8"));
    }

    #[test]
    fn builds_authenticated_proxy() {
        let upstream = UpstreamProxy {
            url: "http://127.0.0.1:3128".into(),
            username: Some("user".into()),
            password: Some("secret".into()),
        };
        assert!(build_upstream_proxy(&upstream).is_ok());
        let socks = UpstreamProxy {
            url: "socks5://127.0.0.1:1080".into(),
            username: Some("user".into()),
            password: Some("secret".into()),
        };
        assert!(build_upstream_proxy(&socks).is_ok());
    }
}
