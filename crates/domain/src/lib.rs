use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SECRET_PLACEHOLDER: &str = "••••••••";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyValue {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TimingTone {
    Base,
    Wait,
    Transfer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TimingPhase {
    pub label: String,
    pub value: f64,
    pub tone: TimingTone,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Body {
    pub kind: BodyKindWire,
    pub text: String,
    pub encoding: BodyEncoding,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum BodyEncoding {
    #[default]
    Utf8,
    Base64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum BodyKindWire {
    #[default]
    Empty,
    Text,
    Json,
    Form,
    Binary,
}

impl Body {
    pub fn empty() -> Self {
        Self {
            kind: BodyKindWire::Empty,
            text: String::new(),
            encoding: BodyEncoding::Utf8,
        }
    }

    pub fn from_utf8_text(text: String, content_type: &str) -> Self {
        if text.is_empty() {
            return Self::empty();
        }
        let kind = classify_body(content_type, &text);
        Self {
            kind,
            text,
            encoding: BodyEncoding::Utf8,
        }
    }

    pub fn from_base64(text: String) -> Self {
        Self {
            kind: BodyKindWire::Binary,
            text,
            encoding: BodyEncoding::Base64,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

pub fn classify_body(content_type: &str, text: &str) -> BodyKindWire {
    let ct = content_type.to_ascii_lowercase();
    if text.is_empty() {
        return BodyKindWire::Empty;
    }
    if ct.contains("json") || serde_json::from_str::<serde_json::Value>(text).is_ok() {
        return BodyKindWire::Json;
    }
    if ct.contains("x-www-form-urlencoded") {
        return BodyKindWire::Form;
    }
    if ct.starts_with("text/")
        || ct.contains("xml")
        || ct.contains("javascript")
        || ct.contains("html")
    {
        return BodyKindWire::Text;
    }
    if ct.starts_with("image/")
        || ct.starts_with("font/")
        || ct.starts_with("audio/")
        || ct.starts_with("video/")
        || ct.contains("octet-stream")
    {
        return BodyKindWire::Binary;
    }
    if text
        .chars()
        .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
    {
        BodyKindWire::Text
    } else {
        BodyKindWire::Binary
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Exchange {
    pub id: String,
    pub session_id: String,
    pub sequence: u64,
    pub captured_at: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: f64,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub content_type: String,
    pub error: Option<String>,
    pub request_headers: Vec<Header>,
    pub response_headers: Vec<Header>,
    pub query: Vec<KeyValue>,
    pub cookies: Vec<KeyValue>,
    pub request_body: Body,
    pub response_body: Body,
    pub raw_request: String,
    pub raw_response: String,
    pub timing: Vec<TimingPhase>,
}

impl Exchange {
    pub fn has_error(&self) -> bool {
        self.error.is_some() || self.status == 0
    }

    pub fn status_group(&self) -> StatusGroup {
        if self.has_error() {
            StatusGroup::Error
        } else if self.status >= 500 {
            StatusGroup::ServerError
        } else if self.status >= 400 {
            StatusGroup::ClientError
        } else if self.status >= 300 {
            StatusGroup::Redirect
        } else if self.status >= 200 {
            StatusGroup::Success
        } else {
            StatusGroup::Informational
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.request_headers
            .iter()
            .chain(self.response_headers.iter())
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn search_haystack(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str(&self.method);
        out.push(' ');
        out.push_str(&self.url);
        out.push(' ');
        out.push_str(&self.host);
        out.push(' ');
        out.push_str(&self.path);
        out.push(' ');
        out.push_str(&self.content_type);
        if let Some(err) = &self.error {
            out.push(' ');
            out.push_str(err);
        }
        for h in self
            .request_headers
            .iter()
            .chain(self.response_headers.iter())
        {
            out.push(' ');
            out.push_str(&h.name);
            out.push(' ');
            out.push_str(&h.value);
        }
        for kv in self.query.iter().chain(self.cookies.iter()) {
            out.push(' ');
            out.push_str(&kv.name);
            out.push(' ');
            out.push_str(&kv.value);
        }
        out.push(' ');
        out.push_str(&self.request_body.text);
        out.push(' ');
        out.push_str(&self.response_body.text);
        out.to_ascii_lowercase()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum StatusGroup {
    Informational,
    Success,
    Redirect,
    ClientError,
    ServerError,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    pub text: String,
    pub methods: Vec<String>,
    pub statuses: Vec<String>,
    pub hosts: Vec<String>,
    pub content_types: Vec<String>,
    pub only_errors: bool,
    pub group_by_host: bool,
}

impl Filter {
    pub fn matches(&self, exchange: &Exchange) -> bool {
        if !self.methods.is_empty()
            && !self
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&exchange.method))
        {
            return false;
        }
        if !self.hosts.is_empty()
            && !self
                .hosts
                .iter()
                .any(|h| h.eq_ignore_ascii_case(&exchange.host))
        {
            return false;
        }
        if !self.content_types.is_empty()
            && !self.content_types.iter().any(|ct| {
                exchange
                    .content_type
                    .to_ascii_lowercase()
                    .starts_with(&ct.to_ascii_lowercase())
            })
        {
            return false;
        }
        if !self.statuses.is_empty() {
            let group = exchange.status_group();
            let matched = self.statuses.iter().any(|s| match s.as_str() {
                "success" | "2xx" => group == StatusGroup::Success,
                "redirect" | "3xx" => group == StatusGroup::Redirect,
                "client" | "4xx" => group == StatusGroup::ClientError,
                "server" | "5xx" => group == StatusGroup::ServerError,
                "error" => group == StatusGroup::Error,
                "1xx" => group == StatusGroup::Informational,
                other => exchange.status.to_string() == other,
            });
            if !matched {
                return false;
            }
        }
        if self.only_errors && !exchange.has_error() && exchange.status < 400 {
            return false;
        }
        let needle = self.text.trim().to_ascii_lowercase();
        if !needle.is_empty() && !exchange.search_haystack().contains(&needle) {
            return false;
        }
        true
    }
}

pub fn filter_exchanges(exchanges: &[Exchange], filter: &Filter) -> Vec<Exchange> {
    exchanges
        .iter()
        .filter(|e| filter.matches(e))
        .cloned()
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostGroup {
    pub host: String,
    pub count: usize,
    pub errors: usize,
    pub bytes: usize,
}

pub fn group_by_host(exchanges: &[Exchange]) -> Vec<HostGroup> {
    let mut map: BTreeMap<String, HostGroup> = BTreeMap::new();
    for e in exchanges {
        let entry = map.entry(e.host.clone()).or_insert_with(|| HostGroup {
            host: e.host.clone(),
            count: 0,
            errors: 0,
            bytes: 0,
        });
        entry.count += 1;
        entry.bytes += e.response_bytes;
        if e.has_error() || e.status >= 400 {
            entry.errors += 1;
        }
    }
    let mut groups: Vec<_> = map.into_values().collect();
    groups.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.host.cmp(&b.host)));
    groups
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamProxy {
    pub url: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    #[serde(default)]
    pub upstream: Option<UpstreamProxy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    pub running: bool,
    pub host: String,
    pub port: u16,
    pub captured: usize,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ReplayProxyMode {
    Direct,
    AppProxy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReplayOptions {
    pub timeout_ms: u64,
    pub follow_redirects: bool,
    pub proxy_mode: ReplayProxyMode,
}

impl Default for ReplayOptions {
    fn default() -> Self {
        Self {
            timeout_ms: 15_000,
            follow_redirects: true,
            proxy_mode: ReplayProxyMode::Direct,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Draft {
    pub id: String,
    pub session_id: String,
    pub source_exchange_id: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<Header>,
    pub cookies: Vec<KeyValue>,
    pub body: Body,
    pub options: ReplayOptions,
    pub created_at: String,
    pub updated_at: String,
}

impl Draft {
    pub fn from_exchange(exchange: &Exchange) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: format!("draft_{}", exchange.id),
            session_id: exchange.session_id.clone(),
            source_exchange_id: exchange.id.clone(),
            method: exchange.method.clone(),
            url: exchange.url.clone(),
            headers: exchange.request_headers.clone(),
            cookies: exchange.cookies.clone(),
            body: exchange.request_body.clone(),
            options: ReplayOptions::default(),
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReplayResult {
    pub draft_id: String,
    pub status: u16,
    pub headers: Vec<Header>,
    pub body: Body,
    pub duration_ms: f64,
    pub url: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResponseDiff {
    pub status_changed: bool,
    pub original_status: u16,
    pub replay_status: u16,
    pub duration_delta_ms: f64,
    pub body_changed: bool,
    pub header_changes: Vec<HeaderChange>,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HeaderChange {
    pub name: String,
    pub original: Option<String>,
    pub replay: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiffLine {
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CurlBundle {
    pub bash: String,
    pub powershell: String,
    pub cmd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub name: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub exchange_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Collection {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub exchange_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SavedFilter {
    pub id: String,
    pub name: String,
    pub filter: Filter,
    pub created_at: String,
}
