use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use base64::Engine;
use domain::{
    Body, BodyEncoding, DiffLine, Draft, Exchange, Header, HeaderChange, ReplayProxyMode,
    ReplayResult, ResponseDiff,
};
use reqwest::redirect::Policy;
use similar::{ChangeTag, TextDiff};

const MAX_DIFF_LINES: usize = 400;
const TRUNCATED_LINE: &str = "… diff truncated";
/// Hard cap for a replayed response body, mirroring the proxy's forward limit.
const MAX_REPLAY_BODY: usize = 32 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("invalid method: {0}")]
    InvalidMethod(String),
    #[error("invalid proxy url: {0}")]
    InvalidProxy(String),
    #[error("app proxy mode requires a proxy url")]
    MissingProxy,
    #[error("invalid base64 request body: {0}")]
    InvalidBody(String),
    #[error("request failed: {0}")]
    Request(String),
    #[error("response body exceeds {0} bytes")]
    ResponseTooLarge(usize),
}

pub async fn replay(draft: &Draft) -> Result<ReplayResult, ReplayError> {
    replay_with_proxy(draft, None).await
}

pub async fn replay_with_proxy(
    draft: &Draft,
    proxy_url: Option<String>,
) -> Result<ReplayResult, ReplayError> {
    replay_with_proxy_ca(draft, proxy_url, None).await
}

/// Replays a draft through an app proxy, trusting the supplied MITM CA.
///
/// The app's proxy signs leaf certificates with its local CA, which is not in
/// the platform trust store, so HTTPS replay needs it explicitly.
pub async fn replay_with_proxy_ca(
    draft: &Draft,
    proxy_url: Option<String>,
    ca_cert_pem: Option<&str>,
) -> Result<ReplayResult, ReplayError> {
    let url = url::Url::parse(&draft.url).map_err(|e| ReplayError::InvalidUrl(e.to_string()))?;
    let method = draft
        .method
        .parse::<reqwest::Method>()
        .map_err(|_| ReplayError::InvalidMethod(draft.method.clone()))?;

    let options = &draft.options;

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(options.timeout_ms))
        .cookie_store(true)
        .redirect(redirect_policy(options.follow_redirects));

    if let Some(ca) = ca_cert_pem {
        let cert = reqwest::Certificate::from_pem(ca.as_bytes())
            .map_err(|e| ReplayError::Request(format!("invalid app CA: {e}")))?;
        builder = builder.add_root_certificate(cert);
    }

    match options.proxy_mode {
        ReplayProxyMode::Direct => {}
        ReplayProxyMode::AppProxy => {
            let proxy = proxy_url.as_deref().ok_or(ReplayError::MissingProxy)?;
            let proxy =
                reqwest::Proxy::all(proxy).map_err(|e| ReplayError::InvalidProxy(e.to_string()))?;
            builder = builder.proxy(proxy);
        }
    }

    let client = builder
        .build()
        .map_err(|e| ReplayError::Request(e.to_string()))?;

    let mut request = client.request(method, url);

    for header in filter_request_headers(&draft.headers) {
        request = request.header(header.name, header.value);
    }

    if let Some(cookie) = merged_cookie_header(&draft.headers, &draft.cookies) {
        request = request.header(reqwest::header::COOKIE, cookie);
    }

    if let Some(body) = request_body(&draft.body)? {
        request = request.body(body);
    }

    let started = Instant::now();
    let mut response = request
        .send()
        .await
        .map_err(|e| ReplayError::Request(e.to_string()))?;

    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut headers = Vec::new();
    for (name, value) in response.headers() {
        if let Ok(value) = value.to_str() {
            headers.push(Header::new(name.as_str(), value));
        }
    }

    if response
        .content_length()
        .is_some_and(|len| len > MAX_REPLAY_BODY as u64)
    {
        return Err(ReplayError::ResponseTooLarge(MAX_REPLAY_BODY));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| ReplayError::Request(e.to_string()))?
    {
        if bytes.len() + chunk.len() > MAX_REPLAY_BODY {
            return Err(ReplayError::ResponseTooLarge(
                bytes.len().saturating_add(chunk.len()),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let duration_ms = started.elapsed().as_secs_f64() * 1000.0;

    let body = decode_body(&bytes, &content_type);

    Ok(ReplayResult {
        draft_id: draft.id.clone(),
        status,
        headers,
        body,
        duration_ms,
        url: final_url,
        error: None,
    })
}

fn redirect_policy(follow_redirects: bool) -> Policy {
    if follow_redirects {
        Policy::limited(10)
    } else {
        Policy::none()
    }
}

fn is_skipped_request_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("accept-encoding")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("expect")
        || name.eq_ignore_ascii_case("keep-alive")
}

fn filter_request_headers(headers: &[Header]) -> Vec<Header> {
    headers
        .iter()
        .filter(|h| !is_skipped_request_header(&h.name))
        .cloned()
        .collect()
}

fn merged_cookie_header(headers: &[Header], cookies: &[domain::KeyValue]) -> Option<String> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut upsert = |name: &str, value: &str| {
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        if let Some(slot) = pairs.iter_mut().find(|(existing, _)| existing == name) {
            slot.1 = value.to_string();
        } else {
            pairs.push((name.to_string(), value.to_string()));
        }
    };

    for header in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("cookie"))
    {
        for part in header.value.split(';') {
            if let Some((name, value)) = part.trim().split_once('=') {
                upsert(name, value);
            }
        }
    }
    // Draft cookies are applied last so they override a stale captured value.
    for cookie in cookies {
        upsert(&cookie.name, &cookie.value);
    }

    if pairs.is_empty() {
        None
    } else {
        Some(
            pairs
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

fn request_body(body: &Body) -> Result<Option<Vec<u8>>, ReplayError> {
    if body.text.is_empty() {
        return Ok(None);
    }
    match body.encoding {
        BodyEncoding::Utf8 => Ok(Some(body.text.as_bytes().to_vec())),
        BodyEncoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(body.text.as_bytes())
            .map(Some)
            .map_err(|e| ReplayError::InvalidBody(e.to_string())),
    }
}

fn is_binary_content_type(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.starts_with("image/")
        || ct.starts_with("font/")
        || ct.starts_with("audio/")
        || ct.starts_with("video/")
        || ct.contains("octet-stream")
        || ct.contains("application/pdf")
        || ct.contains("application/zip")
        || ct.contains("application/gzip")
}

fn decode_body(bytes: &[u8], content_type: &str) -> Body {
    if bytes.is_empty() {
        return Body::empty();
    }
    if is_binary_content_type(content_type) {
        return Body::from_base64(base64::engine::general_purpose::STANDARD.encode(bytes));
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => Body::from_utf8_text(text.to_string(), content_type),
        Err(_) => Body::from_base64(base64::engine::general_purpose::STANDARD.encode(bytes)),
    }
}

pub fn diff_responses(original: &Exchange, replay: &ReplayResult) -> ResponseDiff {
    let status_changed = original.status != replay.status;
    let duration_delta_ms = replay.duration_ms - original.duration_ms;

    let header_changes = diff_headers(&original.response_headers, &replay.headers);

    let binary = original.response_body.encoding == BodyEncoding::Base64
        || replay.body.encoding == BodyEncoding::Base64;

    let body_changed = original.response_body.text != replay.body.text;

    let lines = if binary {
        vec![DiffLine {
            kind: "context".to_string(),
            text: "Binary bodies compared by encoded value".to_string(),
        }]
    } else {
        diff_lines(&original.response_body.text, &replay.body.text)
    };

    ResponseDiff {
        status_changed,
        original_status: original.status,
        replay_status: replay.status,
        duration_delta_ms,
        body_changed,
        header_changes,
        lines,
    }
}

fn diff_headers(original: &[Header], replay: &[Header]) -> Vec<HeaderChange> {
    let mut merged: BTreeMap<String, HeaderChange> = BTreeMap::new();

    for header in original {
        let key = header.name.to_ascii_lowercase();
        let entry = merged.entry(key).or_insert_with(|| HeaderChange {
            name: header.name.clone(),
            original: None,
            replay: None,
        });
        entry.original = Some(match entry.original.take() {
            Some(existing) => format!("{existing}, {}", header.value),
            None => header.value.clone(),
        });
    }

    for header in replay {
        let key = header.name.to_ascii_lowercase();
        let entry = merged.entry(key).or_insert_with(|| HeaderChange {
            name: header.name.clone(),
            original: None,
            replay: None,
        });
        entry.replay = Some(match entry.replay.take() {
            Some(existing) => format!("{existing}, {}", header.value),
            None => header.value.clone(),
        });
    }

    merged
        .into_values()
        .filter(|change| change.original != change.replay)
        .collect()
}

fn diff_lines(original: &str, replay: &str) -> Vec<DiffLine> {
    let diff = TextDiff::from_lines(original, replay);
    let all: Vec<DiffLine> = diff
        .iter_all_changes()
        .map(|change| {
            let kind = match change.tag() {
                ChangeTag::Insert => "add",
                ChangeTag::Delete => "remove",
                ChangeTag::Equal => "context",
            };
            DiffLine {
                kind: kind.to_string(),
                text: change.value().trim_end_matches(['\n', '\r']).to_string(),
            }
        })
        .collect();

    if all.len() > MAX_DIFF_LINES {
        let mut lines = all[..MAX_DIFF_LINES - 1].to_vec();
        lines.push(DiffLine {
            kind: "context".to_string(),
            text: TRUNCATED_LINE.to_string(),
        });
        lines
    } else {
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::{BodyKindWire, Exchange, KeyValue, ReplayOptions};

    fn header(name: &str, value: &str) -> Header {
        Header::new(name, value)
    }

    fn exchange_with(body: Body, status: u16, headers: Vec<Header>) -> Exchange {
        Exchange {
            id: "ex_1".to_string(),
            session_id: "sess_1".to_string(),
            sequence: 1,
            captured_at: String::new(),
            method: "GET".to_string(),
            url: "https://example.com/".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            status,
            duration_ms: 100.0,
            request_bytes: 0,
            response_bytes: 0,
            content_type: "text/plain".to_string(),
            error: None,
            request_headers: Vec::new(),
            response_headers: headers,
            query: Vec::new(),
            cookies: Vec::new(),
            request_body: Body::empty(),
            response_body: body,
            raw_request: String::new(),
            raw_response: String::new(),
            timing: Vec::new(),
        }
    }

    fn replay_result(body: Body, status: u16, headers: Vec<Header>) -> ReplayResult {
        ReplayResult {
            draft_id: "draft_1".to_string(),
            status,
            headers,
            body,
            duration_ms: 150.0,
            url: "https://example.com/".to_string(),
            error: None,
        }
    }

    fn draft(url: &str, proxy_mode: ReplayProxyMode) -> Draft {
        Draft {
            id: "draft_1".to_string(),
            session_id: "sess_1".to_string(),
            source_exchange_id: "ex_1".to_string(),
            method: "GET".to_string(),
            url: url.to_string(),
            headers: Vec::new(),
            cookies: Vec::new(),
            body: Body::empty(),
            options: ReplayOptions {
                timeout_ms: 1_000,
                follow_redirects: true,
                proxy_mode,
            },
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn identical_responses_have_no_changes() {
        let headers = vec![header("content-type", "text/plain")];
        let original = exchange_with(
            Body::from_utf8_text("hello\nworld\n".to_string(), "text/plain"),
            200,
            headers.clone(),
        );
        let replay = replay_result(
            Body::from_utf8_text("hello\nworld\n".to_string(), "text/plain"),
            200,
            headers,
        );

        let diff = diff_responses(&original, &replay);
        assert!(!diff.status_changed);
        assert!(!diff.body_changed);
        assert!(diff.header_changes.is_empty());
        assert_eq!(diff.original_status, 200);
        assert_eq!(diff.replay_status, 200);
        assert_eq!(diff.duration_delta_ms, 50.0);
    }

    #[test]
    fn detects_status_body_and_header_changes() {
        let original = exchange_with(
            Body::from_utf8_text("alpha\nbeta\n".to_string(), "text/plain"),
            200,
            vec![header("x-keep", "same"), header("x-remove", "old")],
        );
        let replay = replay_result(
            Body::from_utf8_text("alpha\ngamma\n".to_string(), "text/plain"),
            404,
            vec![header("x-keep", "same"), header("x-add", "new")],
        );

        let diff = diff_responses(&original, &replay);
        assert!(diff.status_changed);
        assert_eq!(diff.original_status, 200);
        assert_eq!(diff.replay_status, 404);
        assert!(diff.body_changed);

        assert_eq!(diff.header_changes.len(), 2);
        let removed = diff
            .header_changes
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case("x-remove"))
            .expect("removed header change");
        assert_eq!(removed.original.as_deref(), Some("old"));
        assert_eq!(removed.replay, None);

        let added = diff
            .header_changes
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case("x-add"))
            .expect("added header change");
        assert_eq!(added.original, None);
        assert_eq!(added.replay.as_deref(), Some("new"));

        assert!(
            diff.lines
                .iter()
                .any(|l| l.kind == "remove" && l.text == "beta")
        );
        assert!(
            diff.lines
                .iter()
                .any(|l| l.kind == "add" && l.text == "gamma")
        );
        assert!(
            diff.lines
                .iter()
                .any(|l| l.kind == "context" && l.text == "alpha")
        );
    }

    #[test]
    fn base64_bodies_are_compared_as_encoded_text() {
        let original = exchange_with(Body::from_base64("AAAA".to_string()), 200, Vec::new());
        let replay = replay_result(Body::from_base64("AAAA".to_string()), 200, Vec::new());

        let diff = diff_responses(&original, &replay);
        assert!(!diff.body_changed);
        assert_eq!(diff.lines.len(), 1);
        assert_eq!(diff.lines[0].kind, "context");

        let changed = replay_result(Body::from_base64("BBBB".to_string()), 200, Vec::new());
        let diff = diff_responses(&original, &changed);
        assert!(diff.body_changed);
        assert_eq!(diff.lines.len(), 1);
        assert_eq!(diff.lines[0].kind, "context");
    }

    #[test]
    fn binary_and_text_body_uses_encoded_comparison() {
        let original = exchange_with(Body::from_base64("AAAA".to_string()), 200, Vec::new());
        let replay = replay_result(
            Body::from_utf8_text("plain".to_string(), "text/plain"),
            200,
            Vec::new(),
        );

        let diff = diff_responses(&original, &replay);
        assert!(diff.body_changed);
        assert_eq!(diff.lines.len(), 1);
        assert_eq!(diff.lines[0].kind, "context");
    }

    #[test]
    fn redirect_policy_mapping() {
        assert_eq!(
            format!("{:?}", redirect_policy(true)),
            format!("{:?}", Policy::limited(10))
        );
        assert_eq!(
            format!("{:?}", redirect_policy(false)),
            format!("{:?}", Policy::none())
        );
    }

    #[test]
    fn header_filtering_removes_host_content_length_and_connection() {
        let headers = vec![
            header("Host", "example.com"),
            header("Content-Length", "42"),
            header("Connection", "keep-alive"),
            header("Cookie", "a=1"),
            header("Proxy-Authorization", "Basic c2VjcmV0"),
            header("Proxy-Connection", "keep-alive"),
            header("TE", "trailers"),
            header("Upgrade", "h2c"),
            header("Accept", "application/json"),
            header("User-Agent", "test"),
        ];

        let filtered = filter_request_headers(&headers);
        let names: Vec<&str> = filtered.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["Accept", "User-Agent"]);
    }

    #[test]
    fn cookies_merge_with_existing_cookie_header() {
        let headers = vec![header("Cookie", "session=abc")];
        let cookies = vec![
            KeyValue {
                name: "theme".to_string(),
                value: "dark".to_string(),
            },
            KeyValue {
                name: "lang".to_string(),
                value: "en".to_string(),
            },
        ];

        let merged = merged_cookie_header(&headers, &cookies).expect("merged cookie");
        assert_eq!(merged, "session=abc; theme=dark; lang=en");
    }

    #[test]
    fn cookies_without_existing_header() {
        let cookies = vec![KeyValue {
            name: "theme".to_string(),
            value: "dark".to_string(),
        }];
        assert_eq!(
            merged_cookie_header(&[], &cookies).as_deref(),
            Some("theme=dark")
        );
        assert_eq!(merged_cookie_header(&[], &[]), None);
    }

    #[test]
    fn request_body_base64_decode() {
        let body = Body {
            kind: BodyKindWire::Binary,
            text: "aGVsbG8=".to_string(),
            encoding: BodyEncoding::Base64,
        };
        assert_eq!(request_body(&body).unwrap(), Some(b"hello".to_vec()));

        let invalid = Body {
            kind: BodyKindWire::Binary,
            text: "!!!not-base64!!!".to_string(),
            encoding: BodyEncoding::Base64,
        };
        assert!(matches!(
            request_body(&invalid),
            Err(ReplayError::InvalidBody(_))
        ));
    }

    #[test]
    fn decode_body_handles_text_and_binary() {
        let text = decode_body(b"hello", "text/plain");
        assert_eq!(text.encoding, BodyEncoding::Utf8);
        assert_eq!(text.text, "hello");

        let binary = decode_body(&[0xff, 0xfe], "application/octet-stream");
        assert_eq!(binary.encoding, BodyEncoding::Base64);

        let invalid_utf8 = decode_body(&[0xff, 0xfe], "text/plain");
        assert_eq!(invalid_utf8.encoding, BodyEncoding::Base64);
    }

    #[test]
    fn diff_lines_truncates_at_limit() {
        let original: String = (0..500).map(|i| format!("line-{i}\n")).collect();
        let replay: String = (0..500).map(|i| format!("line-{i}-changed\n")).collect();

        let diff = diff_responses(
            &exchange_with(
                Body::from_utf8_text(original, "text/plain"),
                200,
                Vec::new(),
            ),
            &replay_result(Body::from_utf8_text(replay, "text/plain"), 200, Vec::new()),
        );

        assert!(diff.lines.len() <= MAX_DIFF_LINES);
        assert_eq!(diff.lines.len(), MAX_DIFF_LINES);
        assert_eq!(diff.lines.last().unwrap().text, TRUNCATED_LINE);
    }

    #[tokio::test]
    async fn app_proxy_without_proxy_returns_error() {
        let draft = draft("https://example.com/", ReplayProxyMode::AppProxy);
        let result = replay_with_proxy(&draft, None).await;
        assert!(matches!(result, Err(ReplayError::MissingProxy)));
    }

    #[tokio::test]
    async fn app_proxy_with_invalid_proxy_url_returns_error() {
        let draft = draft("https://example.com/", ReplayProxyMode::AppProxy);
        let result = replay_with_proxy(&draft, Some("not a url".to_string())).await;
        assert!(matches!(result, Err(ReplayError::InvalidProxy(_))));
    }

    #[tokio::test]
    async fn invalid_url_returns_error() {
        let draft = draft("not a url", ReplayProxyMode::Direct);
        let result = replay(&draft).await;
        assert!(matches!(result, Err(ReplayError::InvalidUrl(_))));
    }
}
