//! Local secret masking for the HTTP traffic analyzer.
//!
//! Everything in this crate is pure and local: no telemetry, no network calls.

use domain::{Body, BodyEncoding, Exchange, Header, KeyValue, SECRET_PLACEHOLDER};
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// Errors raised while validating CA material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecurityError {
    #[error("certificate PEM is empty")]
    EmptyCertificate,
    #[error("private key PEM is empty")]
    EmptyPrivateKey,
    #[error("certificate PEM does not contain a BEGIN CERTIFICATE block")]
    MissingCertificateBlock,
    #[error("private key PEM does not contain a BEGIN ... PRIVATE KEY block")]
    MissingPrivateKeyBlock,
    #[error("private key could not be converted: {0}")]
    InvalidPrivateKey(String),
}

fn ascii_lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

fn canonical_key(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_sep = false;
    for ch in lower.chars() {
        if ch == '_' || ch == '-' {
            if !prev_sep {
                out.push('_');
                prev_sep = true;
            }
        } else {
            out.push(ch);
            prev_sep = false;
        }
    }
    out
}

/// Returns true when a header name is expected to carry a secret value.
pub fn is_sensitive_header(name: &str) -> bool {
    let lower = ascii_lower(name.trim());
    if lower.is_empty() {
        return false;
    }
    matches!(
        lower.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-csrf-token"
    ) || lower.contains("token")
        || lower.contains("api-key")
        || lower.contains("apikey")
        || lower.contains("secret")
        || lower.contains("session")
        || lower.contains("auth")
        || lower.contains("password")
}

/// Returns true when a JSON or query parameter key is expected to carry a secret.
///
/// Keys are normalized so `accessToken`, `access_token` and `access-token` all
/// match. CamelCase keys matter because they are common in JSON APIs.
pub fn is_sensitive_key(name: &str) -> bool {
    let key = canonical_key(name);
    if key.is_empty() {
        return false;
    }
    let compact: String = key.chars().filter(|ch| *ch != '_').collect();
    matches!(
        compact.as_str(),
        "password"
            | "passwd"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "apikey"
            | "secret"
            | "clientsecret"
            | "authorization"
            | "cookie"
            | "cookies"
            | "setcookie"
            | "session"
            | "sessionid"
            | "sessiontoken"
            | "sessionkey"
            | "csrftoken"
            | "csrf"
            | "auth"
            | "jwt"
            | "sid"
            | "credential"
            | "credentials"
            | "bearer"
            | "privatekey"
    ) || compact.contains("token")
        || compact.contains("secret")
        || compact.contains("password")
        || compact.contains("apikey")
        || compact.contains("credential")
        || compact.contains("jwt")
        || compact.ends_with("sid")
        || compact == "authorization"
}

/// Masks a secret value, keeping a short auth-scheme prefix when present.
pub fn mask_value(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    if let Some((scheme, _rest)) = value.split_once(' ') {
        if scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("basic") {
            return format!("{scheme} {SECRET_PLACEHOLDER}");
        }
    }
    SECRET_PLACEHOLDER.to_string()
}

/// Masks the values of sensitive headers, preserving names and order.
pub fn mask_headers(headers: &[Header]) -> Vec<Header> {
    headers
        .iter()
        .map(|header| {
            if is_sensitive_header(&header.name) {
                Header::new(header.name.clone(), mask_value(&header.value))
            } else {
                header.clone()
            }
        })
        .collect()
}

/// Masks the values of sensitive cookie/query rows, preserving names and order.
pub fn mask_kv(rows: &[KeyValue]) -> Vec<KeyValue> {
    rows.iter()
        .map(|row| {
            if is_sensitive_key(&row.name) {
                KeyValue {
                    name: row.name.clone(),
                    value: mask_value(&row.value),
                }
            } else {
                row.clone()
            }
        })
        .collect()
}

fn header_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?im)^([ \t]*)(authorization|cookie|set-cookie)[ \t]*:[ \t]*(.*)$")
            .expect("valid header redaction regex")
    })
}

fn query_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Also matches a form/query body that starts the text, so
        // `password=hunter2&user=bob` is redacted from its first field.
        Regex::new(
            r#"(?im)(^|[?&])((?:token|api_key|apikey|access_token|refresh_token|id_token|client_secret|password|passwd|secret|session|session_id|csrf|auth|authorization|cookie)=)([^&\s#"']*)"#,
        )
        .expect("valid query redaction regex")
    })
}

fn json_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)("(?:password|passwd|token|access_token|refresh_token|id_token|api_key|apikey|secret|client_secret|authorization|cookie|session|session_id|csrf)"\s*:\s*")[^"]*(")"#,
        )
        .expect("valid json redaction regex")
    })
}

fn bearer_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+").expect("valid bearer redaction regex")
    })
}

fn basic_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bBasic\s+[A-Za-z0-9+/=]+").expect("valid basic redaction regex")
    })
}

fn userinfo_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(https?://)([^\s/:@]+):([^\s/@]+)@").expect("valid url userinfo regex")
    })
}

fn header_template_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(-H|--header)\s+("([^"]*)"|'([^']*)')"#).expect("valid curl header regex")
    })
}

fn cookie_flag_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(--cookie(?:-jar)?|-b)\s+("([^"]*)"|'([^']*)')"#)
            .expect("valid curl cookie regex")
    })
}

fn cookie_flag_unquoted_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(--cookie|-b)\s+([^\s'"]+)"#).expect("valid curl cookie regex")
    })
}

/// Regex/scan-based redaction of secrets embedded in free text.
pub fn redact_text(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }

    let mut out = header_regex()
        .replace_all(text, |caps: &regex::Captures<'_>| {
            let indent = &caps[1];
            let name = &caps[2];
            let value = &caps[3];
            format!("{indent}{name}: {}", mask_value(value))
        })
        .into_owned();

    out = json_regex()
        .replace_all(&out, |caps: &regex::Captures<'_>| {
            format!("{}{}{}", &caps[1], SECRET_PLACEHOLDER, &caps[2])
        })
        .into_owned();

    out = query_regex()
        .replace_all(&out, |caps: &regex::Captures<'_>| {
            format!("{}{}{}", &caps[1], &caps[2], SECRET_PLACEHOLDER)
        })
        .into_owned();

    out = bearer_regex()
        .replace_all(&out, format!("Bearer {SECRET_PLACEHOLDER}"))
        .into_owned();

    out = basic_regex()
        .replace_all(&out, format!("Basic {SECRET_PLACEHOLDER}"))
        .into_owned();

    out = userinfo_regex()
        .replace_all(&out, |caps: &regex::Captures<'_>| {
            format!("{}{}:{SECRET_PLACEHOLDER}@", &caps[1], &caps[2])
        })
        .into_owned();

    out
}

fn redact_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *child = Value::String(SECRET_PLACEHOLDER.to_string());
                } else {
                    redact_json_value(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json_value(item);
            }
        }
        _ => {}
    }
}

/// Recursively redacts sensitive JSON fields; falls back to text redaction.
pub fn redact_json(text: &str) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(mut value) => {
            redact_json_value(&mut value);
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| redact_text(text))
        }
        Err(_) => redact_text(text),
    }
}

fn redact_body(body: &Body) -> Body {
    if body.text.is_empty() {
        return body.clone();
    }
    if body.encoding == BodyEncoding::Base64 {
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            body.text.as_bytes(),
        )
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok());
        return match decoded {
            Some(text) => {
                let redacted = if body.kind == domain::BodyKindWire::Json {
                    redact_json(&text)
                } else {
                    redact_text(&text)
                };
                Body {
                    kind: body.kind,
                    text: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        redacted.as_bytes(),
                    ),
                    encoding: BodyEncoding::Base64,
                }
            }
            // Opaque binary cannot be inspected safely, so its bytes never
            // reach an export surface.
            None => Body {
                kind: domain::BodyKindWire::Text,
                text: SECRET_PLACEHOLDER.to_string(),
                encoding: BodyEncoding::Utf8,
            },
        };
    }
    let text = if body.kind == domain::BodyKindWire::Json {
        redact_json(&body.text)
    } else {
        redact_text(&body.text)
    };
    Body {
        kind: body.kind,
        text,
        encoding: body.encoding,
    }
}

/// Returns a masked clone of an exchange; the original is left untouched.
pub fn mask_exchange(exchange: &Exchange) -> Exchange {
    let mut masked = exchange.clone();
    masked.url = redact_text(&exchange.url);
    masked.path = redact_text(&exchange.path);
    masked.request_headers = mask_headers(&exchange.request_headers);
    masked.response_headers = mask_headers(&exchange.response_headers);
    masked.cookies = mask_kv(&exchange.cookies);
    masked.query = mask_kv(&exchange.query);
    masked.request_body = redact_body(&exchange.request_body);
    masked.response_body = redact_body(&exchange.response_body);
    masked.raw_request = redact_text(&exchange.raw_request);
    masked.raw_response = redact_text(&exchange.raw_response);
    masked
}

fn mask_curl_header(header: &str) -> String {
    if let Some((name, value)) = header.split_once(':') {
        if is_sensitive_header(name) {
            return format!("{}: {}", name.trim(), mask_value(value.trim()));
        }
    }
    header.to_string()
}

/// Redacts secrets from a curl command line.
pub fn redact_curl(curl: &str) -> String {
    if curl.is_empty() {
        return String::new();
    }

    let mut out = header_template_regex()
        .replace_all(curl, |caps: &regex::Captures<'_>| {
            let flag = &caps[1];
            let quoted = &caps[2];
            let inner = caps
                .get(3)
                .or_else(|| caps.get(4))
                .map_or("", |m| m.as_str());
            let quote = &quoted[..1.min(quoted.len())];
            format!("{flag} {quote}{}{quote}", mask_curl_header(inner))
        })
        .into_owned();

    out = cookie_flag_regex()
        .replace_all(&out, |caps: &regex::Captures<'_>| {
            let flag = &caps[1];
            let quoted = &caps[2];
            let quote = &quoted[..1.min(quoted.len())];
            format!("{flag} {quote}{SECRET_PLACEHOLDER}{quote}")
        })
        .into_owned();

    out = cookie_flag_unquoted_regex()
        .replace_all(&out, |caps: &regex::Captures<'_>| {
            format!("{} {SECRET_PLACEHOLDER}", &caps[1])
        })
        .into_owned();

    redact_text(&out)
}

/// Normalizes PEM input: real newlines, trimmed, with a trailing newline.
pub fn normalize_pem(input: &str) -> String {
    let normalized = input.trim().replace("\\n", "\n");
    if normalized.is_empty() {
        return String::new();
    }
    let mut out = normalized.trim().to_string();
    out.push('\n');
    out
}

fn has_pem_block<F>(pem: &str, matches_label: F) -> bool
where
    F: Fn(&str) -> bool,
{
    let normalized = normalize_pem(pem);
    let lines: Vec<&str> = normalized.lines().map(str::trim).collect();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if let Some(label) = pem_marker_label(line, "BEGIN") {
            if matches_label(label) {
                let end_marker = format!("-----END {label}-----");
                if lines[index + 1..].iter().any(|l| *l == end_marker) {
                    return true;
                }
            }
        }
        index += 1;
    }
    false
}

fn pem_marker_label<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let prefix = format!("-----{marker} ");
    let rest = line.strip_prefix(&prefix)?;
    let label = rest.strip_suffix("-----")?;
    if label.is_empty() {
        None
    } else {
        Some(label)
    }
}

/// Validates that the supplied certificate and key PEM material look usable.
pub fn validate_ca_material(cert_pem: &str, key_pem: &str) -> Result<(), SecurityError> {
    if normalize_pem(cert_pem).is_empty() {
        return Err(SecurityError::EmptyCertificate);
    }
    if normalize_pem(key_pem).is_empty() {
        return Err(SecurityError::EmptyPrivateKey);
    }
    if !has_pem_block(cert_pem, |label| label == "CERTIFICATE") {
        return Err(SecurityError::MissingCertificateBlock);
    }
    if !has_pem_block(key_pem, |label| label.contains("PRIVATE KEY")) {
        return Err(SecurityError::MissingPrivateKeyBlock);
    }
    Ok(())
}

/// A certificate and private key extracted from a combined PEM bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaMaterial {
    pub cert_pem: String,
    pub key_pem: String,
}

fn extract_pem_block(pem: &str, label: &str) -> Option<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let normalized = normalize_pem(pem);
    let start = normalized.find(&begin)?;
    let stop = normalized[start..].find(&end)? + start + end.len();
    Some(normalized[start..stop].to_string())
}

/// Splits a combined PEM (as written by mitmproxy) into certificate and key.
pub fn split_pem_bundle(bundle: &str) -> Result<CaMaterial, SecurityError> {
    let cert =
        extract_pem_block(bundle, "CERTIFICATE").ok_or(SecurityError::MissingCertificateBlock)?;
    let key = extract_pem_block(bundle, "PRIVATE KEY")
        .or_else(|| extract_pem_block(bundle, "RSA PRIVATE KEY"))
        .or_else(|| extract_pem_block(bundle, "EC PRIVATE KEY"))
        .ok_or(SecurityError::MissingPrivateKeyBlock)?;
    Ok(CaMaterial {
        cert_pem: format!("{}\n", cert.trim()),
        key_pem: format!("{}\n", key.trim()),
    })
}

/// Converts legacy `RSA PRIVATE KEY` (PKCS#1) material to PKCS#8, which the
/// TLS stack accepts. PKCS#8 keys are returned unchanged.
pub fn normalize_private_key_pem(key_pem: &str) -> Result<String, SecurityError> {
    let normalized = normalize_pem(key_pem);
    if normalized.contains("BEGIN RSA PRIVATE KEY") {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::EncodePrivateKey;
        let key = rsa::RsaPrivateKey::from_pkcs1_pem(&normalized)
            .map_err(|e| SecurityError::InvalidPrivateKey(e.to_string()))?;
        let pem = key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| SecurityError::InvalidPrivateKey(e.to_string()))?;
        return Ok(pem.to_string());
    }
    if !normalized.contains("PRIVATE KEY") {
        return Err(SecurityError::MissingPrivateKeyBlock);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::{BodyKindWire, TimingPhase};

    fn sample_exchange() -> Exchange {
        Exchange {
            id: "ex_1".to_string(),
            session_id: "sess_1".to_string(),
            sequence: 1,
            captured_at: "2026-01-01T00:00:00Z".to_string(),
            method: "GET".to_string(),
            url: "https://example.com/api?token=supersecret&safe=1".to_string(),
            host: "example.com".to_string(),
            path: "/api".to_string(),
            status: 200,
            duration_ms: 12.5,
            request_bytes: 100,
            response_bytes: 200,
            content_type: "application/json".to_string(),
            error: None,
            request_headers: vec![
                Header::new("Authorization", "Bearer topsecret"),
                Header::new("Accept", "application/json"),
            ],
            response_headers: vec![Header::new("Set-Cookie", "session=abc123")],
            query: vec![
                KeyValue {
                    name: "token".to_string(),
                    value: "supersecret".to_string(),
                },
                KeyValue {
                    name: "safe".to_string(),
                    value: "1".to_string(),
                },
            ],
            cookies: vec![KeyValue {
                name: "session".to_string(),
                value: "abc123".to_string(),
            }],
            request_body: Body {
                kind: BodyKindWire::Json,
                text: r#"{"password":"hunter2","name":"bob"}"#.to_string(),
                encoding: BodyEncoding::Utf8,
            },
            response_body: Body {
                kind: BodyKindWire::Binary,
                text: "AAECAwQ=".to_string(),
                encoding: BodyEncoding::Base64,
            },
            raw_request:
                "GET /api?token=supersecret HTTP/1.1\r\nAuthorization: Bearer topsecret\r\n\r\n"
                    .to_string(),
            raw_response: "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\n\r\n".to_string(),
            timing: Vec::<TimingPhase>::new(),
        }
    }

    #[test]
    fn masks_authorization_header() {
        let headers = vec![Header::new("Authorization", "Bearer abc123")];
        let masked = mask_headers(&headers);
        assert_eq!(masked[0].name, "Authorization");
        assert_eq!(masked[0].value, format!("Bearer {SECRET_PLACEHOLDER}"));
        assert!(!masked[0].value.contains("abc123"));
    }

    #[test]
    fn masks_cookies() {
        let rows = vec![
            KeyValue {
                name: "session".to_string(),
                value: "cookie-secret".to_string(),
            },
            KeyValue {
                name: "theme".to_string(),
                value: "dark".to_string(),
            },
        ];
        let masked = mask_kv(&rows);
        assert_eq!(masked[0].value, SECRET_PLACEHOLDER);
        assert_eq!(masked[1].value, "dark");
    }

    #[test]
    fn redacts_json_tokens() {
        let input = r#"{"token":"abc","access_token":"def","name":"bob"}"#;
        let output = redact_json(input);
        assert!(!output.contains("abc"));
        assert!(!output.contains("def"));
        assert!(output.contains("bob"));
        assert!(output.contains(SECRET_PLACEHOLDER));
    }

    #[test]
    fn redacts_query_tokens() {
        let output = redact_text("GET /x?token=abc&api_key=def&safe=1 HTTP/1.1");
        assert!(!output.contains("abc"));
        assert!(!output.contains("def"));
        assert!(output.contains("safe=1"));
        assert!(output.contains("token="));
    }

    #[test]
    fn masks_structured_auth_jwt_and_sid_names() {
        let rows = vec![
            KeyValue {
                name: "auth".to_string(),
                value: "auth-secret".to_string(),
            },
            KeyValue {
                name: "jwt".to_string(),
                value: "jwt-secret".to_string(),
            },
            KeyValue {
                name: "connect.sid".to_string(),
                value: "sid-secret".to_string(),
            },
            KeyValue {
                name: "credential".to_string(),
                value: "cred-secret".to_string(),
            },
            KeyValue {
                name: "theme".to_string(),
                value: "dark".to_string(),
            },
        ];
        let masked = mask_kv(&rows);
        for row in &masked[..4] {
            assert_eq!(row.value, SECRET_PLACEHOLDER, "{}", row.name);
        }
        assert_eq!(masked[4].value, "dark");
    }

    #[test]
    fn redacts_url_userinfo() {
        let output = redact_text("https://user:hunter2@example.com/path");
        assert!(!output.contains("hunter2"));
        assert!(output.contains("user:"));
        assert!(output.contains("example.com"));
    }

    #[test]
    fn preserves_bearer_prefix() {
        assert_eq!(
            mask_value("Bearer abc.def"),
            format!("Bearer {SECRET_PLACEHOLDER}")
        );
        assert_eq!(
            mask_value("Basic dXNlcjpwYXNz"),
            format!("Basic {SECRET_PLACEHOLDER}")
        );
        assert_eq!(mask_value(""), "");
    }

    #[test]
    fn mask_exchange_does_not_mutate_original() {
        let exchange = sample_exchange();
        let original = exchange.clone();
        let masked = mask_exchange(&exchange);
        assert_eq!(exchange, original);
        assert_ne!(masked, original);
        assert_eq!(
            masked.request_headers[0].value,
            format!("Bearer {SECRET_PLACEHOLDER}")
        );
        assert_eq!(masked.query[0].value, SECRET_PLACEHOLDER);
        assert_eq!(masked.query[1].value, "1");
        assert_eq!(masked.response_body.text, "AAECAwQ=");
        assert!(!masked.raw_request.contains("topsecret"));
        assert!(!masked.raw_response.contains("abc123"));
        assert!(!masked.request_body.text.contains("hunter2"));
    }

    #[test]
    fn redact_curl_removes_secret() {
        let curl = "curl -H 'Authorization: Bearer s3cr3t' --cookie 'session=abc' https://x.test";
        let output = redact_curl(curl);
        assert!(!output.contains("s3cr3t"));
        assert!(!output.contains("session=abc"));
        assert!(output.contains(SECRET_PLACEHOLDER));
    }

    #[test]
    fn validates_pem_material() {
        let cert = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n";
        let key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG\n-----END PRIVATE KEY-----\n";
        assert_eq!(validate_ca_material(cert, key), Ok(()));
        assert!(validate_ca_material("garbage", key).is_err());
        assert!(validate_ca_material(cert, "garbage").is_err());
        assert!(validate_ca_material("", key).is_err());
        assert!(validate_ca_material(cert, "").is_err());
    }

    #[test]
    fn normalizes_literal_newlines() {
        let input = "  -----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----  ";
        let normalized = normalize_pem(input);
        assert!(normalized.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(normalized.ends_with('\n'));
        assert!(!normalized.contains("\\n"));
    }
}

#[cfg(test)]
mod ca_material_tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::LineEnding;

    #[test]
    fn converts_pkcs1_rsa_key_to_pkcs8() {
        let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).expect("rsa key");
        let pkcs1 = key.to_pkcs1_pem(LineEnding::LF).expect("pkcs1");
        assert!(pkcs1.contains("BEGIN RSA PRIVATE KEY"));
        let converted = normalize_private_key_pem(&pkcs1).expect("converted");
        assert!(converted.contains("BEGIN PRIVATE KEY"));
        assert!(!converted.contains("RSA PRIVATE KEY"));
    }

    #[test]
    fn splits_combined_bundle() {
        let cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----";
        let bundle = format!("{key}\n{cert}\n");
        let material = split_pem_bundle(&bundle).expect("split");
        assert!(material.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(material.key_pem.contains("BEGIN RSA PRIVATE KEY"));
    }
}
