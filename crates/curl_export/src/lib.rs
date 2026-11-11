//! Render captured exchanges and drafts as replayable curl commands for
//! Bash, PowerShell and CMD.

use domain::{BodyEncoding, CurlBundle, Draft, Exchange, KeyValue, ReplayOptions};

const FORBIDDEN_HEADERS: [&str; 4] = ["content-length", "host", "connection", "transfer-encoding"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurlTarget {
    Bash,
    PowerShell,
    Cmd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurlRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub body_encoding: BodyEncoding,
    pub options: ReplayOptions,
}

impl CurlRequest {
    pub fn from_exchange(exchange: &Exchange) -> Self {
        let mut headers = collect_headers(&exchange.request_headers);
        append_cookies(&mut headers, &exchange.cookies);
        let body = non_empty_body(&exchange.request_body.text);
        Self {
            method: exchange.method.clone(),
            url: exchange_url(exchange),
            headers,
            body,
            body_encoding: exchange.request_body.encoding,
            options: ReplayOptions::default(),
        }
    }

    pub fn from_draft(draft: &Draft) -> Self {
        let mut headers = collect_headers(&draft.headers);
        append_cookies(&mut headers, &draft.cookies);
        let body = non_empty_body(&draft.body.text);
        Self {
            method: draft.method.clone(),
            url: draft.url.clone(),
            headers,
            body,
            body_encoding: draft.body.encoding,
            options: draft.options.clone(),
        }
    }

    pub fn render(&self, target: CurlTarget, redact: bool) -> String {
        match target {
            CurlTarget::Bash => self.render_bash(redact),
            CurlTarget::PowerShell => self.render_powershell(redact),
            CurlTarget::Cmd => self.render_cmd(redact),
        }
    }

    fn rendered_url(&self, redact: bool) -> String {
        if redact {
            security::redact_text(&self.url)
        } else {
            self.url.clone()
        }
    }

    fn render_bash(&self, redact: bool) -> String {
        let mut parts = Vec::new();
        parts.push(format!("--request {}", sh_quote(&self.method)));
        parts.push(format!("--url {}", sh_quote(&self.rendered_url(redact))));
        for (name, value) in self.rendered_headers(redact) {
            parts.push(format!(
                "--header {}",
                sh_quote(&format!("{name}: {value}"))
            ));
        }
        if self.is_binary_body() {
            parts.push("--data-binary @body.bin".to_string());
        } else if let Some(body) = self.rendered_body(redact) {
            parts.push(format!("--data-raw {}", sh_quote(&body)));
        }
        parts.push(format!("--max-time {}", self.timeout_secs()));
        if !self.options.follow_redirects {
            parts.push("--max-redirs 0".to_string());
        }

        let mut out = String::from("curl");
        for part in parts {
            out.push_str(" \\\n  ");
            out.push_str(&part);
        }
        if self.is_binary_body() {
            out.insert_str(0, "# Decode the captured body into body.bin first.\n");
        }
        out
    }

    fn render_powershell(&self, redact: bool) -> String {
        let mut out = String::from("Invoke-WebRequest");
        out.push_str(&format!(" -Method {}", ps_quote(&self.method)));
        out.push_str(&format!(" -Uri {}", ps_quote(&self.rendered_url(redact))));

        let headers = self.rendered_headers(redact);
        if !headers.is_empty() {
            let inner = headers
                .iter()
                .map(|(name, value)| format!("{} = {}", ps_quote(name), ps_quote(value)))
                .collect::<Vec<_>>()
                .join("; ");
            out.push_str(&format!(" -Headers @{{ {inner} }}"));
        }

        if self.is_binary_body() {
            out.push_str(" -InFile body.bin");
        } else if let Some(body) = self.rendered_body(redact) {
            out.push_str(&format!(" -Body {}", ps_quote(&body)));
        }

        out.push_str(&format!(" -TimeoutSec {}", self.timeout_secs()));
        if !self.options.follow_redirects {
            out.push_str(" -MaximumRedirection 0");
        }
        if self.is_binary_body() {
            out.insert_str(0, "# Decode the captured body into body.bin first.\n");
        }
        out
    }

    fn render_cmd(&self, redact: bool) -> String {
        let mut parts = vec!["curl.exe".to_string()];
        parts.push(format!("--request {}", cmd_quote(&self.method)));
        parts.push(format!("--url {}", cmd_quote(&self.rendered_url(redact))));
        for (name, value) in self.rendered_headers(redact) {
            parts.push(format!(
                "--header {}",
                cmd_quote(&format!("{name}: {value}"))
            ));
        }
        let file_body = self.is_binary_body() || self.body_has_newlines();
        if file_body {
            parts.push("--data-binary @body.bin".to_string());
        } else if let Some(body) = self.rendered_body(redact) {
            parts.push(format!("--data-raw {}", cmd_quote(&body)));
        }
        parts.push(format!("--max-time {}", self.timeout_secs()));
        if !self.options.follow_redirects {
            parts.push("--max-redirs 0".to_string());
        }
        let mut out = parts.join(" ");
        if file_body {
            out.insert_str(
                0,
                "REM Save the captured request body as body.bin first.\r\n",
            );
        }
        out
    }

    fn body_has_newlines(&self) -> bool {
        if matches!(self.method.to_ascii_uppercase().as_str(), "GET" | "HEAD") {
            return false;
        }
        self.body
            .as_deref()
            .is_some_and(|body| body.contains('\n') || body.contains('\r'))
    }

    fn is_binary_body(&self) -> bool {
        self.body.is_some()
            && self.body_encoding == BodyEncoding::Base64
            && !matches!(self.method.to_ascii_uppercase().as_str(), "GET" | "HEAD")
    }

    fn rendered_headers(&self, redact: bool) -> Vec<(String, String)> {
        self.headers
            .iter()
            .map(|(name, value)| {
                let value = if redact {
                    redact_header_value(name, value)
                } else {
                    value.clone()
                };
                (name.clone(), value)
            })
            .collect()
    }

    fn rendered_body(&self, redact: bool) -> Option<String> {
        let body = self.body.as_deref()?;
        if body.is_empty() {
            return None;
        }
        if matches!(self.method.to_ascii_uppercase().as_str(), "GET" | "HEAD") {
            return None;
        }
        Some(if redact {
            let trimmed = body.trim_start();
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                security::redact_json(body)
            } else {
                security::redact_text(body)
            }
        } else {
            body.to_string()
        })
    }

    fn timeout_secs(&self) -> u64 {
        let ms = self.options.timeout_ms;
        if ms == 0 { 0 } else { ms.div_ceil(1000) }
    }
}

pub fn render_bundle(req: &CurlRequest, redact: bool) -> CurlBundle {
    CurlBundle {
        bash: req.render(CurlTarget::Bash, redact),
        powershell: req.render(CurlTarget::PowerShell, redact),
        cmd: req.render(CurlTarget::Cmd, redact),
    }
}

pub fn generate(exchange: &Exchange, redact: bool) -> CurlBundle {
    render_bundle(&CurlRequest::from_exchange(exchange), redact)
}

pub fn generate_from_draft(draft: &Draft, redact: bool) -> CurlBundle {
    render_bundle(&CurlRequest::from_draft(draft), redact)
}

fn collect_headers(headers: &[domain::Header]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|h| !is_forbidden_header(&h.name))
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect()
}

fn is_forbidden_header(name: &str) -> bool {
    FORBIDDEN_HEADERS
        .iter()
        .any(|f| name.eq_ignore_ascii_case(f))
}

fn append_cookies(headers: &mut Vec<(String, String)>, cookies: &[KeyValue]) {
    if cookies.is_empty() {
        return;
    }
    let existing = headers
        .iter()
        .position(|(name, _)| name.eq_ignore_ascii_case("cookie"));
    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(index) = existing {
        for part in headers[index].1.split(';') {
            let part = part.trim();
            if let Some((name, value)) = part.split_once('=') {
                pairs.push((name.trim().to_string(), value.trim().to_string()));
            }
        }
    }
    // Parsed cookies and a raw Cookie header describe the same jar; keep one
    // copy per name so replay does not send duplicates.
    for cookie in cookies {
        if let Some(slot) = pairs.iter_mut().find(|(name, _)| name == &cookie.name) {
            slot.1 = cookie.value.clone();
        } else {
            pairs.push((cookie.name.clone(), cookie.value.clone()));
        }
    }
    let joined = pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    match existing {
        Some(index) => headers[index].1 = joined,
        None => headers.push(("Cookie".to_string(), joined)),
    }
}

fn non_empty_body(text: &str) -> Option<String> {
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn exchange_url(exchange: &Exchange) -> String {
    if exchange.url.to_ascii_lowercase().starts_with("http") {
        return exchange.url.clone();
    }
    let path = if exchange.path.is_empty() {
        "/"
    } else {
        exchange.path.as_str()
    };
    format!("https://{}{}", exchange.host, path)
}

fn redact_header_value(name: &str, value: &str) -> String {
    if security::is_sensitive_header(name) {
        return domain::SECRET_PLACEHOLDER.to_string();
    }
    if name.eq_ignore_ascii_case("cookie") {
        return mask_cookie_header(value);
    }
    value.to_string()
}

fn mask_cookie_header(value: &str) -> String {
    value
        .split(';')
        .map(|part| {
            let trimmed = part.trim();
            match trimmed.split_once('=') {
                Some((key, _)) => format!("{key}={}", domain::SECRET_PLACEHOLDER),
                None => trimmed.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn cmd_quote(value: &str) -> String {
    // cmd.exe does not treat `\"` as an escaped quote: it closes the quoted
    // region and exposes `&`, `|` and friends to the shell. Doubling the quote
    // keeps the whole argument quoted, and `%%` stops `%VAR%` expansion.
    // Newlines terminate a CMD command even inside quotes, so they are folded
    // into spaces as a last-resort guard (bodies with newlines use a file).
    let escaped = value
        .replace(['\r', '\n'], " ")
        .replace('"', "\"\"")
        .replace('%', "%%");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::{Body, Header};

    fn make_exchange(
        method: &str,
        url: &str,
        headers: Vec<Header>,
        cookies: Vec<KeyValue>,
        body: &str,
    ) -> Exchange {
        Exchange {
            id: "ex_1".into(),
            session_id: "sess_1".into(),
            sequence: 1,
            captured_at: "2026-01-01T00:00:00Z".into(),
            method: method.into(),
            url: url.into(),
            host: "api.example.com".into(),
            path: "/v1/items".into(),
            status: 200,
            duration_ms: 12.0,
            request_bytes: body.len(),
            response_bytes: 0,
            content_type: "application/json".into(),
            error: None,
            request_headers: headers,
            response_headers: Vec::new(),
            query: Vec::new(),
            cookies,
            request_body: Body::from_utf8_text(body.to_string(), "application/json"),
            response_body: Body::empty(),
            raw_request: String::new(),
            raw_response: String::new(),
            timing: Vec::new(),
        }
    }

    #[test]
    fn bash_post_has_expected_flags() {
        let exchange = make_exchange(
            "POST",
            "https://api.example.com/v1/items",
            vec![Header::new("Content-Type", "application/json")],
            Vec::new(),
            "{\"a\":1}",
        );
        let bundle = generate(&exchange, false);
        assert!(bundle.bash.contains("--request 'POST'"));
        assert!(bundle.bash.contains("--header"));
        assert!(bundle.bash.contains("--data-raw"));
        assert!(bundle.bash.contains("https://api.example.com/v1/items"));
    }

    #[test]
    fn bash_escapes_single_quotes_in_body() {
        let exchange = make_exchange(
            "POST",
            "https://api.example.com/v1/items",
            Vec::new(),
            Vec::new(),
            "it's fine",
        );
        let bundle = generate(&exchange, false);
        assert!(bundle.bash.contains("'it'\\''s fine'"));
    }

    #[test]
    fn powershell_prefix_and_quote_escaping() {
        let mut exchange = make_exchange(
            "POST",
            "https://api.example.com/v1/items",
            vec![Header::new("X-Test", "a'b")],
            Vec::new(),
            "it's",
        );
        exchange
            .request_headers
            .push(Header::new("X-Other", "plain"));
        let bundle = generate(&exchange, false);
        assert!(bundle.powershell.starts_with("Invoke-WebRequest"));
        assert!(bundle.powershell.contains("'a''b'"));
        assert!(bundle.powershell.contains("'it''s'"));
    }

    #[test]
    fn cmd_uses_curl_exe_and_double_quotes() {
        let exchange = make_exchange(
            "POST",
            "https://api.example.com/v1/items",
            vec![Header::new("Content-Type", "application/json")],
            Vec::new(),
            "{\"a\":1}",
        );
        let bundle = generate(&exchange, false);
        assert!(bundle.cmd.starts_with("curl.exe "));
        assert!(bundle.cmd.contains("\"https://api.example.com/v1/items\""));
        assert!(bundle.cmd.contains("--data-raw \"{\"\"a\"\":1}\""));
    }

    #[test]
    fn cmd_quotes_cannot_break_out_of_the_argument() {
        let exchange = make_exchange(
            "POST",
            "https://api.example.com/v1/items",
            Vec::new(),
            Vec::new(),
            "x\" & calc & \"",
        );
        let bundle = generate(&exchange, false);
        assert!(bundle.cmd.contains("\"\" & calc & \"\""));
        assert!(!bundle.cmd.contains("x\" & calc"));
    }

    #[test]
    fn cmd_body_with_newlines_is_written_to_a_file_instead_of_inlined() {
        let exchange = make_exchange(
            "POST",
            "https://api.example.com/v1/items",
            Vec::new(),
            Vec::new(),
            "line one\r\n& calc\r\nline two",
        );
        let bundle = generate(&exchange, false);
        assert!(bundle.cmd.contains("--data-binary @body.bin"));
        assert!(!bundle.cmd.contains("calc"));
        assert!(!bundle.cmd.contains("--data-raw"));
        assert!(bundle.cmd.starts_with("REM "));
    }

    #[test]
    fn cookies_are_not_duplicated() {
        let exchange = make_exchange(
            "GET",
            "https://api.example.com/v1/items",
            vec![Header::new("Cookie", "session=one; theme=dark")],
            vec![KeyValue {
                name: "session".into(),
                value: "two".into(),
            }],
            "",
        );
        let bundle = generate(&exchange, false);
        assert!(bundle.bash.contains("session=two"));
        assert!(!bundle.bash.contains("session=one"));
        assert_eq!(bundle.bash.matches("theme=dark").count(), 1);
        assert_eq!(bundle.bash.matches("session=").count(), 1);
    }

    #[test]
    fn form_body_secrets_are_redacted() {
        let exchange = make_exchange(
            "POST",
            "https://api.example.com/v1/items",
            Vec::new(),
            Vec::new(),
            "password=hunter2&user=bob",
        );
        let bundle = generate(&exchange, true);
        for rendered in [&bundle.bash, &bundle.powershell, &bundle.cmd] {
            assert!(!rendered.contains("hunter2"), "{rendered}");
            assert!(rendered.contains(domain::SECRET_PLACEHOLDER), "{rendered}");
        }
    }

    #[test]
    fn binary_body_is_not_exported_as_base64_text() {
        let mut exchange = make_exchange(
            "POST",
            "https://api.example.com/v1/items",
            vec![],
            vec![],
            "",
        );
        exchange.request_body = Body::from_base64("AAECAwQ=".into());
        let bundle = generate(&exchange, false);
        assert!(bundle.bash.contains("--data-binary @body.bin"));
        assert!(!bundle.bash.contains("AAECAwQ="));
        assert!(bundle.cmd.contains("--data-binary @body.bin"));
    }

    #[test]
    fn redacted_output_hides_secrets() {
        let exchange = make_exchange(
            "POST",
            "https://api.example.com/v1/items",
            vec![Header::new("Authorization", "Bearer abcsecret")],
            vec![KeyValue {
                name: "session".into(),
                value: "supersecret".into(),
            }],
            "token=abcsecret",
        );
        let bundle = generate(&exchange, true);
        for rendered in [&bundle.bash, &bundle.powershell, &bundle.cmd] {
            assert!(!rendered.contains("Bearer abcsecret"));
            assert!(!rendered.contains("session=supersecret"));
            assert!(rendered.contains(domain::SECRET_PLACEHOLDER));
        }
    }

    #[test]
    fn redacted_output_hides_query_secrets() {
        let exchange = make_exchange(
            "GET",
            "https://api.example.com/items?token=querysecret&safe=1",
            vec![],
            vec![],
            "",
        );
        let bundle = generate(&exchange, true);
        for rendered in [&bundle.bash, &bundle.powershell, &bundle.cmd] {
            assert!(!rendered.contains("querysecret"), "{rendered}");
        }
    }

    #[test]
    fn forbidden_headers_are_omitted() {
        let exchange = make_exchange(
            "POST",
            "https://api.example.com/v1/items",
            vec![
                Header::new("Content-Length", "42"),
                Header::new("Host", "api.example.com"),
                Header::new("Connection", "keep-alive"),
                Header::new("Transfer-Encoding", "chunked"),
            ],
            Vec::new(),
            "{}",
        );
        let bundle = generate(&exchange, false);
        assert!(!bundle.bash.to_ascii_lowercase().contains("content-length"));
        assert!(
            !bundle
                .bash
                .to_ascii_lowercase()
                .contains("transfer-encoding")
        );
    }

    #[test]
    fn timeout_and_redirect_flags() {
        let mut exchange = make_exchange(
            "GET",
            "https://api.example.com/v1/items",
            Vec::new(),
            Vec::new(),
            "",
        );
        exchange.request_body = Body::empty();
        let mut req = CurlRequest::from_exchange(&exchange);
        req.options.timeout_ms = 5000;
        req.options.follow_redirects = false;
        let bundle = render_bundle(&req, false);
        assert!(bundle.bash.contains("--max-time 5"));
        assert!(bundle.bash.contains("--max-redirs 0"));
        assert!(bundle.powershell.contains("-TimeoutSec 5"));
        assert!(bundle.powershell.contains("-MaximumRedirection 0"));
        assert!(bundle.cmd.contains("--max-time 5"));
        assert!(bundle.cmd.contains("--max-redirs 0"));
    }

    #[test]
    fn omits_body_for_get_and_empty() {
        let exchange = make_exchange(
            "GET",
            "https://api.example.com/v1/items",
            Vec::new(),
            Vec::new(),
            "should-not-appear",
        );
        let bundle = generate(&exchange, false);
        assert!(!bundle.bash.contains("--data-raw"));
        assert!(!bundle.cmd.contains("--data-raw"));
        assert!(!bundle.powershell.contains("-Body"));
    }

    #[test]
    fn generate_from_draft_works() {
        let exchange = make_exchange(
            "POST",
            "https://api.example.com/v1/items",
            vec![Header::new("Content-Type", "application/json")],
            vec![KeyValue {
                name: "session".into(),
                value: "abc".into(),
            }],
            "{\"a\":1}",
        );
        let draft = Draft::from_exchange(&exchange);
        let bundle = generate_from_draft(&draft, false);
        assert!(bundle.bash.contains("--request 'POST'"));
        assert!(bundle.bash.contains("Cookie: session=abc"));
    }
}
