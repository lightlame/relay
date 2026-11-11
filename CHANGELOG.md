# Changelog

## 0.1.0 — 2026-11-12

Initial public preview.

### Capture
- Rust-native HTTP/HTTPS MITM proxy with CA reuse, import and generation.
- Live traffic table, search, filters, grouping, inspector and HAR export.
- `mitm.it` certificate installation page served by the proxy.
- Upstream proxy with HTTP/HTTPS/SOCKS5 authentication and exit-IP check.
- Optional Windows system proxy with automatic restore and one-click CA install for the current PC.

### Workspace
- Draft editing, diff, replay and response comparison.
- curl export for Bash, PowerShell and CMD with secret redaction.
- SQLite sessions, drafts, collections and saved filters.
- Light/dark theme, command palette, keyboard shortcuts, resizable panels.

### Hardening
- Bounded request/response forwarding and replay bodies.
- CMD curl export writes bodies containing newlines to a file instead of inlining them.
- Masked export covers `auth`, `jwt`, `sid`, `credential` and URL userinfo.
- Proxy shutdown cannot be blocked by a full connection table and stops recording immediately.
- CA/upstream/config changes are serialized against proxy start.
- HAR export reports HTTP/1.1 and parses `Set-Cookie` response cookies.
- Replay strips proxy-only headers such as `Proxy-Authorization`.
- Draft, selection and certificate acknowledgement flows no longer lose data.
