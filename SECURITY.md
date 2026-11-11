# Security policy

Relay is a local MITM proxy. Treat it as a debugging tool for devices you own.

## Reporting

Please report vulnerabilities privately through GitHub Security Advisories or by opening
a minimal issue that does not include secrets or exploit details. Do not include CA private
keys, upstream credentials, captured tokens or personal traffic in reports.

## Design notes

- The proxy listens on `0.0.0.0:8888` by default so a phone on the LAN can reach it.
  Bind `127.0.0.1` when only this machine needs capture.
- The CA private key and upstream proxy password are stored in the local SQLite database
  in the user's app-data directory. They are never uploaded.
- `http://mitm.it` is answered locally by the proxy with the current CA certificate. Only
  install the profile on devices you control.
- HAR export masks Authorization headers, cookies, tokens, API keys and passwords.
- Relay contains no telemetry, analytics or cloud backend.
