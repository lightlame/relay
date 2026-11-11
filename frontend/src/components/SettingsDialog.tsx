import { useEffect, useState } from "react";
import { Icon } from "./Icon";
import type { AppConfigView, ProxyStatus, UpstreamCheck } from "../types";

interface SettingsDialogProps {
  open: boolean;
  config: AppConfigView;
  proxy: ProxyStatus;
  upstreamCheck: UpstreamCheck | null;
  checkingUpstream: boolean;
  busy: boolean;
  error: string;
  onClose: () => void;
  onSave: (host: string, port: number) => void;
  onImportCa: (cert: string, key: string) => void;
  onDiscover: () => void;
  onOpenCertificateGuide: () => void;
  onToggleSystemProxy: (enabled: boolean) => void;
  onSaveUpstream: (url: string, username: string, password: string) => void;
  onCheckUpstream: () => void;
  onStart: (host: string, port: number) => void;
  onStop: () => void;
}

export function SettingsDialog(props: SettingsDialogProps) {
  const {
    open,
    config,
    proxy,
    upstreamCheck,
    checkingUpstream,
    busy,
    error,
    onClose,
    onSave,
    onImportCa,
    onDiscover,
    onOpenCertificateGuide,
    onToggleSystemProxy,
    onSaveUpstream,
    onCheckUpstream,
    onStart,
    onStop,
  } = props;
  const [host, setHost] = useState(config.host);
  const [port, setPort] = useState(String(config.port));
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const [localError, setLocalError] = useState("");
  const [copied, setCopied] = useState(false);
  const [upstreamUrl, setUpstreamUrl] = useState(config.upstreamUrl ?? "");
  const [upstreamUser, setUpstreamUser] = useState(config.upstreamUsername ?? "");
  const [upstreamPass, setUpstreamPass] = useState("");

  useEffect(() => {
    if (open) {
      setHost(config.host);
      setPort(String(config.port));
      setUpstreamUrl(config.upstreamUrl ?? "");
      setUpstreamUser(config.upstreamUsername ?? "");
      setUpstreamPass("");
      setLocalError("");
    }
  }, [open, config.host, config.port, config.upstreamUrl, config.upstreamUsername]);

  if (!open) return null;

  const readFile = (file: File | undefined, setter: (value: string) => void) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setter(String(reader.result ?? ""));
    reader.readAsText(file);
  };

  const validate = () => {
    const numericPort = Number(port);
    if (!host.trim()) {
      setLocalError("Host is required");
      return null;
    }
    if (!Number.isInteger(numericPort) || numericPort < 1 || numericPort > 65535) {
      setLocalError("Port must be between 1 and 65535");
      return null;
    }
    setLocalError("");
    return numericPort;
  };

  const submitSave = () => {
    const numericPort = validate();
    if (numericPort != null) onSave(host.trim(), numericPort);
  };

  const submitStart = () => {
    const numericPort = validate();
    if (numericPort != null) onStart(host.trim(), numericPort);
  };

  const submitCa = () => {
    if (!cert.trim() || !key.trim()) {
      setLocalError("Both certificate and private key PEM are required");
      return;
    }
    setLocalError("");
    onImportCa(cert, key);
  };

  const submitUpstream = () => {
    onSaveUpstream(upstreamUrl.trim(), upstreamUser.trim(), upstreamPass);
    setUpstreamPass("");
  };

  const shownError = error || localError;
  const fromMitmproxy = config.caSource.toLowerCase().includes("mitmproxy");
  const needsInstall = config.caSource.toLowerCase().includes("generated");
  const bindAll = !host || host === "0.0.0.0" || host === "::" || host === "[::]";
  const deviceHost = bindAll ? config.lanIp || "127.0.0.1" : host;
  const deviceAddress = `${deviceHost}:${port}`;

  const copyDeviceAddress = async () => {
    try {
      await navigator.clipboard.writeText(deviceAddress);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setLocalError("Clipboard is unavailable");
    }
  };

  return (
    <div className="overlay settings-overlay" onMouseDown={onClose}>
      <div className="settings-dialog" onMouseDown={(event) => event.stopPropagation()} role="dialog" aria-label="Capture settings">
        <div className="settings-head">
          <div>
            <div className="eyebrow">LOCAL CAPTURE</div>
            <h2>Capture settings</h2>
            <p>A local certificate authority lets Relay inspect HTTPS. Reuse the mitmproxy CA or install the Relay CA on your device.</p>
          </div>
          <button className="icon-button" onClick={onClose} title="Close settings">
            <Icon name="close" />
          </button>
        </div>

        <div className="settings-grid">
          <section className="settings-block">
            <div className="block-heading">
              Listener <span className={`pill ${proxy.running ? "pill-live" : "pill-idle"}`}>{proxy.running ? "running" : "stopped"}</span>
            </div>
            <div className="settings-fields">
              <label>
                HOST
                <input value={host} onChange={(event) => setHost(event.target.value)} spellCheck={false} />
              </label>
              <label>
                PORT
                <input value={port} onChange={(event) => setPort(event.target.value)} inputMode="numeric" />
              </label>
            </div>
            <p className="helper-copy">
              Port 8888 matches the usual mitmproxy setup. Bind to 0.0.0.0 for a device on the local network; use
              127.0.0.1 for same-machine clients.
            </p>
            <div className="settings-actions">
              <button className="quiet-button" onClick={submitSave} disabled={busy || proxy.running}>
                Save
              </button>
              {proxy.running ? (
                <button className="quiet-button danger" onClick={onStop} disabled={busy}>
                  <Icon name="stop" /> Stop proxy
                </button>
              ) : (
                <button className="primary-button" onClick={submitStart} disabled={busy || !config.caLoaded}>
                  <Icon name="play" /> {busy ? "Starting…" : "Start proxy"}
                </button>
              )}
            </div>
            {!config.caLoaded && (
              <div className="inline-hint">Run mitmproxy once or import another CA to enable capture.</div>
            )}
            <label className={`system-proxy-toggle ${config.systemProxy ? "is-on" : ""}`}>
              <input
                type="checkbox"
                checked={config.systemProxy}
                disabled={!proxy.running || busy}
                onChange={(event) => onToggleSystemProxy(event.target.checked)}
              />
              <span className="switch" />
              <span>
                <strong>Route this PC through Relay</strong>
                <small>Windows system proxy; lets PC browsers open http://mitm.it. Restored when the proxy stops.</small>
              </span>
            </label>
          </section>

          <section className="settings-block">
            <div className="block-heading">
              Device trust{" "}
              <span className={`pill ${config.caLoaded && !needsInstall ? "pill-live" : "pill-warn"}`}>
                {!config.caLoaded ? "missing" : needsInstall ? "install profile" : "trusted CA"}
              </span>
            </div>
            <div className="ca-source">
              <Icon name="lock" />
              <div>
                <strong>{fromMitmproxy ? "Existing mitmproxy CA" : config.caSource}</strong>
                <small>
                  {needsInstall
                    ? "Install this profile on the device once. Relay cannot decrypt HTTPS until the CA is trusted there."
                    : config.caLoaded
                      ? "This CA is already known to the device. Certificates for captured hosts are signed with it."
                      : "No CA available yet."}
                </small>
              </div>
            </div>

            <div className="install-block">
              <div className="subheading">Install on your device</div>
              <div className="portal-url">
                <code>{deviceAddress}</code>
                <button className="text-button" onClick={() => void copyDeviceAddress()}>
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
              {!bindAll && (host === "127.0.0.1" || host === "::1" || host === "[::1]") && (
                <div className="inline-hint">Loopback only. Set HOST to 0.0.0.0 to accept a phone or tablet.</div>
              )}
              <ol className="install-steps">
                <li>Connect the device to the same Wi-Fi network.</li>
                <li>Set its Wi-Fi HTTP proxy to <code>{deviceAddress}</code>.</li>
                <li>Start the proxy, then open <code>http://mitm.it</code> on the device and install the CA.</li>
              </ol>
              <div className="settings-actions">
                <button className="primary-button" onClick={onOpenCertificateGuide}>
                  <Icon name="lock" /> Open certificate setup
                </button>
              </div>
              <p className="helper-copy">
                Detailed iOS, Android and Windows steps, QR code and one-click Windows install are in the setup guide.
              </p>
            </div>

            <div className="settings-actions">
              <button className="quiet-button" onClick={onDiscover} disabled={busy || proxy.running}>
                <Icon name="search" /> Use mitmproxy CA instead
              </button>
            </div>
            <p className="helper-copy">
              Relay can reuse <code>~/.mitmproxy/mitmproxy-ca.pem</code> when it exists. Otherwise a local Relay CA is generated. Nothing leaves this machine.
            </p>

            <details className="ca-advanced">
              <summary>Import a different CA</summary>
              <div className="settings-fields">
                <label>
                  CERTIFICATE PEM
                  <input
                    type="file"
                    accept=".pem,.crt,.cer,.txt"
                    onChange={(event) => readFile(event.target.files?.[0], setCert)}
                  />
                </label>
                <textarea
                  value={cert}
                  onChange={(event) => setCert(event.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  spellCheck={false}
                />
                <label>
                  PRIVATE KEY PEM
                  <input
                    type="file"
                    accept=".pem,.key,.txt"
                    onChange={(event) => readFile(event.target.files?.[0], setKey)}
                  />
                </label>
                <textarea
                  value={key}
                  onChange={(event) => setKey(event.target.value)}
                  placeholder="-----BEGIN PRIVATE KEY-----"
                  spellCheck={false}
                />
                <div className="settings-actions">
                  <button className="quiet-button" onClick={submitCa} disabled={busy}>
                    <Icon name="download" /> Import CA
                  </button>
                </div>
              </div>
            </details>
          </section>

          <section className="settings-block settings-wide">
            <div className="block-heading">
              Upstream proxy{" "}
              <span className={`pill ${config.upstreamUrl ? "pill-live" : "pill-idle"}`}>
                {config.upstreamUrl ? "enabled" : "direct"}
              </span>
            </div>
            <p className="helper-copy upstream-copy">
              Relay connects to the internet through this proxy, so the device's visible IP becomes the upstream exit
              IP. Supports HTTP/HTTPS and SOCKS5, including username/password authentication.
            </p>
            <div className="settings-fields upstream-fields">
              <label className="upstream-url-field">
                PROXY URL
                <input
                  value={upstreamUrl}
                  onChange={(event) => setUpstreamUrl(event.target.value)}
                  placeholder="http://host:port or socks5://host:port"
                  spellCheck={false}
                />
              </label>
              <label>
                USERNAME
                <input
                  value={upstreamUser}
                  onChange={(event) => setUpstreamUser(event.target.value)}
                  placeholder="optional"
                  autoComplete="off"
                  spellCheck={false}
                />
              </label>
              <label>
                PASSWORD
                <input
                  type="password"
                  value={upstreamPass}
                  onChange={(event) => setUpstreamPass(event.target.value)}
                  placeholder={config.upstreamHasPassword ? "saved — blank keeps it" : "optional"}
                  autoComplete="new-password"
                />
              </label>
            </div>
            <div className="settings-actions">
              <button className="primary-button" onClick={submitUpstream} disabled={busy || proxy.running}>
                <Icon name="check" /> Save upstream
              </button>
              {config.upstreamUrl && (
                <button
                  className="quiet-button"
                  onClick={() => {
                    setUpstreamUrl("");
                    setUpstreamUser("");
                    setUpstreamPass("");
                    onSaveUpstream("", "", "");
                  }}
                  disabled={busy || proxy.running}
                >
                  Remove
                </button>
              )}
              <button className="quiet-button" onClick={onCheckUpstream} disabled={checkingUpstream || !config.upstreamUrl}>
                {checkingUpstream ? <span className="spinner" /> : <Icon name="external" />} Check exit IP
              </button>
            </div>
            {upstreamCheck && (
              <div className="inline-success upstream-result">
                <Icon name="check" /> Exit IP {upstreamCheck.ip} · {Math.round(upstreamCheck.latencyMs)} ms
              </div>
            )}
            {proxy.running && <div className="inline-hint">Stop the proxy to change the upstream.</div>}
          </section>
        </div>

        {shownError && (
          <div className="inline-error settings-error">
            <Icon name="error" /> {shownError}
          </div>
        )}
        {proxy.lastError && !shownError && (
          <div className="inline-error settings-error">
            <Icon name="error" /> {proxy.lastError}
          </div>
        )}
      </div>
    </div>
  );
}








