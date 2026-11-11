import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { Icon } from "./Icon";

type Platform = "iOS" | "Android" | "Windows";

interface CertificateGuideProps {
  open: boolean;
  address: string;
  proxyRunning: boolean;
  systemProxy: boolean;
  caSource: string;
  installing: boolean;
  onClose: () => void;
  onInstallPc: () => Promise<string>;
  onOpenMitmIt: () => Promise<void>;
  onProxyAndOpen: () => Promise<void>;
  onAcknowledge: () => void;
}

export function CertificateGuide(props: CertificateGuideProps) {
  const { open, address, proxyRunning, systemProxy, caSource, installing, onClose, onInstallPc, onOpenMitmIt, onProxyAndOpen, onAcknowledge } = props;
  const [platform, setPlatform] = useState<Platform>("iOS");
  const [qr, setQr] = useState("");
  const [copied, setCopied] = useState(false);
  const [installState, setInstallState] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [opening, setOpening] = useState(false);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    QRCode.toDataURL("http://mitm.it", {
      margin: 1,
      width: 210,
      color: { dark: "#202420", light: "#f8f9f6" },
    })
      .then((url) => {
        if (!cancelled) setQr(url);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [open]);

  useEffect(() => {
    if (open) {
      setCopied(false);
      setInstallState(null);
    }
  }, [open]);

  if (!open) return null;

  const copyAddress = async () => {
    try {
      await navigator.clipboard.writeText(address);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setInstallState({ tone: "error", text: "Clipboard is unavailable" });
    }
  };

  const installPc = async () => {
    setInstallState(null);
    try {
      const message = await onInstallPc();
      setInstallState({ tone: "ok", text: message });
    } catch (cause) {
      setInstallState({ tone: "error", text: String(cause) });
    }
  };

  const steps: Record<Platform, string[]> = {
    iOS: [
      "Connect the iPhone to the same Wi-Fi network, then open Settings > Wi-Fi > (i) > Configure Proxy > Manual.",
      `Set Server and Port to ${address}.`,
      "Start the proxy in Relay if it is not running.",
      "Scan the QR code or open http://mitm.it in Safari.",
      "Tap “Install on iOS”, allow the download, then close the page.",
      "Settings > General > VPN & Device Management > install the downloaded profile.",
      "Settings > General > About > Certificate Trust Settings > enable full trust for the certificate.",
    ],
    Android: [
      "Connect the device to the same Wi-Fi network and open the Wi-Fi network settings.",
      "Set the advanced proxy to Manual and enter the server and port from the address above.",
      "Start the proxy in Relay if it is not running.",
      "Scan the QR code or open http://mitm.it in the browser.",
      "Download the .cer certificate.",
      "Settings > Security > Encryption & credentials > Install a certificate > CA certificate > Install anyway.",
      "Select the downloaded relay-ca.cer file.",
    ],
    Windows: [
      "Start the proxy in Relay.",
      "Point the Windows/browser proxy at the address above if this PC should be captured.",
      "Click “Open mitm.it on this PC” and download the .cer certificate.",
      "Double-click the certificate > Install Certificate > Current User or Local Machine.",
      "Choose “Place all certificates in the following store” > Trusted Root Certification Authorities.",
      "Or use “Install on this PC” below for a one-click install for the current user.",
    ],
  };

  return (
    <div className="overlay cert-overlay" onMouseDown={onClose}>
      <div className="cert-dialog" role="dialog" aria-label="Certificate setup" onMouseDown={(event) => event.stopPropagation()}>
        <div className="settings-head">
          <div>
            <div className="eyebrow">DEVICE SETUP</div>
            <h2>Install the certificate</h2>
            <p>HTTPS can be read only after the device trusts the Relay CA. iOS always asks for confirmation; Windows can install automatically.</p>
          </div>
          <button className="icon-button" onClick={onClose} title="Close certificate setup">
            <Icon name="close" />
          </button>
        </div>

        <div className="cert-body">
          <aside className="cert-side">
            <div className="cert-address">
              <span>WI-FI PROXY</span>
              <code>{address}</code>
              <button className="quiet-button" onClick={() => void copyAddress()}>
                <Icon name="copy" /> {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <div className={`cert-status ${proxyRunning ? "is-live" : ""}`}>
              <span className={proxyRunning ? "live-dot" : "idle-dot"} />
              {proxyRunning ? "Proxy is running" : "Start the proxy to continue"}
            </div>
            {platform === "Windows" && (
              <div className="cert-status">
                <span className={systemProxy ? "live-dot" : "idle-dot"} />
                {systemProxy ? "This PC uses Relay as system proxy" : "PC is not proxied"}
              </div>
            )}
            {qr && (
              <div className="qr-card">
                <img src={qr} alt="QR code for http://mitm.it" width={180} height={180} />
                <strong>http://mitm.it</strong>
                <small>Scan with the device camera after setting the proxy.</small>
              </div>
            )}
            <div className="cert-source">
              <Icon name="lock" />
              <span>{caSource}</span>
            </div>
          </aside>

          <section className="cert-main">
            <div className="cert-platforms">
              {(["iOS", "Android", "Windows"] as Platform[]).map((entry) => (
                <button key={entry} className={platform === entry ? "active" : ""} onClick={() => setPlatform(entry)}>
                  {entry}
                </button>
              ))}
            </div>
            <ol className="cert-steps">
              {steps[platform].map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
            <div className="cert-actions">
              {platform === "Windows" ? (
                <>
                  <button
                    className="primary-button"
                    disabled={opening}
                    onClick={async () => {
                      setOpening(true);
                      try {
                        await onProxyAndOpen();
                      } finally {
                        setOpening(false);
                      }
                    }}
                  >
                    {opening ? <span className="spinner" /> : <Icon name="external" />}
                    {opening ? "Opening…" : "Proxy this PC & open mitm.it"}
                  </button>
                  <button className="quiet-button" onClick={() => void installPc()} disabled={installing}>
                    {installing ? <span className="spinner" /> : <Icon name="download" />}
                    {installing ? "Installing…" : "Install on this PC"}
                  </button>
                  <button className="quiet-button" onClick={() => void onOpenMitmIt()}>
                    <Icon name="external" /> Open mitm.it on this PC
                  </button>
                  <button className="quiet-button" onClick={onAcknowledge}>
                    <Icon name="check" /> I installed it — start capture
                  </button>
                </>
              ) : (
                <button className="primary-button" onClick={onAcknowledge}>
                  <Icon name="check" /> I installed it — start capture
                </button>
              )}
            </div>
            {installState && (
              <div className={installState.tone === "ok" ? "inline-success" : "inline-error"}>
                <Icon name={installState.tone === "ok" ? "check" : "error"} /> {installState.text}
              </div>
            )}
            <p className="helper-copy">
              {platform === "Windows"
                ? "Windows shows a security confirmation for the Trusted Root store; approve it to finish the one-click install."
                : "The certificate must be confirmed in the device settings. Relay cannot install or trust it remotely."}
            </p>
            <p className="helper-copy">
              The certificate is served by Relay itself when the device opens http://mitm.it through the proxy. It never
              leaves this machine.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
