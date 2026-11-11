import { Icon } from "./Icon";
import type { CurlBundle, CurlTarget } from "../types";

const targets: CurlTarget[] = ["bash", "powershell", "cmd"];

interface CurlPanelProps {
  bundle: CurlBundle | null;
  cleanBundle: CurlBundle | null;
  redact: boolean;
  onRedactChange: (value: boolean) => void;
  target: CurlTarget;
  onTargetChange: (target: CurlTarget) => void;
  onCopy: (value: string, label: string) => void;
  loading: boolean;
  sourceLabel: string;
}

export function CurlPanel(props: CurlPanelProps) {
  const { bundle, cleanBundle, redact, onRedactChange, target, onTargetChange, onCopy, loading, sourceLabel } = props;
  const value = (redact ? cleanBundle : bundle)?.[target] ?? "";
  return (
    <section className="curl-panel">
      <div className="curl-head">
        <div>
          <div className="eyebrow">GENERATED CURL · {sourceLabel}</div>
        </div>
        <div className="curl-head-controls">
          <div className="segmented">
            {targets.map((entry) => (
              <button key={entry} className={target === entry ? "active" : ""} onClick={() => onTargetChange(entry)}>
                {entry === "bash" ? "Bash" : entry === "powershell" ? "PowerShell" : "CMD"}
              </button>
            ))}
          </div>
          <span className="divider" />
          <label className="switch-label">
            <input type="checkbox" checked={redact} onChange={(event) => onRedactChange(event.target.checked)} />
            <span className="switch" />
            Redact secrets
          </label>
          <button className="quiet-button" disabled={!bundle} onClick={() => onCopy(value, "Curl")}>
            <Icon name="copy" /> Copy
          </button>
          <button
            className="quiet-button"
            disabled={!cleanBundle}
            onClick={() => onCopy(cleanBundle?.[target] ?? "", "Redacted curl")}
          >
            <Icon name="lock" /> Copy clean
          </button>
        </div>
      </div>
      <pre className="curl-code">{loading ? "Generating curl…" : value || "Select an exchange or draft to generate curl."}</pre>
    </section>
  );
}
