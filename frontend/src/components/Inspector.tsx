import { useMemo, useState } from "react";
import { Icon } from "./Icon";
import type { Exchange, HeaderRow, InspectorTab, KeyValue } from "../types";
import {
  bodyText,
  clockOfSequence,
  contentKindLabel,
  contentLabel,
  formatBytes,
  formatDuration,
  isSensitiveHeader,
  maskHeaders,
  maskKv,
  maskText,
  prettyBody,
  statusClass,
} from "../lib/format";

const tabs: InspectorTab[] = ["Overview", "Headers", "Query", "Cookies", "Request", "Response", "Timing", "Raw"];

interface InspectorProps {
  exchange: Exchange;
  tab: InspectorTab;
  onTab: (tab: InspectorTab) => void;
  masked: boolean;
  onToggleMasked: () => void;
  onCreateDraft: () => void;
  onNotice: (message: string) => void;
}

function HeaderTable({ rows, masked }: { rows: HeaderRow[]; masked: boolean }) {
  const display = maskHeaders(rows, masked);
  return (
    <div className="key-values">
      {display.map((row, index) => (
        <div className="kv-row" key={`${row.name}-${index}`}>
          <span>{row.name}</span>
          <code className={masked && isSensitiveHeader(row.name) ? "masked" : ""}>{row.value}</code>
        </div>
      ))}
      {!rows.length && <div className="inline-empty">No headers captured</div>}
    </div>
  );
}

function KeyValueTable({ rows, masked }: { rows: KeyValue[]; masked: boolean }) {
  const display = maskKv(rows, masked);
  return (
    <div className="key-values">
      {display.map((row, index) => (
        <div className="kv-row" key={`${row.name}-${index}`}>
          <span>{row.name}</span>
          <code className="wrap">{row.value}</code>
        </div>
      ))}
      {!rows.length && <div className="inline-empty">No values captured</div>}
    </div>
  );
}

function BodyPane({ title, body, masked }: { title: string; body: Exchange["requestBody"]; masked: boolean }) {
  const [raw, setRaw] = useState(false);
  const [copied, setCopied] = useState(false);
  const pretty = useMemo(() => prettyBody(body), [body]);
  const text = raw ? bodyText(body, masked) : masked ? maskText(pretty.text) : pretty.text;
  const copyBody = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <div className="body-pane">
      <div className="body-toolbar">
        <span>
          {title} · {contentKindLabel(body)} {body.encoding === "base64" ? "base64" : ""}
        </span>
        <div className="body-tools">
          <button className="text-button" onClick={copyBody} disabled={!text}>
            <Icon name="copy" /> {copied ? "Copied" : "Copy"}
          </button>
          <button className="text-button" onClick={() => setRaw((value) => !value)} disabled={body.encoding === "base64"}>
            {raw ? "Formatted" : "Raw"}
          </button>
        </div>
      </div>
      <pre>{text || "No body captured"}</pre>
      <div className="body-note">{pretty.note}</div>
    </div>
  );
}

export function Inspector(props: InspectorProps) {
  const { exchange, tab, onTab, masked, onToggleMasked, onCreateDraft, onNotice } = props;
  const responseCookies = useMemo(() => {
    const result: KeyValue[] = [];
    for (const header of exchange.responseHeaders) {
      if (header.name.toLowerCase() !== "set-cookie") continue;
      const pair = header.value.split(";")[0] ?? "";
      const index = pair.indexOf("=");
      if (index > 0) result.push({ name: pair.slice(0, index), value: pair.slice(index + 1) });
    }
    return result;
  }, [exchange.responseHeaders]);

  const totalTiming = exchange.timing.reduce((sum, phase) => sum + phase.value, 0);
  const maxTiming = Math.max(...exchange.timing.map((phase) => phase.value), 1);
  const preview = prettyBody(exchange.responseBody);
  const previewText = masked ? maskText(preview.text) : preview.text;

  const copy = async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      onNotice(`${label} copied`);
    } catch {
      onNotice("Clipboard is unavailable");
    }
  };

  return (
    <aside className="inspector">
      <div className="inspector-head">
        <div className="inspector-head-main">
          <div className="eyebrow">SELECTED EXCHANGE</div>
          <div className="inspector-title">
            <span className={`method ${`m-${exchange.method.toLowerCase()}`}`}>{exchange.method}</span>
            <span className={statusClass(exchange)}>{exchange.status || "ERR"}</span>
            {exchange.error && <span className="error-chip">{exchange.error}</span>}
          </div>
          <h2>{exchange.host}</h2>
          <p title={exchange.path}>{exchange.path}</p>
        </div>
        <div className="inspector-actions">
          <button className="icon-button" title={masked ? "Reveal secrets" : "Mask secrets"} onClick={onToggleMasked}>
            <Icon name={masked ? "eye" : "lock"} />
          </button>
          <button className="icon-button" title="Copy URL" onClick={() => copy(masked ? maskText(exchange.url) : exchange.url, "URL")}>
            <Icon name="copy" />
          </button>
        </div>
      </div>

      <div className="inspector-meta">
        <span className="meta-seq">#{String(exchange.sequence).padStart(2, "0")}</span>
        <span>{formatDuration(exchange.durationMs)}</span>
        <span>{formatBytes(exchange.responseBytes)} response</span>
        <span>{contentLabel(exchange.contentType)}</span>
        <span>{clockOfSequence(exchange)}</span>
      </div>

      <div className="inspector-tabs">
        {tabs.map((entry) => (
          <button key={entry} className={tab === entry ? "active" : ""} onClick={() => onTab(entry)}>
            {entry}
          </button>
        ))}
      </div>

      <div className="inspector-content">
        {exchange.error && (
          <div className="error-banner">
            <Icon name="error" />
            <div>
              <strong>Request did not complete</strong>
              <span>{exchange.error}</span>
            </div>
          </div>
        )}

        {tab === "Overview" && (
          <>
            <div className="overview-block">
              <div className="block-heading">Summary</div>
              <div className="summary-grid">
                <span>Request</span>
                <strong>
                  {exchange.method} {masked ? maskText(exchange.url) : exchange.url}
                </strong>
                <span>Protocol</span>
                <strong>{exchange.url.startsWith("https://") ? "HTTPS · TLS" : "HTTP"}</strong>
                <span>Content type</span>
                <strong>{exchange.contentType || "Unknown"}</strong>
                <span>Upload / download</span>
                <strong>
                  {formatBytes(exchange.requestBytes)} / {formatBytes(exchange.responseBytes)}
                </strong>
                <span>Captured</span>
                <strong>{new Date(exchange.capturedAt).toLocaleString()}</strong>
              </div>
            </div>
            <div className="overview-block">
              <div className="block-heading">Request query</div>
              <KeyValueTable rows={exchange.query} masked={masked} />
            </div>
            <div className="overview-block">
              <div className="block-heading">Cookies</div>
              <KeyValueTable rows={[...exchange.cookies, ...responseCookies]} masked={masked} />
            </div>
            <div className="overview-block">
              <div className="block-heading-row">
                <div className="block-heading">Response preview</div>
                <button className="text-button" onClick={() => copy(previewText, "Response body")} disabled={!previewText}>
                  <Icon name="copy" /> Copy
                </button>
              </div>
              <pre className="body-preview">{previewText || "No response body"}</pre>
            </div>
          </>
        )}

        {tab === "Headers" && (
          <div className="split-content">
            <div>
              <div className="subheading">
                Request headers <small>{exchange.requestHeaders.length}</small>
              </div>
              <HeaderTable rows={exchange.requestHeaders} masked={masked} />
            </div>
            <div>
              <div className="subheading">
                Response headers <small>{exchange.responseHeaders.length}</small>
              </div>
              <HeaderTable rows={exchange.responseHeaders} masked={masked} />
            </div>
          </div>
        )}

        {tab === "Query" && (
          <div className="overview-block">
            <div className="subheading">
              Query parameters <small>{exchange.query.length}</small>
            </div>
            <KeyValueTable rows={exchange.query} masked={masked} />
          </div>
        )}

        {tab === "Cookies" && (
          <div className="split-content">
            <div>
              <div className="subheading">
                Request cookies <small>{exchange.cookies.length}</small>
              </div>
              <KeyValueTable rows={exchange.cookies} masked={masked} />
            </div>
            <div>
              <div className="subheading">
                Response cookies <small>{responseCookies.length}</small>
              </div>
              <KeyValueTable rows={responseCookies} masked={masked} />
            </div>
          </div>
        )}

        {tab === "Request" && (
          <div className="split-content">
            <BodyPane title="Request body" body={exchange.requestBody} masked={masked} />
            <div>
              <div className="subheading">Request headers</div>
              <HeaderTable rows={exchange.requestHeaders} masked={masked} />
            </div>
          </div>
        )}

        {tab === "Response" && <BodyPane title="Response body" body={exchange.responseBody} masked={masked} />}

        {tab === "Timing" && (
          <div className="timing-pane">
            <div className="timing-total">
              <strong>{formatDuration(totalTiming || exchange.durationMs)}</strong>
              <span>total wall time</span>
            </div>
            {exchange.timing.map((phase) => (
              <div className="timing-row" key={phase.label}>
                <span>{phase.label}</span>
                <div className="timing-track">
                  <i className={phase.tone} style={{ width: `${Math.max(2, (phase.value / maxTiming) * 100)}%` }} />
                </div>
                <code>{formatDuration(phase.value)}</code>
              </div>
            ))}
            {!exchange.timing.length && <div className="inline-empty">No timing phases recorded</div>}
            <p className="helper-copy">
              Values come from the proxy. When a transport does not expose a phase, Relay reports total waiting and
              download time rather than inventing sub-timings.
            </p>
          </div>
        )}

        {tab === "Raw" && (
          <div className="raw-split">
            <div>
              <div className="body-toolbar">
                <span>Raw request</span>
                <button className="text-button" onClick={() => copy(masked ? maskText(exchange.rawRequest) : exchange.rawRequest, "Raw request")}>
                  <Icon name="copy" /> Copy
                </button>
              </div>
              <pre>{masked ? maskText(exchange.rawRequest) : exchange.rawRequest}</pre>
            </div>
            <div>
              <div className="body-toolbar">
                <span>Raw response</span>
                <button className="text-button" onClick={() => copy(masked ? maskText(exchange.rawResponse) : exchange.rawResponse, "Raw response")}>
                  <Icon name="copy" /> Copy
                </button>
              </div>
              <pre>{masked ? maskText(exchange.rawResponse) : exchange.rawResponse}</pre>
            </div>
          </div>
        )}
      </div>

      <div className="draft-cta">
        <div>
          <strong>Work on a copy</strong>
          <span>The captured exchange stays read-only.</span>
        </div>
        <button className="primary-button" onClick={onCreateDraft}>
          <Icon name="drafts" /> Create draft
        </button>
      </div>
    </aside>
  );
}
