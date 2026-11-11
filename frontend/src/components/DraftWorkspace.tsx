import { useMemo, useState } from "react";
import { Icon } from "./Icon";
import type { Draft, Exchange, ReplayOutcome } from "../types";
import {
  applyQuery,
  bodyFromText,
  draftDiffLines,
  formatDuration,
  lineDiff,
  parseCookies,
  parseHeaders,
  parseQuery,
  prettyBody,
  serializeCookies,
  serializeHeaders,
  serializeQuery,
  maskHeaders,
  maskText,
} from "../lib/format";

interface DraftWorkspaceProps {
  original: Exchange;
  draft: Draft;
  onChange: (draft: Draft) => void;
  onClose: () => void;
  onSave: () => void;
  onReplay: () => void;
  replaying: boolean;
  replayError: string;
  outcome: ReplayOutcome | null;
  saved: boolean;
  masked: boolean;
  onToggleMasked: () => void;
  onNotice: (message: string) => void;
}

type DraftTab = "Edit" | "Diff" | "Compare";

export function DraftWorkspace(props: DraftWorkspaceProps) {
  const { original, draft, onChange, onClose, onSave, onReplay, replaying, replayError, outcome, saved, masked, onToggleMasked, onNotice } = props;
  const [tab, setTab] = useState<DraftTab>("Edit");
  const [headerText, setHeaderText] = useState(() => serializeHeaders(draft.headers));
  const [cookieText, setCookieText] = useState(() => serializeCookies(draft.cookies));
  const [queryText, setQueryText] = useState(() => {
    try {
      const parsed = new URL(draft.url);
      const rows = Array.from(parsed.searchParams.entries()).map(([name, value]) => ({ name, value }));
      return serializeQuery(rows);
    } catch {
      return "";
    }
  });

  const contentHeader =
    draft.headers.find((header) => header.name.toLowerCase() === "content-type")?.value ?? "";
  const diffLines = useMemo(() => draftDiffLines(original, draft), [original, draft]);
  const changed = diffLines.some((line) => line.kind !== "context");

  const update = (patch: Partial<Draft>) =>
    onChange({ ...draft, ...patch, updatedAt: new Date().toISOString() });

  const updateQuery = (text: string) => {
    setQueryText(text);
    const rows = parseQuery(text);
    update({ url: applyQuery(draft.url, rows) });
  };

  const updateBody = (text: string) => {
    update({ body: bodyFromText(text, contentHeader) });
  };

  const bodyText = draft.body.encoding === "base64" ? draft.body.text : draft.body.text;
  const response = outcome?.result;
  const responsePretty = response ? prettyBody(response.body) : null;
  const responseDiff = outcome?.diff;

  const copyDiff = async () => {
    const text = diffLines.map((line) => `${line.kind === "add" ? "+" : line.kind === "remove" ? "-" : " "}${masked ? maskText(line.text) : line.text}`).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      onNotice("Draft diff copied");
    } catch {
      onNotice("Clipboard is unavailable");
    }
  };

  return (
    <section className="draft-workspace">
      <header className="draft-topbar">
        <div>
          <div className="eyebrow">DRAFT WORKSPACE · SOURCE {original.id.slice(0, 8)}</div>
          <h2>
            {draft.method} <span>{draft.url}</span>
          </h2>
        </div>
        <div className="draft-topbar-actions">
          <span className={`save-state ${saved ? "is-saved" : "is-dirty"}`}>
            <Icon name={saved ? "check" : "clock"} /> {saved ? "Saved locally" : "Unsaved changes"}
          </span>
          <button className="icon-button" title={masked ? "Reveal secrets" : "Mask secrets"} onClick={onToggleMasked}>
            <Icon name={masked ? "eye" : "lock"} />
          </button>
          <button className="quiet-button" onClick={onSave}>
            Save draft
          </button>
          <button className="icon-button" onClick={onClose} title="Close draft">
            <Icon name="close" />
          </button>
        </div>
      </header>

      <div className="draft-tabs">
        {(["Edit", "Diff", "Compare"] as DraftTab[]).map((entry) => (
          <button key={entry} className={tab === entry ? "active" : ""} onClick={() => setTab(entry)}>
            {entry}
            {entry === "Diff" && changed && <span className="tab-dot" />}
          </button>
        ))}
        <div className="draft-tabs-spacer" />
        <span className="draft-shot">Original request is immutable</span>
      </div>

      {tab === "Edit" && (
        <div className="draft-edit-grid">
          <div className="draft-form">
            <div className="field-line">
              <label>
                METHOD
                <select value={draft.method} onChange={(event) => update({ method: event.target.value })}>
                  {["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].map((method) => (
                    <option key={method}>{method}</option>
                  ))}
                </select>
              </label>
              <label>
                URL
                <input
                  value={draft.url}
                  spellCheck={false}
                  onChange={(event) => {
                    update({ url: event.target.value });
                    try {
                      const parsed = new URL(event.target.value);
                      setQueryText(
                        serializeQuery(Array.from(parsed.searchParams.entries()).map(([name, value]) => ({ name, value }))),
                      );
                    } catch {
                      /* keep query text */
                    }
                  }}
                />
              </label>
            </div>
            <label>
              QUERY PARAMETERS · name=value per line
              <textarea value={queryText} spellCheck={false} onChange={(event) => updateQuery(event.target.value)} />
            </label>
            <label>
              HEADERS
              <textarea
                value={headerText}
                spellCheck={false}
                onChange={(event) => { setHeaderText(event.target.value); update({ headers: parseHeaders(event.target.value) }); }}
              />
            </label>
            <label>
              COOKIES
              <textarea
                value={cookieText}
                spellCheck={false}
                onChange={(event) => { setCookieText(event.target.value); update({ cookies: parseCookies(event.target.value) }); }}
              />
            </label>
            <label>
              BODY
              <textarea
                className="code-area"
                value={bodyText}
                spellCheck={false}
                disabled={draft.body.encoding === "base64"}
                onChange={(event) => updateBody(event.target.value)}
              />
            </label>
            <div className="replay-options">
              <label>
                TIMEOUT
                <input
                  type="number"
                  min={1}
                  max={300}
                  value={Math.round(draft.options.timeoutMs / 1000)}
                  onChange={(event) =>
                    update({ options: { ...draft.options, timeoutMs: Math.max(1, Number(event.target.value)) * 1000 } })
                  }
                />
                <span>s</span>
              </label>
              <label className="check-line">
                <input
                  type="checkbox"
                  checked={draft.options.followRedirects}
                  onChange={(event) => update({ options: { ...draft.options, followRedirects: event.target.checked } })}
                />
                Follow redirects
              </label>
              <label>
                PROXY MODE
                <select
                  value={draft.options.proxyMode}
                  onChange={(event) =>
                    update({ options: { ...draft.options, proxyMode: event.target.value as Draft["options"]["proxyMode"] } })
                  }
                >
                  <option value="direct">Direct</option>
                  <option value="appProxy">Use app proxy</option>
                </select>
              </label>
              <button className="primary-button replay-button" onClick={onReplay} disabled={replaying}>
                {replaying ? <span className="spinner" /> : <Icon name="play" />}
                {replaying ? "Sending…" : "Send draft"}
              </button>
            </div>
            {replayError && (
              <div className="inline-error">
                <Icon name="error" /> {replayError}
              </div>
            )}
            {outcome && !replayError && (
              <div className="inline-success">
                <Icon name="check" /> Replay finished · {outcome.result.status} · {formatDuration(outcome.result.durationMs)}
              </div>
            )}
          </div>

          <aside className="draft-original">
            <div className="eyebrow">ORIGINAL · READ ONLY</div>
            <div className="summary-grid compact">
              <span>Method</span>
              <strong>{original.method}</strong>
              <span>URL</span>
              <strong>{masked ? maskText(original.url) : original.url}</strong>
              <span>Status</span>
              <strong>{original.status || "ERR"}</strong>
              <span>Duration</span>
              <strong>{formatDuration(original.durationMs)}</strong>
            </div>
            <div className="subheading">Original headers</div>
            <div className="key-values">
              {maskHeaders(original.requestHeaders, masked).map((header, index) => (
                <div className="kv-row" key={`${header.name}-${index}`}>
                  <span>{header.name}</span>
                  <code className="wrap">{header.value}</code>
                </div>
              ))}
            </div>
            <div className="subheading">Original body</div>
            <pre className="body-preview">
              {masked ? maskText(prettyBody(original.requestBody).text) : prettyBody(original.requestBody).text || "No body"}
            </pre>
          </aside>
        </div>
      )}

      {tab === "Diff" && (
        <div className="diff-pane">
          <div className="diff-head">
            <div>
              <strong>Request diff</strong>
              <span>{changed ? "Draft differs from the captured request" : "Draft matches the captured request"}</span>
            </div>
            <button className="quiet-button" onClick={copyDiff}>
              <Icon name="copy" /> Copy diff
            </button>
          </div>
          <div className="diff-lines">
            {diffLines.map((line, index) => (
              <div className={`diff-line ${line.kind}`} key={`${line.kind}-${index}`}>
                <span>{line.kind === "add" ? "+" : line.kind === "remove" ? "−" : " "}</span>
                <code>{(masked ? maskText(line.text) : line.text) || " "}</code>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "Compare" && (
        <div className="compare-pane">
          {!outcome && (
            <div className="empty-state compact">
              <div className="empty-icon">
                <Icon name="layers" />
              </div>
              <h3>No replay yet</h3>
              <p>Send the draft from the Edit tab to compare the original and repeated responses.</p>
              <button className="primary-button" onClick={onReplay} disabled={replaying}>
                {replaying ? "Sending…" : "Send draft"}
              </button>
            </div>
          )}
          {outcome && response && responseDiff && (
            <>
              <div className="compare-summary">
                <div>
                  <span>Original</span>
                  <strong>{responseDiff.originalStatus || "ERR"}</strong>
                  <small>{formatDuration(original.durationMs)}</small>
                </div>
                <div>
                  <span>Replay</span>
                  <strong className={responseDiff.replayStatus >= 400 ? "status-warn" : "status-ok"}>
                    {responseDiff.replayStatus || "ERR"}
                  </strong>
                  <small>{formatDuration(response.durationMs)}</small>
                </div>
                <div>
                  <span>Δ time</span>
                  <strong>{formatDuration(Math.abs(responseDiff.durationDeltaMs))}</strong>
                  <small>{responseDiff.durationDeltaMs >= 0 ? "slower" : "faster"}</small>
                </div>
                <div>
                  <span>Body</span>
                  <strong>{responseDiff.bodyChanged ? "Changed" : "Identical"}</strong>
                  <small>{responseDiff.headerChanges.length} header changes</small>
                </div>
              </div>

              <div className="compare-columns">
                <div className="compare-block">
                  <div className="block-heading">Original response</div>
                  <pre className="body-preview tall">
                    {(masked ? maskText(prettyBody(original.responseBody).text) : prettyBody(original.responseBody).text) || "No response body"}
                  </pre>
                </div>
                <div className="compare-block">
                  <div className="block-heading">Replay response</div>
                  <pre className="body-preview tall">
                    {(masked ? maskText(responsePretty?.text ?? "") : responsePretty?.text) || "No response body"}
                  </pre>
                </div>
              </div>

              <div className="diff-pane flat">
                <div className="diff-head">
                  <div>
                    <strong>Response lines</strong>
                    <span>{responseDiff.lines.length} lines · {responseDiff.bodyChanged ? "content changed" : "content equal"}</span>
                  </div>
                </div>
                <div className="diff-lines">
                  {responseDiff.lines.map((line, index) => (
                    <div className={`diff-line ${line.kind}`} key={`${line.kind}-${index}`}>
                      <span>{line.kind === "add" ? "+" : line.kind === "remove" ? "−" : " "}</span>
                      <code>{(masked ? maskText(line.text) : line.text) || " "}</code>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </section>
  );
}

