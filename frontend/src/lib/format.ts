import type {
  Body,
  DiffLine,
  Draft,
  Exchange,
  Filter,
  HeaderRow,
  KeyValue,
} from "../types";

export const PLACEHOLDER = "••••••••";

export function formatBytes(size: number): string {
  if (!Number.isFinite(size) || size <= 0) return "0 B";
  if (size >= 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(2)} MB`;
  if (size >= 1024) return `${(size / 1024).toFixed(size >= 10240 ? 0 : 1)} KB`;
  return `${size} B`;
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms)) return "—";
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  return `${Math.round(ms)} ms`;
}

export function formatClock(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleDateString([], { month: "short", day: "numeric" });
}

export function clockOfSequence(exchange: Exchange): string {
  return formatClock(exchange.capturedAt);
}

export function methodClass(method: string): string {
  return `m-${method.toLowerCase()}`;
}

export function statusClass(exchange: Exchange): string {
  if (exchange.status === 0 || (exchange.error && !exchange.status)) return "status-error";
  if (exchange.status >= 400) return "status-warn";
  if (exchange.status >= 300) return "status-muted";
  return "status-ok";
}

export function isError(exchange: Exchange): boolean {
  return Boolean(exchange.error) || exchange.status === 0 || exchange.status >= 400;
}

export function contentLabel(contentType: string): string {
  return contentType.split(";")[0].trim() || "—";
}

export function shortContentType(contentType: string): string {
  const base = contentLabel(contentType).toLowerCase();
  if (base === "—") return base;
  const known: Record<string, string> = {
    "application/json": "json",
    "application/ld+json": "json",
    "application/x-www-form-urlencoded": "form",
    "application/octet-stream": "binary",
    "application/javascript": "js",
    "text/javascript": "js",
    "text/html": "html",
    "text/css": "css",
    "text/plain": "text",
    "text/event-stream": "sse",
    "application/xml": "xml",
    "text/xml": "xml",
    "image/webp": "webp",
    "image/png": "png",
    "image/jpeg": "jpeg",
    "image/svg+xml": "svg",
    "font/woff2": "woff2",
    "font/woff": "woff",
    "application/pdf": "pdf",
    "application/protobuf": "protobuf",
  };
  if (known[base]) return known[base];
  return base.replace(/^(application|text|image|font|audio|video)\//, "");
}

const sensitiveHeaderPattern = /authorization|proxy-authorization|cookie|set-cookie|token|api[-_]?key|secret|session|csrf|password/i;
const sensitiveKeyPattern = /password|passwd|token|access_token|refresh_token|id_token|api[-_]?key|apikey|secret|client_secret|authorization|cookie|session|csrf/i;

export function isSensitiveHeader(name: string): boolean {
  return sensitiveHeaderPattern.test(name);
}

export function isSensitiveKey(name: string): boolean {
  return sensitiveKeyPattern.test(name);
}

export function maskValue(value: string): string {
  if (!value) return value;
  const scheme = value.match(/^(Bearer|Basic|Token|Digest)\s+/i);
  return scheme ? `${scheme[0]}${PLACEHOLDER}` : PLACEHOLDER;
}

export function maskHeaders(headers: HeaderRow[], mask: boolean): HeaderRow[] {
  if (!mask) return headers;
  return headers.map((h) => (isSensitiveHeader(h.name) ? { ...h, value: maskValue(h.value) } : h));
}

export function maskKv(rows: KeyValue[], mask: boolean): KeyValue[] {
  if (!mask) return rows;
  return rows.map((row) => (isSensitiveKey(row.name) ? { ...row, value: maskValue(row.value) } : row));
}

export function maskText(text: string): string {
  return text
    .replace(/((?:authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*)([^\r\n]+)/gi, (_m, head: string) => `${head}${PLACEHOLDER}`)
    .replace(/(^|[?&])((?:token|access_token|refresh_token|api_key|apikey|password|secret|session|session_id)=)([^&\s]+)/gim, (_m, prefix: string, head: string) => `${prefix}${head}${PLACEHOLDER}`)
    .replace(/("(?:[A-Za-z0-9_.-]*(?:password|passwd|token|api[-_]?key|secret|cookie|authorization|session)[A-Za-z0-9_.-]*)"\s*:\s*")([^"]*)(")/gi, (_m, head: string, _v: string, tail: string) => `${head}${PLACEHOLDER}${tail}`)
    .replace(/(\\"(?:[A-Za-z0-9_.-]*(?:password|passwd|token|api[-_]?key|secret|cookie|authorization|session)[A-Za-z0-9_.-]*)\\"\s*:\s*\\")([^"\\]*)(\\")/gi, (_m, head: string, _v: string, tail: string) => `${head}${PLACEHOLDER}${tail}`)
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}/gi, (_m, scheme: string) => `${scheme} ${PLACEHOLDER}`);
}

export function bodyText(body: Body, mask: boolean): string {
  if (!body || body.kind === "empty") return "";
  if (body.encoding === "base64") return `[binary payload · ${body.text.length} base64 chars]`;
  return mask ? maskText(body.text) : body.text;
}

export function prettyBody(body: Body): { text: string; note: string } {
  if (!body || body.kind === "empty") return { text: "", note: "No body captured" };
  if (body.encoding === "base64") {
    return { text: body.text, note: `Binary · base64 · ${body.text.length} chars` };
  }
  if (body.kind === "json") {
    try {
      return { text: JSON.stringify(JSON.parse(body.text), null, 2), note: "JSON · formatted" };
    } catch {
      return { text: body.text, note: "JSON · invalid, raw" };
    }
  }
  if (body.kind === "form") {
    const decode = (value: string) => {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    };
    const lines = body.text
      .split("&")
      .filter(Boolean)
      .map((pair) => {
        const [name, ...rest] = pair.split("=");
        return `${decode(name || "")} = ${decode(rest.join("=") || "")}`;
      });
    return { text: lines.join("\n"), note: "form-urlencoded · decoded" };
  }
  return { text: body.text, note: `${body.kind} · plain` };
}

export function parseHeaders(text: string): HeaderRow[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const index = line.indexOf(":");
      if (index < 0) return { name: line, value: "" };
      return { name: line.slice(0, index).trim(), value: line.slice(index + 1).trim() };
    })
    .filter((h) => h.name.length > 0);
}

export function serializeHeaders(headers: HeaderRow[]): string {
  return headers.map((h) => `${h.name}: ${h.value}`).join("\n");
}

export function parseCookies(text: string): KeyValue[] {
  return text
    .split(/\r?\n|;/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const index = line.indexOf("=");
      if (index < 0) return { name: line, value: "" };
      return { name: line.slice(0, index).trim(), value: line.slice(index + 1).trim() };
    })
    .filter((c) => c.name.length > 0);
}

export function serializeCookies(cookies: KeyValue[]): string {
  return cookies.map((c) => `${c.name}=${c.value}`).join("\n");
}

export function parseQuery(text: string): KeyValue[] {
  return text
    .split(/\r?\n|&/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const index = line.indexOf("=");
      if (index < 0) return { name: line, value: "" };
      return { name: line.slice(0, index).trim(), value: line.slice(index + 1).trim() };
    })
    .filter((q) => q.name.length > 0);
}

export function serializeQuery(query: KeyValue[]): string {
  return query.map((q) => `${q.name}=${q.value}`).join("\n");
}

export function applyQuery(url: string, query: KeyValue[]): string {
  try {
    const parsed = new URL(url);
    parsed.search = query.map((q) => `${encodeURIComponent(q.name)}=${encodeURIComponent(q.value)}`).join("&");
    return parsed.toString();
  } catch {
    return url;
  }
}

export function bodyFromText(text: string, contentType: string): Body {
  if (!text.trim()) return { kind: "empty", text: "", encoding: "utf8" };
  const ct = contentType.toLowerCase();
  if (ct.includes("json") || /^[{[].*[}\]]$/s.test(text.trim())) {
    try {
      JSON.parse(text);
      return { kind: "json", text, encoding: "utf8" };
    } catch {
      /* fall through */
    }
  }
  if (ct.includes("x-www-form-urlencoded")) return { kind: "form", text, encoding: "utf8" };
  return { kind: "text", text, encoding: "utf8" };
}

export function contentKindLabel(body: Body): string {
  if (body.kind === "empty") return "empty";
  if (body.encoding === "base64") return "binary";
  return body.kind;
}

export function searchHaystack(exchange: Exchange): string {
  const bodyLimit = 16_000;
  return [
    exchange.method,
    exchange.url,
    exchange.host,
    exchange.path,
    exchange.contentType,
    exchange.error ?? "",
    ...exchange.requestHeaders.flatMap((h) => [h.name, h.value]),
    ...exchange.responseHeaders.flatMap((h) => [h.name, h.value]),
    ...exchange.query.flatMap((q) => [q.name, q.value]),
    ...exchange.cookies.flatMap((c) => [c.name, c.value]),
    exchange.requestBody.text.slice(0, bodyLimit),
    exchange.responseBody.text.slice(0, bodyLimit),
  ]
    .join(" ")
    .toLowerCase();
}

export function matchesFilter(exchange: Exchange, filter: Filter, haystack?: string): boolean {
  if (filter.methods.length && !filter.methods.some((m) => m.toUpperCase() === exchange.method.toUpperCase())) return false;
  if (filter.hosts.length && !filter.hosts.some((h) => h.toLowerCase() === exchange.host.toLowerCase())) return false;
  if (filter.contentTypes.length) {
    const ct = exchange.contentType.toLowerCase();
    if (!filter.contentTypes.some((value) => ct.startsWith(value.toLowerCase()))) return false;
  }
  if (filter.statuses.length) {
    const status = exchange.status;
    const matched = filter.statuses.some((entry) => {
      switch (entry) {
        case "success":
        case "2xx":
          return status >= 200 && status < 300;
        case "redirect":
        case "3xx":
          return status >= 300 && status < 400;
        case "client":
        case "4xx":
          return status >= 400 && status < 500;
        case "server":
        case "5xx":
          return status >= 500;
        case "error":
          return isError(exchange);
        default:
          return String(status) === entry;
      }
    });
    if (!matched) return false;
  }
  if (filter.onlyErrors && !isError(exchange)) return false;
  const needle = filter.text.trim().toLowerCase();
  if (needle && !(haystack ?? searchHaystack(exchange)).includes(needle)) return false;
  return true;
}

export function uniqueHosts(exchanges: Exchange[]): string[] {
  return Array.from(new Set(exchanges.map((e) => e.host))).sort();
}

export function uniqueContentTypes(exchanges: Exchange[]): string[] {
  return Array.from(new Set(exchanges.map((e) => contentLabel(e.contentType)).filter((t) => t !== "—"))).sort();
}

export function groupByHost(exchanges: Exchange[]): Array<{ host: string; items: Exchange[]; errors: number }> {
  const map = new Map<string, Exchange[]>();
  for (const exchange of exchanges) {
    const list = map.get(exchange.host) ?? [];
    list.push(exchange);
    map.set(exchange.host, list);
  }
  return Array.from(map.entries())
    .map(([host, items]) => ({ host, items, errors: items.filter(isError).length }))
    .sort((a, b) => b.items.length - a.items.length || a.host.localeCompare(b.host));
}

export function makeDraft(exchange: Exchange): Draft {
  const now = new Date().toISOString();
  return {
    id: `draft_${exchange.id}`,
    sessionId: exchange.sessionId,
    sourceExchangeId: exchange.id,
    method: exchange.method,
    url: exchange.url,
    headers: exchange.requestHeaders.map((h) => ({ ...h })),
    cookies: exchange.cookies.map((c) => ({ ...c })),
    body: { ...exchange.requestBody },
    options: { timeoutMs: 15000, followRedirects: true, proxyMode: "direct" },
    createdAt: now,
    updatedAt: now,
  };
}

export function draftDiffLines(original: Exchange, draft: Draft): DiffLine[] {
  const left = [
    `method: ${original.method}`,
    `url: ${original.url}`,
    ...original.requestHeaders.map((h) => `${h.name}: ${h.value}`),
    "",
    original.requestBody.text,
  ].join("\n");
  const right = [
    `method: ${draft.method}`,
    `url: ${draft.url}`,
    ...draft.headers.map((h) => `${h.name}: ${h.value}`),
    "",
    draft.body.text,
  ].join("\n");
  return lineDiff(left, right);
}

export function lineDiff(left: string, right: string): DiffLine[] {
  const a = left.split("\n").slice(0, 400);
  const b = right.split("\n").slice(0, 400);
  const matrix: number[][] = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      matrix[i][j] = a[i] === b[j] ? matrix[i + 1][j + 1] + 1 : Math.max(matrix[i + 1][j], matrix[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      out.push({ kind: "context", text: a[i] });
      i += 1;
      j += 1;
    } else if (matrix[i + 1][j] >= matrix[i][j + 1]) {
      out.push({ kind: "remove", text: a[i] });
      i += 1;
    } else {
      out.push({ kind: "add", text: b[j] });
      j += 1;
    }
  }
  while (i < a.length) {
    out.push({ kind: "remove", text: a[i] });
    i += 1;
  }
  while (j < b.length) {
    out.push({ kind: "add", text: b[j] });
    j += 1;
  }
  return out.slice(0, 500);
}

export function downloadText(filename: string, content: string, mime = "application/json"): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function uuid(): string {
  const cryptoObj = window.crypto;
  if (cryptoObj && "randomUUID" in cryptoObj) return cryptoObj.randomUUID();
  return `id_${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
}
