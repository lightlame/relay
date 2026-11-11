import type { Exchange, HeaderRow, KeyValue } from "../types";

const iso = (offset: number) => new Date(Date.now() - 96000 + offset).toISOString();
const h = (name: string, value: string): HeaderRow => ({ name, value });
const json = (value: unknown) => JSON.stringify(value, null, 2);

interface DemoInput {
  id: string;
  method: string;
  host: string;
  path: string;
  status: number;
  duration: number;
  requestBytes: number;
  responseBytes: number;
  contentType: string;
  error?: string;
  requestHeaders?: HeaderRow[];
  responseHeaders?: HeaderRow[];
  cookies?: KeyValue[];
  requestBody?: string;
  responseBody?: string;
  requestBodyKind?: "json" | "form" | "text";
  responseBodyKind?: "json" | "form" | "text";
  timing?: Exchange["timing"];
}

const baseTiming = (waiting: number, download: number): Exchange["timing"] => [
  { label: "Waiting", value: waiting, tone: "wait" },
  { label: "Download", value: download, tone: "transfer" },
];

const make = (input: DemoInput): Exchange => {
  const requestHeaders = input.requestHeaders ?? [h("Accept", "application/json"), h("User-Agent", "RelaySample/1.0")];
  const responseHeaders = input.responseHeaders ?? [h("Content-Type", input.contentType), h("Server", "edge")];
  const requestBody = input.requestBody ?? "";
  const responseBody = input.responseBody ?? "";
  return {
    id: input.id,
    sessionId: "sample",
    sequence: Number(input.id.replace(/\D/g, "")) || 1,
    capturedAt: iso(Number(input.id.replace(/\D/g, "")) * 240),
    method: input.method,
    url: `https://${input.host}${input.path}`,
    host: input.host,
    path: input.path,
    status: input.status,
    durationMs: input.duration,
    requestBytes: input.requestBytes,
    responseBytes: input.responseBytes,
    contentType: input.contentType,
    error: input.error ?? null,
    requestHeaders,
    responseHeaders,
    query: input.path.includes("?")
      ? input.path
          .split("?")[1]
          .split("&")
          .map((pair) => {
            const [name, ...rest] = pair.split("=");
            return { name, value: rest.join("=") };
          })
      : [],
    cookies: [],
    requestBody: requestBody
      ? { kind: input.requestBodyKind ?? "json", text: requestBody, encoding: "utf8" }
      : { kind: "empty", text: "", encoding: "utf8" },
    responseBody: responseBody
      ? { kind: input.responseBodyKind ?? "json", text: responseBody, encoding: "utf8" }
      : { kind: "empty", text: "", encoding: "utf8" },
    rawRequest: `${input.method} ${input.path} HTTP/2\n${requestHeaders.map((header) => `${header.name}: ${header.value}`).join("\n")}\n\n${requestBody}`,
    rawResponse: `HTTP/2 ${input.status}\n${responseHeaders.map((header) => `${header.name}: ${header.value}`).join("\n")}\n\n${responseBody}`,
    timing: input.timing ?? baseTiming(input.duration * 0.7, input.duration * 0.3),
  };
};

export const sampleExchanges: Exchange[] = [
  make({
    id: "s1",
    method: "GET",
    host: "feed.arcnews.io",
    path: "/v4/for-you?cursor=eyJvZmZzZXQiOjIwfQ&limit=20",
    status: 200,
    duration: 184,
    requestBytes: 312,
    responseBytes: 24860,
    contentType: "application/json; charset=utf-8",
    requestHeaders: [h("Accept", "application/json"), h("Authorization", "Bearer sample_feed_token"), h("Accept-Encoding", "gzip, br")],
    responseHeaders: [h("Content-Type", "application/json; charset=utf-8"), h("Content-Encoding", "br"), h("Server", "edge")],
    responseBody: json({
      storyCount: 20,
      next: "eyJvZmZzZXQiOjQwfQ",
      items: [
        { id: "st_102", title: "The quiet architecture of local radio", readMinutes: 7 },
        { id: "st_103", title: "A new map of the night sky", readMinutes: 5 },
      ],
    }),
    timing: [
      { label: "Waiting", value: 139, tone: "wait" },
      { label: "Download", value: 45, tone: "transfer" },
    ],
  }),
  make({
    id: "s2",
    method: "GET",
    host: "cdn.avatars.studio",
    path: "/u/48291/profile-720.webp",
    status: 304,
    duration: 43,
    requestBytes: 188,
    responseBytes: 0,
    contentType: "image/webp",
    requestHeaders: [h("Accept", "image/webp,image/*"), h("If-None-Match", 'W/"82e1-g0"')],
    responseHeaders: [h("Content-Type", "image/webp"), h("ETag", 'W/"82e1-g0"')],
  }),
  make({
    id: "s3",
    method: "POST",
    host: "api.northstar.shop",
    path: "/v2/orders?currency=USD",
    status: 201,
    duration: 336,
    requestBytes: 842,
    responseBytes: 1462,
    contentType: "application/json",
    requestHeaders: [
      h("Accept", "application/json"),
      h("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.sample.signature"),
      h("Content-Type", "application/json"),
      h("Cookie", "session_id=sample_session"),
    ],
    responseHeaders: [h("Content-Type", "application/json"), h("Server", "edge")],
    cookies: [{ name: "session_id", value: "sample_session" }],
    requestBody: json({
      items: [{ sku: "ALP-492", quantity: 1, price: 74.5 }],
      destination: { city: "Portland", region: "OR", country: "US" },
      paymentToken: "pm_sample_token",
    }),
    responseBody: json({ ok: true, orderId: "ord_1a7d3", status: "accepted", total: 98.5 }),
    timing: [
      { label: "Waiting", value: 214, tone: "wait" },
      { label: "Download", value: 122, tone: "transfer" },
    ],
  }),
  make({
    id: "s4",
    method: "POST",
    host: "inbox.roundtable.chat",
    path: "/api/v3/messages",
    status: 429,
    duration: 1290,
    requestBytes: 642,
    responseBytes: 181,
    contentType: "application/json",
    error: "rate_limit_exceeded",
    requestHeaders: [h("Content-Type", "application/json"), h("Authorization", "Bearer sample_chat_token")],
    responseHeaders: [h("Content-Type", "application/json"), h("Retry-After", "12")],
    requestBody: json({ conversationId: "des_9914", message: "Landing at 6:40 — see you by arrivals." }),
    responseBody: json({ error: "rate_limit_exceeded", message: "Too many updates", retryAfter: 12 }),
    timing: [
      { label: "Waiting", value: 1142, tone: "wait" },
      { label: "Download", value: 148, tone: "transfer" },
    ],
  }),
  make({
    id: "s5",
    method: "PATCH",
    host: "billing.lumen.so",
    path: "/v1/subscription/preferences",
    status: 200,
    duration: 391,
    requestBytes: 497,
    responseBytes: 814,
    contentType: "application/json",
    requestHeaders: [h("Content-Type", "application/json"), h("Cookie", "auth=lumen_session_sample")],
    responseHeaders: [h("Content-Type", "application/json"), h("Server", "edge")],
    cookies: [{ name: "auth", value: "lumen_session_sample" }],
    requestBody: json({ renewalReminder: true, invoiceFormat: "compact" }),
    responseBody: json({ renewalReminder: true, invoiceFormat: "compact", updatedAt: "2026-11-10T01:23:31Z" }),
  }),
  make({
    id: "s6",
    method: "POST",
    host: "telemetry.reader.app",
    path: "/collect/v1",
    status: 204,
    duration: 88,
    requestBytes: 1206,
    responseBytes: 0,
    contentType: "application/json",
    requestHeaders: [h("Content-Type", "application/json"), h("X-Event-Token", "sample_event_token")],
    responseHeaders: [h("Content-Type", "application/json")],
    requestBody: json({ event: "article_open", articleId: "st_102", position: 12 }),
  }),
  make({
    id: "s7",
    method: "GET",
    host: "sync.northstar.shop",
    path: "/health",
    status: 0,
    duration: 10002,
    requestBytes: 167,
    responseBytes: 0,
    contentType: "",
    error: "Timeout after 10,000 ms",
    requestHeaders: [h("Accept", "application/json")],
    responseHeaders: [],
    timing: [
      { label: "Waiting", value: 9999, tone: "wait" },
      { label: "Download", value: 0, tone: "transfer" },
    ],
  }),
  make({
    id: "s8",
    method: "GET",
    host: "static.craftwork.site",
    path: "/fonts/fraunces-var.woff2?v=2",
    status: 200,
    duration: 62,
    requestBytes: 197,
    responseBytes: 38722,
    contentType: "font/woff2",
    requestHeaders: [h("Accept", "*/*")],
    responseHeaders: [h("Content-Type", "font/woff2"), h("Cache-Control", "public, max-age=31536000")],
  }),
];
