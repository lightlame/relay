export interface HeaderRow {
  name: string;
  value: string;
}

export interface KeyValue {
  name: string;
  value: string;
}

export type BodyKind = "empty" | "text" | "json" | "form" | "binary";
export type BodyEncoding = "utf8" | "base64";

export interface Body {
  kind: BodyKind;
  text: string;
  encoding: BodyEncoding;
}

export interface TimingPhase {
  label: string;
  value: number;
  tone: "base" | "wait" | "transfer";
}

export interface Exchange {
  id: string;
  sessionId: string;
  sequence: number;
  capturedAt: string;
  method: string;
  url: string;
  host: string;
  path: string;
  status: number;
  durationMs: number;
  requestBytes: number;
  responseBytes: number;
  contentType: string;
  error?: string | null;
  requestHeaders: HeaderRow[];
  responseHeaders: HeaderRow[];
  query: KeyValue[];
  cookies: KeyValue[];
  requestBody: Body;
  responseBody: Body;
  rawRequest: string;
  rawResponse: string;
  timing: TimingPhase[];
}

export type ReplayProxyMode = "direct" | "appProxy";

export interface ReplayOptions {
  timeoutMs: number;
  followRedirects: boolean;
  proxyMode: ReplayProxyMode;
}

export interface Draft {
  id: string;
  sessionId: string;
  sourceExchangeId: string;
  method: string;
  url: string;
  headers: HeaderRow[];
  cookies: KeyValue[];
  body: Body;
  options: ReplayOptions;
  createdAt: string;
  updatedAt: string;
}

export interface ReplayResult {
  draftId: string;
  status: number;
  headers: HeaderRow[];
  body: Body;
  durationMs: number;
  url: string;
  error?: string | null;
}

export interface HeaderChange {
  name: string;
  original?: string | null;
  replay?: string | null;
}

export interface DiffLine {
  kind: string;
  text: string;
}

export interface ResponseDiff {
  statusChanged: boolean;
  originalStatus: number;
  replayStatus: number;
  durationDeltaMs: number;
  bodyChanged: boolean;
  headerChanges: HeaderChange[];
  lines: DiffLine[];
}

export interface ReplayOutcome {
  result: ReplayResult;
  diff: ResponseDiff;
}

export interface CurlBundle {
  bash: string;
  powershell: string;
  cmd: string;
}

export type CurlTarget = "bash" | "powershell" | "cmd";

export interface Session {
  id: string;
  name: string;
  startedAt: string;
  endedAt?: string | null;
  exchangeCount: number;
}

export interface Collection {
  id: string;
  name: string;
  createdAt: string;
  exchangeIds: string[];
}

export interface Filter {
  text: string;
  methods: string[];
  statuses: string[];
  hosts: string[];
  contentTypes: string[];
  onlyErrors: boolean;
  groupByHost: boolean;
}

export interface SavedFilter {
  id: string;
  name: string;
  filter: Filter;
  createdAt: string;
}

export interface ProxyStatus {
  running: boolean;
  host: string;
  port: number;
  captured: number;
  lastError?: string | null;
}

export interface AppConfigView {
  host: string;
  port: number;
  caLoaded: boolean;
  caSource: string;
  upstreamUrl?: string | null;
  upstreamUsername?: string | null;
  upstreamHasPassword: boolean;
  lanIp?: string | null;
  systemProxy: boolean;
}

export interface UpstreamCheck {
  ip: string;
  latencyMs: number;
}

export interface Snapshot {
  status: ProxyStatus;
  config: AppConfigView;
  sessions: Session[];
  currentSessionId?: string | null;
}

export type InspectorTab =
  | "Overview"
  | "Headers"
  | "Query"
  | "Cookies"
  | "Request"
  | "Response"
  | "Timing"
  | "Raw";

export type ViewMode = "traffic" | "drafts" | "collections" | "history";
export type Theme = "light" | "dark";

export const emptyBody = (): Body => ({ kind: "empty", text: "", encoding: "utf8" });

export const emptyFilter = (): Filter => ({
  text: "",
  methods: [],
  statuses: [],
  hosts: [],
  contentTypes: [],
  onlyErrors: false,
  groupByHost: false,
});



