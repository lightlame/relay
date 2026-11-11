import type {
  Collection,
  CurlBundle,
  Draft,
  Exchange,
  ReplayOutcome,
  SavedFilter,
  Session,
  Snapshot,
  UpstreamCheck,
} from "./types";

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
type Listen = (
  event: string,
  handler: (event: { payload: unknown }) => void,
) => Promise<() => void>;

const globalWindow = window as unknown as {
  __TAURI_INTERNALS__?: unknown;
  __TAURI__?: { core?: { invoke?: Invoke }; event?: { listen?: Listen } };
};

export const isDesktop = Boolean(globalWindow.__TAURI_INTERNALS__ || globalWindow.__TAURI__);

let invokeImpl: Invoke | null = null;
let listenImpl: Listen | null = null;

async function loadTauri() {
  if (!isDesktop) return;
  if (!invokeImpl) {
    const core = await import("@tauri-apps/api/core");
    invokeImpl = core.invoke as Invoke;
  }
  if (!listenImpl) {
    const event = await import("@tauri-apps/api/event");
    listenImpl = event.listen as unknown as Listen;
  }
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isDesktop) {
    throw new Error("Desktop backend is not connected. Start the app with Tauri.");
  }
  await loadTauri();
  if (!invokeImpl) throw new Error("Tauri invoke bridge is unavailable");
  return invokeImpl<T>(cmd, args);
}

export const api = {
  async snapshot(): Promise<Snapshot> {
    return call<Snapshot>("get_snapshot");
  },
  async importCa(certPem: string, keyPem: string): Promise<Snapshot> {
    return call<Snapshot>("import_ca", { certPem, keyPem });
  },
  async discoverCa(): Promise<Snapshot> {
    return call<Snapshot>("discover_ca");
  },
  async deleteExchanges(ids: string[]): Promise<number> {
    return call<number>("delete_exchanges", { ids });
  },
  async setSystemProxy(enabled: boolean): Promise<Snapshot> {
    return call<Snapshot>("set_system_proxy", { enabled });
  },
  async setUpstream(url: string, username: string, password: string): Promise<Snapshot> {
    return call<Snapshot>("set_upstream", { url, username, password });
  },
  async checkUpstream(): Promise<UpstreamCheck> {
    return call<UpstreamCheck>("check_upstream");
  },
  async updateConfig(host: string, port: number): Promise<Snapshot> {
    return call<Snapshot>("update_config", { host, port });
  },
  async startProxy(host: string, port: number): Promise<Snapshot> {
    return call<Snapshot>("start_proxy", { host, port });
  },
  async stopProxy(): Promise<Snapshot> {
    return call<Snapshot>("stop_proxy");
  },
  async listExchanges(sessionId: string): Promise<Exchange[]> {
    return call<Exchange[]>("list_exchanges", { sessionId });
  },
  async getExchanges(ids: string[]): Promise<Exchange[]> {
    return call<Exchange[]>("get_exchanges", { ids });
  },
  async listSessions(): Promise<Session[]> {
    return call<Session[]>("list_sessions");
  },
  async clearSessions(): Promise<Snapshot> {
    return call<Snapshot>("clear_sessions");
  },
  async installCaOnPc(): Promise<string> {
    return call<string>("install_ca_on_pc");
  },
  async openMitmIt(): Promise<void> {
    return call<void>("open_mitm_it");
  },
  async deleteSession(sessionId: string): Promise<Snapshot> {
    return call<Snapshot>("delete_session", { sessionId });
  },
  async saveDraft(draft: Draft): Promise<void> {
    return call<void>("save_draft", { draft });
  },
  async listDrafts(): Promise<Draft[]> {
    return call<Draft[]>("list_drafts");
  },
  async deleteDraft(draftId: string): Promise<void> {
    return call<void>("delete_draft", { draftId });
  },
  async replayDraft(original: Exchange, draft: Draft): Promise<ReplayOutcome> {
    return call<ReplayOutcome>("replay_draft", { original, draft });
  },
  async generateCurl(exchange: Exchange, redact: boolean): Promise<CurlBundle> {
    return call<CurlBundle>("generate_curl", { exchange, redact });
  },
  async generateCurlDraft(draft: Draft, redact: boolean): Promise<CurlBundle> {
    return call<CurlBundle>("generate_curl_draft", { draft, redact });
  },
  async exportHar(exchanges: Exchange[]): Promise<string> {
    return call<string>("export_har", { exchanges });
  },
  async exportHarToPath(exchanges: Exchange[], path: string): Promise<string> {
    return call<string>("export_har_to_path", { exchanges, path });
  },
  async saveCollection(collection: Collection): Promise<void> {
    return call<void>("save_collection", { collection });
  },
  async listCollections(): Promise<Collection[]> {
    return call<Collection[]>("list_collections");
  },
  async deleteCollection(collectionId: string): Promise<void> {
    return call<void>("delete_collection", { collectionId });
  },
  async saveFilter(filter: SavedFilter): Promise<void> {
    return call<void>("save_filter", { filter });
  },
  async listFilters(): Promise<SavedFilter[]> {
    return call<SavedFilter[]>("list_filters");
  },
  async deleteFilter(filterId: string): Promise<void> {
    return call<void>("delete_filter", { filterId });
  },
  async onExchange(handler: (exchange: Exchange) => void): Promise<() => void> {
    if (!isDesktop) return () => undefined;
    await loadTauri();
    if (!listenImpl) return () => undefined;
    return listenImpl("exchange", (event) => handler(event.payload as Exchange));
  },
  async onProxyStatus(handler: (status: string) => void): Promise<() => void> {
    if (!isDesktop) return () => undefined;
    await loadTauri();
    if (!listenImpl) return () => undefined;
    return listenImpl("proxy-status", (event) => handler(String(event.payload)));
  },
};




