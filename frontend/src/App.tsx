import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, isDesktop } from "./api";
import type {
  AppConfigView,
  Collection,
  CurlBundle,
  CurlTarget,
  Draft,
  Exchange,
  Filter,
  InspectorTab,
  ProxyStatus,
  ReplayOutcome,
  SavedFilter,
  Session,
  Snapshot,
  Theme,
  UpstreamCheck,
  ViewMode,
} from "./types";
import { emptyFilter } from "./types";
import { sampleExchanges } from "./data/demo";
import {
  makeDraft,
  matchesFilter,
  searchHaystack,
  uniqueContentTypes,
  uniqueHosts,
  uuid,
} from "./lib/format";
import { Sidebar } from "./components/Sidebar";
import { TrafficTable } from "./components/TrafficTable";
import { Inspector } from "./components/Inspector";
import { DraftWorkspace } from "./components/DraftWorkspace";
import { CurlPanel } from "./components/CurlPanel";
import { CommandPalette, type PaletteCommand } from "./components/CommandPalette";
import { SettingsDialog } from "./components/SettingsDialog";
import { FolderDialog } from "./components/FolderDialog";
import { PromptDialog } from "./components/PromptDialog";
import { CertificateGuide } from "./components/CertificateGuide";
import { DraftsView, CollectionsView, HistoryView } from "./components/Views";
import { Icon } from "./components/Icon";

const emptyProxy: ProxyStatus = { running: false, host: "0.0.0.0", port: 8888, captured: 0, lastError: null };
const emptyConfig: AppConfigView = {
  host: "0.0.0.0",
  port: 8888,
  caLoaded: false,
  caSource: "missing",
  upstreamUrl: null,
  upstreamUsername: null,
  upstreamHasPassword: false,
  lanIp: null,
  systemProxy: false,
};

export default function App() {
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = localStorage.getItem("relay.theme");
    if (stored === "light" || stored === "dark") return stored;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  const [view, setView] = useState<ViewMode>("traffic");
  const [caAcknowledged, setCaAcknowledged] = useState(false);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [exchanges, setExchanges] = useState<Exchange[]>([]);
  const [drafts, setDrafts] = useState<Draft[]>([]);
  const [collections, setCollections] = useState<Collection[]>([]);
  const [savedFilters, setSavedFilters] = useState<SavedFilter[]>([]);
  const [proxy, setProxy] = useState<ProxyStatus>(emptyProxy);
  const [config, setConfig] = useState<AppConfigView>(emptyConfig);
  const [filter, setFilter] = useState<Filter>(() => emptyFilter());
  const [selectedId, setSelectedId] = useState<string | undefined>();
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [tab, setTab] = useState<InspectorTab>("Overview");
  const [masked, setMasked] = useState(true);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [upstreamCheck, setUpstreamCheck] = useState<UpstreamCheck | null>(null);
  const [checkingUpstream, setCheckingUpstream] = useState(false);
  const [folderOpen, setFolderOpen] = useState(false);
  const [promptKind, setPromptKind] = useState<null | "filter" | "collection">(null);
  const [certGuideOpen, setCertGuideOpen] = useState(false);
  const [installingCa, setInstallingCa] = useState(false);
  const [sidebarWidth, setSidebarWidth] = useState(() => Number(localStorage.getItem("relay.width.sidebar")) || 224);
  const [inspectorWidth, setInspectorWidth] = useState(() => Number(localStorage.getItem("relay.width.inspector")) || 470);
  const [curlHeight, setCurlHeight] = useState(() => Number(localStorage.getItem("relay.height.curl")) || 150);
  const [dragging, setDragging] = useState<null | "sidebar" | "inspector" | "curl">(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [draftOriginal, setDraftOriginal] = useState<Exchange | null>(null);
  const [draftSaved, setDraftSaved] = useState(true);
  const [replayOutcome, setReplayOutcome] = useState<ReplayOutcome | null>(null);
  const [replaying, setReplaying] = useState(false);
  const [replayError, setReplayError] = useState("");
  const [curlTarget, setCurlTarget] = useState<CurlTarget>("bash");
  const [curlRedact, setCurlRedact] = useState(false);
  const [bundle, setBundle] = useState<CurlBundle | null>(null);
  const [cleanBundle, setCleanBundle] = useState<CurlBundle | null>(null);
  const [curlLoading, setCurlLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [sampleMode, setSampleMode] = useState(false);
  const [scopeLabel, setScopeLabel] = useState("");
  const [draftsLoading, setDraftsLoading] = useState(false);
  const [collectionsLoading, setCollectionsLoading] = useState(false);

  const activeRef = useRef<string | null>(null);
  activeRef.current = activeSessionId;
  const loadSeq = useRef(0);

  const notify = useCallback((message: string) => setNotice(message), []);
  const openSettings = useCallback(() => {
    setError("");
    setSettingsOpen(true);
  }, []);

  const applySnapshot = useCallback((snapshot: Snapshot) => {
    setProxy(snapshot.status);
    setConfig(snapshot.config);
    setSessions(snapshot.sessions);
    setCurrentSessionId(snapshot.currentSessionId ?? null);
  }, []);

  const refreshLists = useCallback(async () => {
    if (!isDesktop) return;
    const [nextDrafts, nextCollections, nextFilters] = await Promise.all([
      api.listDrafts(),
      api.listCollections(),
      api.listFilters(),
    ]);
    setDrafts(nextDrafts);
    setCollections(nextCollections);
    setSavedFilters(nextFilters);
  }, []);

  const loadSession = useCallback(
    async (session: Session) => {
      if (draft && !draftSaved && !window.confirm("Discard unsaved draft changes?")) {
        return;
      }
      if (!isDesktop) {
        notify("Desktop backend is not connected");
        return;
      }
      const seq = ++loadSeq.current;
      setLoading(true);
      setError("");
      setSampleMode(false);
      setScopeLabel("");
      try {
        const items = await api.listExchanges(session.id);
        if (seq !== loadSeq.current) return;
        setActiveSessionId(session.id);
        setExchanges(items);
        setSelectedId(items[0]?.id);
        setSelectedIds(new Set());
        setDraft(null);
        setDraftOriginal(null);
        setView("traffic");
        setTab("Overview");
      } catch (cause) {
        if (seq === loadSeq.current) setError(String(cause));
      } finally {
        if (seq === loadSeq.current) setLoading(false);
      }
    },
    [notify, draft, draftSaved],
  );

  const bootstrap = useCallback(async () => {
    const seq = ++loadSeq.current;
    setLoading(true);
    setError("");
    if (!isDesktop) {
      setLoading(false);
      setError("Preview mode. Launch the desktop app to capture traffic with the Rust proxy.");
      setSampleMode(true);
      setScopeLabel("Sample traffic");
      setActiveSessionId("sample");
      setExchanges(sampleExchanges);
      setSelectedId(sampleExchanges[0]?.id);
      return;
    }
    try {
      const snapshot = await api.snapshot();
      if (seq !== loadSeq.current) return;
      applySnapshot(snapshot);
      const target =
        snapshot.sessions.find((session) => session.id === snapshot.currentSessionId) ?? snapshot.sessions[0] ?? null;
      if (target) {
        const items = await api.listExchanges(target.id);
        if (seq !== loadSeq.current) return;
        setActiveSessionId(target.id);
        setExchanges(items);
        setSelectedId(items[0]?.id);
      } else {
        setSampleMode(true);
        setScopeLabel("Sample traffic");
        setActiveSessionId("sample");
        setExchanges(sampleExchanges);
        setSelectedId(sampleExchanges[0]?.id);
      }
      await refreshLists();
    } catch (cause) {
      if (seq === loadSeq.current) setError(String(cause));
    } finally {
      if (seq === loadSeq.current) setLoading(false);
    }
  }, [applySnapshot, refreshLists]);

  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("relay.theme", theme);
  }, [theme]);

  useEffect(() => {
    setCaAcknowledged(localStorage.getItem("relay.caAck") === config.caSource);
  }, [config.caSource]);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(""), 3200);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    localStorage.setItem("relay.width.sidebar", String(sidebarWidth));
    localStorage.setItem("relay.width.inspector", String(inspectorWidth));
    localStorage.setItem("relay.height.curl", String(curlHeight));
  }, [sidebarWidth, inspectorWidth, curlHeight]);

  useEffect(() => {
    if (!dragging) return;
    const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));
    const move = (event: MouseEvent) => {
      if (dragging === "sidebar") {
        setSidebarWidth(clamp(event.clientX, 180, 340));
      } else if (dragging === "inspector") {
        setInspectorWidth(clamp(window.innerWidth - event.clientX, 320, 760));
      } else {
        const workspace = document.querySelector(".workspace");
        const bottom = workspace?.getBoundingClientRect().bottom ?? window.innerHeight;
        setCurlHeight(clamp(bottom - event.clientY, 90, 380));
      }
    };
    const stop = () => setDragging(null);
    document.body.classList.add("resizing");
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", stop);
    return () => {
      document.body.classList.remove("resizing");
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", stop);
    };
  }, [dragging]);

  useEffect(() => {
    if (!isDesktop) return;
    let disposed = false;
    let disposeExchange: (() => void) | undefined;
    let disposeStatus: (() => void) | undefined;
    void api
      .onExchange((exchange) => {
        setSessions((current) =>
          current.map((session) =>
            session.id === exchange.sessionId
              ? { ...session, exchangeCount: session.exchangeCount + 1 }
              : session,
          ),
        );
        if (activeRef.current === exchange.sessionId) {
          setExchanges((current) => (current.some((item) => item.id === exchange.id) ? current : [...current, exchange]));
        }
      })
      .then((dispose) => {
        // StrictMode mounts, cleans up and mounts again; a listener that
        // resolves after cleanup must be disposed immediately.
        if (disposed) dispose();
        else disposeExchange = dispose;
      })
      .catch((cause) => setError(String(cause)));
    void api
      .onProxyStatus(() => {
        void api.snapshot().then(applySnapshot).catch(() => undefined);
      })
      .then((dispose) => {
        if (disposed) dispose();
        else disposeStatus = dispose;
      })
      .catch(() => undefined);
    return () => {
      disposed = true;
      disposeExchange?.();
      disposeStatus?.();
    };
  }, [applySnapshot]);

  const searchIndex = useMemo(() => {
    if (!filter.text.trim()) return null;
    return new Map(exchanges.map((exchange) => [exchange.id, searchHaystack(exchange)]));
  }, [exchanges, filter.text]);
  const filtered = useMemo(
    () => exchanges.filter((exchange) => matchesFilter(exchange, filter, searchIndex?.get(exchange.id))),
    [exchanges, filter, searchIndex],
  );
  const selected = useMemo(
    () => filtered.find((exchange) => exchange.id === selectedId) ?? filtered[0] ?? null,
    [filtered, selectedId],
  );
  const hosts = useMemo(() => uniqueHosts(exchanges), [exchanges]);
  const contentTypes = useMemo(() => uniqueContentTypes(exchanges), [exchanges]);

  useEffect(() => {
    if (!selected) return;
    if (selected.id !== selectedId) setSelectedId(selected.id);
  }, [selected, selectedId]);

  const curlSource = draft && draftOriginal ? draft : selected;
  useEffect(() => {
    if (!curlSource) {
      setBundle(null);
      setCleanBundle(null);
      setCurlLoading(false);
      return;
    }
    if (!isDesktop) {
      setBundle(null);
      setCleanBundle(null);
      setCurlLoading(false);
      return;
    }
    let cancelled = false;
    setCurlLoading(true);
    const work = draft && draftOriginal
      ? Promise.all([api.generateCurlDraft(draft, false), api.generateCurlDraft(draft, true)])
      : Promise.all([
          api.generateCurl(draftOriginal ?? (selected as Exchange), false),
          api.generateCurl(draftOriginal ?? (selected as Exchange), true),
        ]);
    work
      .then(([normal, clean]) => {
        if (cancelled) return;
        setBundle(normal);
        setCleanBundle(clean);
      })
      .catch((cause) => {
        if (cancelled) return;
        setBundle(null);
        setCleanBundle(null);
        setError(String(cause));
      })
      .finally(() => {
        if (!cancelled) setCurlLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft?.updatedAt, draft?.id, selected?.id, selected?.method, selected?.url, draftOriginal?.id]);

  const startProxy = useCallback(
    async (host: string, port: number) => {
      setBusy(true);
      setError("");
      try {
        const snapshot = await api.startProxy(host, port);
        applySnapshot(snapshot);
        setSettingsOpen(false);
        setSampleMode(false);
        setScopeLabel("");
        const session = snapshot.sessions.find((entry) => entry.id === snapshot.currentSessionId);
        if (session) {
          const items = await api.listExchanges(session.id);
          setActiveSessionId(session.id);
          setExchanges(items);
          setSelectedId(items[0]?.id);
          setSelectedIds(new Set());
          setView("traffic");
        }
        notify(`Proxy listening on ${snapshot.status.host}:${snapshot.status.port}`);
      } catch (cause) {
        setError(String(cause));
      } finally {
        setBusy(false);
      }
    },
    [applySnapshot, notify],
  );

  const stopProxy = useCallback(async () => {
    setBusy(true);
    try {
      const snapshot = await api.stopProxy();
      applySnapshot(snapshot);
      notify("Proxy stopped");
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }, [applySnapshot, notify]);

  const toggleCapture = useCallback(() => {
    const needsProfile = /generated|imported/i.test(config.caSource);
    if (proxy.running) {
      void stopProxy();
    } else if (config.caLoaded && (!needsProfile || caAcknowledged)) {
      void startProxy(config.host, config.port);
    } else if (config.caLoaded) {
      setCertGuideOpen(true);
    } else {
      openSettings();
    }
  }, [proxy.running, config.caLoaded, config.caSource, caAcknowledged, config.host, config.port, stopProxy, startProxy, openSettings]);

  const importCa = useCallback(
    async (cert: string, key: string) => {
      setBusy(true);
      setError("");
      try {
        const snapshot = await api.importCa(cert, key);
        applySnapshot(snapshot);
        localStorage.removeItem("relay.caAck");
        setCaAcknowledged(false);
        notify("CA material imported");
      } catch (cause) {
        setError(String(cause));
      } finally {
        setBusy(false);
      }
    },
    [applySnapshot, notify, settingsOpen],
  );

  const discoverCa = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const snapshot = await api.discoverCa();
      applySnapshot(snapshot);
      localStorage.setItem("relay.caAck", snapshot.config.caSource);
      setCaAcknowledged(true);
      notify("Using the mitmproxy CA already trusted on the device");
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }, [applySnapshot, notify, settingsOpen]);

  const saveConfig = useCallback(
    async (host: string, port: number) => {
      setBusy(true);
      try {
        const snapshot = await api.updateConfig(host, port);
        applySnapshot(snapshot);
        notify("Proxy settings saved");
      } catch (cause) {
        setError(String(cause));
      } finally {
        setBusy(false);
      }
    },
    [applySnapshot, notify],
  );

  const installCaOnPc = useCallback(async () => {
    setInstallingCa(true);
    try {
      return await api.installCaOnPc();
    } finally {
      setInstallingCa(false);
    }
  }, []);

  const openMitmIt = useCallback(async () => {
    try {
      await api.openMitmIt();
    } catch (cause) {
      setError(String(cause));
    }
  }, []);

  const setSystemProxy = useCallback(async (enabled: boolean) => {
    setBusy(true);
    try {
      const snapshot = await api.setSystemProxy(enabled);
      applySnapshot(snapshot);
      notify(enabled ? "This PC now uses Relay as its system proxy" : "System proxy restored");
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }, [applySnapshot, notify]);

  const proxyThisPcAndOpen = useCallback(async () => {
    setError("");
    try {
      if (!proxy.running) {
        await startProxy(config.host, config.port);
      }
      const snapshot = await api.setSystemProxy(true);
      applySnapshot(snapshot);
      await api.openMitmIt();
    } catch (cause) {
      setError(String(cause));
    }
  }, [proxy.running, config.host, config.port, startProxy, applySnapshot]);

  const acknowledgeCertificate = useCallback(() => {
    localStorage.setItem("relay.caAck", config.caSource);
    setCaAcknowledged(true);
    setCertGuideOpen(false);
    if (!proxy.running) {
      void startProxy(config.host, config.port);
    }
  }, [config.caSource, config.host, config.port, proxy.running, startProxy]);

  const saveUpstream = useCallback(
    async (url: string, username: string, password: string) => {
      setBusy(true);
      setError("");
      try {
        const snapshot = await api.setUpstream(url, username, password);
        applySnapshot(snapshot);
        setUpstreamCheck(null);
        notify(url.trim() ? "Upstream proxy saved" : "Upstream proxy removed");
      } catch (cause) {
        setError(String(cause));
      } finally {
        setBusy(false);
      }
    },
    [applySnapshot, notify],
  );

  const checkUpstream = useCallback(async () => {
    setCheckingUpstream(true);
    setError("");
    try {
      const result = await api.checkUpstream();
      setUpstreamCheck(result);
      notify(`Exit IP: ${result.ip}`);
    } catch (cause) {
      setUpstreamCheck(null);
      setError(String(cause));
    } finally {
      setCheckingUpstream(false);
    }
  }, [notify]);

  const openDraft = useCallback(
    (next: Draft, original: Exchange) => {
      setDraft(next);
      setDraftOriginal(original);
      setDraftSaved(true);
      setReplayOutcome(null);
      setReplayError("");
    },
    [],
  );

  const createDraftFromSelected = useCallback(async () => {
    if (!selected) {
      notify("Select an exchange first");
      return;
    }
    if (sampleMode) {
      notify("Start a capture before creating drafts");
      return;
    }
    if (draft) {
      notify("Close the current draft before creating another");
      return;
    }
    const existing = drafts.find((item) => item.sourceExchangeId === selected.id);
    if (existing) {
      setDraft(existing);
      setDraftOriginal(selected);
      setDraftSaved(true);
      setReplayOutcome(null);
      setReplayError("");
      notify("Opened the existing draft for this exchange");
      return;
    }
    const next = makeDraft(selected);
    setDraft(next);
    setDraftOriginal(selected);
    setReplayOutcome(null);
    setReplayError("");
    if (isDesktop) {
      try {
        await api.saveDraft(next);
        setDraftSaved(true);
        await refreshLists();
      } catch (cause) {
        setError(String(cause));
        setDraftSaved(false);
      }
    } else {
      setDraftSaved(false);
    }
    notify("Draft created. The captured exchange stays read-only.");
  }, [selected, draft, drafts, refreshLists, notify, sampleMode]);

  const confirmDiscardDraft = useCallback(() => {
    if (!draft || draftSaved) return true;
    return window.confirm("Discard unsaved draft changes?");
  }, [draft, draftSaved]);

  const closeDraft = useCallback(() => {
    if (!confirmDiscardDraft()) {
      return false;
    }
    setDraft(null);
    setDraftOriginal(null);
    setReplayOutcome(null);
    return true;
  }, [confirmDiscardDraft]);

  const saveDraft = useCallback(async () => {
    if (!draft) return;
    if (!isDesktop) return notify("Saving drafts requires the desktop backend");
    try {
      await api.saveDraft(draft);
      setDraftSaved(true);
      await refreshLists();
      notify("Draft saved locally");
    } catch (cause) {
      setError(String(cause));
    }
  }, [draft, refreshLists, notify]);

  const updateDraft = useCallback((next: Draft) => {
    setDraft(next);
    setDraftSaved(false);
    setReplayOutcome(null);
    setReplayError("");
  }, []);

  const replayDraft = useCallback(async () => {
    if (!draft || !draftOriginal || replaying) return;
    setReplaying(true);
    setReplayError("");
    setReplayOutcome(null);
    try {
      const outcome = await api.replayDraft(draftOriginal, draft);
      setReplayOutcome(outcome);
      notify(`Replay completed · ${outcome.result.status}`);
    } catch (cause) {
      setReplayError(String(cause));
      return;
    } finally {
      setReplaying(false);
    }
    if (!draftSaved) {
      try {
        await api.saveDraft(draft);
        setDraftSaved(true);
        await refreshLists();
      } catch (cause) {
        setError(String(cause));
        notify("Replay finished, but the draft could not be saved");
      }
    }
  }, [draft, draftOriginal, draftSaved, refreshLists, notify]);

  const exportHar = useCallback(async () => {
    if (!exchanges.length) return;
    if (!isDesktop) return notify("HAR export requires the desktop backend");
    const scope = selectedIds.size
      ? exchanges.filter((exchange) => selectedIds.has(exchange.id))
      : filtered;
    if (!scope.length) return notify("Nothing to export");
    try {
      const { save } = await import("@tauri-apps/plugin-dialog");
      const defaultPath = `relay-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.har`;
      const path = await save({
        defaultPath,
        filters: [{ name: "HAR archive", extensions: ["har"] }],
      });
      if (!path) return;
      const saved = await api.exportHarToPath(scope, path);
      notify(`HAR saved to ${saved}`);
    } catch (cause) {
      setError(String(cause));
    }
  }, [exchanges, selectedIds, filtered, notify]);

  const saveFilter = useCallback(
    async (name: string) => {
      if (!isDesktop) return notify("Saved filters require the desktop backend");
      try {
        await api.saveFilter({ id: uuid(), name, filter, createdAt: new Date().toISOString() });
        await refreshLists();
        notify("Filter saved");
      } catch (cause) {
        setError(String(cause));
      }
    },
    [filter, refreshLists, notify],
  );

  const createCollection = useCallback(
    async (name: string) => {
      if (!isDesktop) return notify("Collections require the desktop backend");
      if (sampleMode) return notify("Start a capture before saving collections");
      const ids = selectedIds.size ? Array.from(selectedIds) : filtered.map((exchange) => exchange.id);
      if (!ids.length) return notify("Select at least one exchange");
      try {
        await api.saveCollection({ id: uuid(), name, createdAt: new Date().toISOString(), exchangeIds: ids });
        await refreshLists();
        notify(`Saved ${ids.length} exchanges to "${name}"`);
      } catch (cause) {
        setError(String(cause));
      }
    },
    [selectedIds, filtered, refreshLists, notify, sampleMode],
  );

  const openFolderDialog = useCallback(() => {
    if (!selectedIds.size) {
      notify("Select requests first");
      return;
    }
    if (sampleMode) {
      notify("Start a capture before saving requests to folders");
      return;
    }
    setFolderOpen(true);
  }, [selectedIds, sampleMode, notify]);

  const saveToExistingFolder = useCallback(
    async (collection: Collection) => {
      if (sampleMode) return notify("Start a capture before saving requests to folders");
      const ids = Array.from(selectedIds);
      const merged = Array.from(new Set([...collection.exchangeIds, ...ids]));
      try {
        await api.saveCollection({ ...collection, exchangeIds: merged });
        await refreshLists();
        setFolderOpen(false);
        setSelectedIds(new Set());
        notify(`Saved ${ids.length} requests to “${collection.name}”`);
      } catch (cause) {
        setError(String(cause));
      }
    },
    [selectedIds, refreshLists, notify, sampleMode],
  );

  const createFolderWithSelection = useCallback(
    async (name: string) => {
      if (sampleMode) return notify("Start a capture before saving requests to folders");
      const ids = Array.from(selectedIds);
      try {
        await api.saveCollection({ id: uuid(), name, createdAt: new Date().toISOString(), exchangeIds: ids });
        await refreshLists();
        setFolderOpen(false);
        setSelectedIds(new Set());
        notify(`Created “${name}” with ${ids.length} requests`);
      } catch (cause) {
        setError(String(cause));
      }
    },
    [selectedIds, refreshLists, notify, sampleMode],
  );

  const deleteSelected = useCallback(async () => {
    const ids = Array.from(selectedIds);
    if (!ids.length) return;
    if (!window.confirm(`Delete ${ids.length} selected request${ids.length === 1 ? "" : "s"}?`)) return;
    if (sampleMode) {
      setExchanges((current) => current.filter((exchange) => !selectedIds.has(exchange.id)));
      setSelectedIds(new Set());
      notify("Removed from sample traffic");
      return;
    }
    try {
      const deleted = await api.deleteExchanges(ids);
      setExchanges((current) => current.filter((exchange) => !selectedIds.has(exchange.id)));
      setSelectedIds(new Set());
      const snapshot = await api.snapshot();
      applySnapshot(snapshot);
      notify(`${deleted} request${deleted === 1 ? "" : "s"} deleted`);
    } catch (cause) {
      setError(String(cause));
    }
  }, [selectedIds, sampleMode, applySnapshot, notify]);

  const openCollection = useCallback(
    async (collection: Collection) => {
      if (draft && !draftSaved && !window.confirm("Discard unsaved draft changes?")) {
        return;
      }
      if (!isDesktop) return notify("Collections require the desktop backend");
      const seq = ++loadSeq.current;
      try {
        const items = await api.getExchanges(collection.exchangeIds);
        if (seq !== loadSeq.current) return;
        setActiveSessionId(`collection:${collection.id}`);
        setSampleMode(false);
        setScopeLabel(`Collection · ${collection.name}`);
        setExchanges(items);
        setSelectedId(items[0]?.id);
        setSelectedIds(new Set());
        setView("traffic");
        setDraft(null);
        setDraftOriginal(null);
        if (!items.length) notify("This collection is empty");
      } catch (cause) {
        if (seq === loadSeq.current) setError(String(cause));
      }
    },
    [notify, draft, draftSaved],
  );

  const openDraftFromList = useCallback(
    async (next: Draft) => {
      if (!confirmDiscardDraft()) return;
      try {
        const source = exchanges.find((exchange) => exchange.id === next.sourceExchangeId)
          ?? (isDesktop ? (await api.getExchanges([next.sourceExchangeId]))[0] : undefined);
        if (!source) {
          notify("Source exchange is no longer available");
          return;
        }
        openDraft(next, source);
        setView("traffic");
      } catch (cause) {
        setError(String(cause));
      }
    },
    [exchanges, openDraft, notify, confirmDiscardDraft],
  );

  const deleteDraft = useCallback(
    async (target: Draft) => {
      if (!window.confirm(`Delete draft for ${target.url}?`)) return;
      try {
        await api.deleteDraft(target.id);
        if (draft?.id === target.id) {
          setDraft(null);
          setDraftOriginal(null);
        }
        await refreshLists();
        notify("Draft deleted");
      } catch (cause) {
        setError(String(cause));
      }
    },
    [draft, refreshLists, notify],
  );

  const clearHistory = useCallback(async () => {
    if (!window.confirm("Delete all capture sessions and their requests?")) return;
    try {
      const snapshot = await api.clearSessions();
      applySnapshot(snapshot);
      setSessions(snapshot.sessions);
      setActiveSessionId(null);
      setExchanges([]);
      setSelectedId(undefined);
      setSelectedIds(new Set());
      setDraft(null);
      setDraftOriginal(null);
      notify("History cleared");
    } catch (cause) {
      setError(String(cause));
    }
  }, [applySnapshot, notify]);

  const clearEmptySessions = useCallback(async () => {
    const empty = sessions.filter(
      (session) => session.exchangeCount === 0 && !(proxy.running && session.id === currentSessionId),
    );
    if (!empty.length) {
      notify("No empty sessions to remove");
      return;
    }
    if (!window.confirm(`Remove ${empty.length} session${empty.length === 1 ? "" : "s"} with no captured requests?`)) {
      return;
    }
    try {
      for (const session of empty) {
        await api.deleteSession(session.id);
      }
      const snapshot = await api.snapshot();
      applySnapshot(snapshot);
      setSessions(snapshot.sessions);
      if (activeSessionId && empty.some((session) => session.id === activeSessionId)) {
        setActiveSessionId(null);
        setExchanges([]);
        setSelectedId(undefined);
        setSelectedIds(new Set());
      }
      notify(`Removed ${empty.length} empty session${empty.length === 1 ? "" : "s"}`);
    } catch (cause) {
      setError(String(cause));
    }
  }, [sessions, currentSessionId, activeSessionId, applySnapshot, notify]);

  const deleteSession = useCallback(
    async (session: Session) => {
      if (!window.confirm(`Delete “${session.name}” and its exchanges?`)) return;
      try {
        const snapshot = await api.deleteSession(session.id);
        applySnapshot(snapshot);
        if (activeSessionId === session.id) {
          const fallback = snapshot.sessions[0];
          if (fallback) await loadSession(fallback);
          else {
            setExchanges([]);
            setSelectedId(undefined);
            setSelectedIds(new Set());
            setActiveSessionId(null);
          }
        }
        notify("Session deleted");
      } catch (cause) {
        setError(String(cause));
      }
    },
    [activeSessionId, applySnapshot, loadSession, notify],
  );

  const deleteCollection = useCallback(
    async (collection: Collection) => {
      if (!window.confirm(`Delete collection “${collection.name}”?`)) return;
      try {
        await api.deleteCollection(collection.id);
        await refreshLists();
        if (activeSessionId === `collection:${collection.id}`) {
          setExchanges([]);
          setSelectedId(undefined);
          setSelectedIds(new Set());
          setActiveSessionId(null);
          setScopeLabel("");
        }
        notify("Collection deleted");
      } catch (cause) {
        setError(String(cause));
      }
    },
    [activeSessionId, refreshLists, notify],
  );

  const deleteSavedFilter = useCallback(
    async (saved: SavedFilter) => {
      try {
        await api.deleteFilter(saved.id);
        await refreshLists();
      } catch (cause) {
        setError(String(cause));
      }
    },
    [refreshLists],
  );

  const loadSample = useCallback(() => {
    if (!confirmDiscardDraft()) return;
    setSampleMode(true);
    setScopeLabel("Sample traffic");
    setActiveSessionId("sample");
    setExchanges(sampleExchanges);
    setSelectedId(sampleExchanges[0]?.id);
    setSelectedIds(new Set());
    setView("traffic");
    setDraft(null);
    setDraftOriginal(null);
    setDraftSaved(true);
    setReplayOutcome(null);
    setReplayError("");
    notify("Sample traffic loaded for layout review");
  }, [notify, confirmDiscardDraft]);

  const clearSample = useCallback(() => {
    if (!confirmDiscardDraft()) return;
    setSampleMode(false);
    setScopeLabel("");
    setActiveSessionId(null);
    setExchanges([]);
    setSelectedId(undefined);
    setSelectedIds(new Set());
    setDraft(null);
    setDraftOriginal(null);
    setDraftSaved(true);
    setReplayOutcome(null);
    setReplayError("");
  }, [confirmDiscardDraft]);

  const copy = useCallback(async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      notify(`${label} copied`);
    } catch {
      notify("Clipboard is unavailable");
    }
  }, [notify]);

  const refreshDrafts = useCallback(async () => {
    if (!isDesktop) return;
    setDraftsLoading(true);
    try {
      setDrafts(await api.listDrafts());
    } catch (cause) {
      setError(String(cause));
    } finally {
      setDraftsLoading(false);
    }
  }, []);

  const refreshCollections = useCallback(async () => {
    if (!isDesktop) return;
    setCollectionsLoading(true);
    try {
      setCollections(await api.listCollections());
    } catch (cause) {
      setError(String(cause));
    } finally {
      setCollectionsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (view === "drafts") void refreshDrafts();
    if (view === "collections") void refreshCollections();
    if (view === "history" && isDesktop) void api.snapshot().then((snapshot) => {
      applySnapshot(snapshot);
    }).catch(() => undefined);
  }, [view, refreshDrafts, refreshCollections, applySnapshot]);

  const commands = useMemo<PaletteCommand[]>(() => {
    const base: PaletteCommand[] = [
      { id: "traffic", title: "Go to traffic", group: "Navigate", icon: "traffic" },
      { id: "drafts", title: "Go to drafts", group: "Navigate", icon: "drafts" },
      { id: "collections", title: "Go to collections", group: "Navigate", icon: "collections" },
      { id: "history", title: "Go to history", group: "Navigate", icon: "history" },
      { id: "theme", title: "Toggle theme", group: "Appearance", icon: "moon" },
      { id: "settings", title: "Open proxy settings", group: "Capture", icon: "settings" },
      { id: "certificate", title: "Certificate setup guide", group: "Capture", icon: "lock" },
      { id: "search", title: "Focus search", group: "Navigate", icon: "search", hint: "Ctrl F" },
      { id: "group", title: "Toggle host grouping", group: "View", icon: "layers" },
      { id: "mask", title: masked ? "Reveal secrets" : "Mask secrets", group: "Privacy", icon: "lock" },
      { id: "har", title: "Export HAR", group: "Data", icon: "download", hint: "Ctrl Shift H" },
      { id: "filter", title: "Save current filter", group: "Filters", icon: "filter" },
      { id: "sample", title: "Load sample traffic", group: "Workspace", icon: "layers" },
    ];
    if (proxy.running) base.unshift({ id: "stop", title: "Stop proxy", group: "Capture", icon: "stop" });
    else base.unshift({ id: "start", title: "Start proxy", group: "Capture", icon: "play" });
    if (selected) {
      base.unshift({ id: "draft", title: "Create draft from selection", group: "Workflow", icon: "drafts", hint: "Ctrl D" });
      base.push({ id: "copy-curl", title: "Copy current curl", group: "Data", icon: "copy" });
    }
    if (selectedIds.size > 0) {
      base.push({ id: "folder", title: "Save selected to folder", group: "Data", icon: "collections" });
      base.push({ id: "delete-selected", title: `Delete ${selectedIds.size} selected`, group: "Data", icon: "trash" });
    }
    if (sampleMode) {
      base.push({ id: "clear-sample", title: "Clear sample traffic", group: "Workspace", icon: "close" });
    }
    if (draft) {
      base.unshift({ id: "replay", title: "Replay current draft", group: "Workflow", icon: "play", hint: "Ctrl Enter" });
      base.unshift({ id: "save-draft", title: "Save current draft", group: "Workflow", icon: "check", hint: "Ctrl S" });
    }
    return base;
  }, [proxy.running, selected, draft, masked, selectedIds.size, sampleMode]);

  const runCommand = useCallback(
    (id: string) => {
      switch (id) {
        case "start":
          toggleCapture();
          break;
        case "stop":
          void stopProxy();
          break;
        case "traffic":
        case "drafts":
        case "collections":
        case "history":
          setView(id as ViewMode);
          break;
        case "theme":
          setTheme((value) => (value === "light" ? "dark" : "light"));
          break;
        case "settings":
          openSettings();
          break;
        case "certificate":
          setCertGuideOpen(true);
          break;
        case "search":
          document.getElementById("traffic-search")?.focus();
          break;
        case "group":
          setFilter((current) => ({ ...current, groupByHost: !current.groupByHost }));
          break;
        case "mask":
          setMasked((value) => !value);
          break;
        case "har":
          void exportHar();
          break;
        case "filter":
          setPromptKind("filter");
          break;
        case "sample":
          loadSample();
          break;
        case "draft":
          void createDraftFromSelected();
          break;
        case "copy-curl": {
          const source = curlRedact ? cleanBundle : bundle;
          if (source) void copy(source[curlTarget], curlRedact ? "Redacted curl" : "Curl");
          break;
        }
        case "collection":
        case "folder":
          openFolderDialog();
          break;
        case "delete-selected":
          void deleteSelected();
          break;
        case "clear-sample":
          clearSample();
          break;
        case "replay":
          void replayDraft();
          break;
        case "save-draft":
          void saveDraft();
          break;
        default:
          break;
      }
    },
    [
      stopProxy,
      toggleCapture,
      exportHar,
      saveFilter,
      loadSample,
      createDraftFromSelected,
      bundle,
      cleanBundle,
      curlRedact,
      curlTarget,
      copy,
      openFolderDialog,
      deleteSelected,
      clearSample,
      replayDraft,
      saveDraft,
    ],
  );

  useEffect(() => {
    const listener = (event: KeyboardEvent) => {
      const mod = event.metaKey || event.ctrlKey;
      const target = event.target;
      const typing =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement;
      if (document.querySelector(".overlay")) {
        if (event.key === "Escape") {
          setCertGuideOpen(false);
          setSettingsOpen(false);
          setFolderOpen(false);
          setPromptKind(null);
          setPaletteOpen(false);
        }
        return;
      }
      if (mod && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((value) => !value);
      } else if (mod && event.key.toLowerCase() === "f") {
        event.preventDefault();
        document.getElementById("traffic-search")?.focus();
      } else if (mod && event.key === ",") {
        event.preventDefault();
        openSettings();
      } else if (mod && event.key.toLowerCase() === "d") {
        event.preventDefault();
        if (selected) void createDraftFromSelected();
      } else if (mod && event.key.toLowerCase() === "s" && draft) {
        event.preventDefault();
        void saveDraft();
      } else if (mod && event.key === "Enter" && draft) {
        event.preventDefault();
        void replayDraft();
      } else if (mod && event.shiftKey && event.key.toLowerCase() === "h") {
        event.preventDefault();
        void exportHar();
      } else if (event.key === "/" && !typing && !document.querySelector(".overlay")) {
        event.preventDefault();
        document.getElementById("traffic-search")?.focus();
      } else if (event.key === "Escape") {
        setPaletteOpen(false);
        setSettingsOpen(false);
        setFolderOpen(false);
        setPromptKind(null);
        setCertGuideOpen(false);
      } else if (event.key === "Delete" && selectedIds.size > 0) {
        if (!typing) {
          event.preventDefault();
          void deleteSelected();
        }
      }
    };
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, [selected, createDraftFromSelected, draft, saveDraft, replayDraft, exportHar, selectedIds, deleteSelected]);

  const activeSession = sessions.find((session) => session.id === activeSessionId);
  const breadcrumb = sampleMode
    ? "Sample traffic"
    : scopeLabel || activeSession?.name || (currentSessionId ? "Live session" : "No session");

  const curlSourceLabel = draft && draftOriginal ? "draft" : selected ? `${selected.method} ${selected.host}` : "none";
  const bindAll = config.host === "0.0.0.0" || config.host === "::" || config.host === "[::]";
  const certificateAddress = `${bindAll ? config.lanIp || config.host : config.host}:${config.port}`;

  const renderInspector = () => {
    if (!selected) {
      return (
        <aside className="inspector inspector-empty">
          <div className="empty-state">
            <div className="empty-icon"><Icon name="empty" /></div>
            <h3>No exchange selected</h3>
            <p>Select a request from the table to inspect headers, bodies, timing and raw payloads.</p>
          </div>
        </aside>
      );
    }
    return (
      <Inspector
        exchange={selected}
        tab={tab}
        onTab={setTab}
        masked={masked}
        onToggleMasked={() => setMasked((value) => !value)}
        onCreateDraft={() => void createDraftFromSelected()}
        onNotice={notify}
      />
    );
  };

  return (
    <div
      className="app-shell"
      style={{ gridTemplateColumns: `${sidebarWidth}px 6px minmax(0,1fr)` }}
    >
      <Sidebar
        view={view}
        setView={(next) => {
          if (next !== "traffic" && !closeDraft()) return;
          setView(next);
        }}
        theme={theme}
        onToggleTheme={() => setTheme((value) => (value === "light" ? "dark" : "light"))}
        onCommand={() => setPaletteOpen(true)}
        sessions={sessions}
        currentSessionId={currentSessionId}
        activeSessionId={activeSessionId}
        onOpenSession={(session) => void loadSession(session)}
        onDeleteSession={(session) => void deleteSession(session)}
        filter={filter}
        onChangeFilter={setFilter}
        hosts={hosts}
        contentTypes={contentTypes}
        proxy={proxy}
        onOpenSettings={() => openSettings()}
        savedFilters={savedFilters}
        onApplySavedFilter={(saved) => {
          setFilter(saved.filter);
          setView("traffic");
          notify(`Filter “${saved.name}” applied`);
        }}
        onSaveFilter={() => setPromptKind("filter")}
        onDeleteSavedFilter={(saved) => void deleteSavedFilter(saved)}
        counts={{ traffic: exchanges.length, drafts: drafts.length, collections: collections.length }}
      />

      <div
        className={`splitter splitter-vertical sidebar-splitter ${dragging === "sidebar" ? "active" : ""}`}
        onMouseDown={() => setDragging("sidebar")}
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize sidebar"
      />

      <main className="workspace">
        <header className="topbar">
          <div className="topbar-crumbs">
            <span>Local workspace</span>
            <Icon name="chevron" />
            <strong>{breadcrumb}</strong>
            {sampleMode && (
              <>
                <span className="crumb-flag">sample</span>
                <button className="crumb-action" onClick={clearSample}>clear</button>
                <button className="crumb-action" onClick={toggleCapture}>capture</button>
              </>
            )}
            {scopeLabel && !sampleMode && <span className="crumb-flag">scope</span>}
          </div>
          <div className="topbar-actions">
            {config.upstreamUrl && (
              <span className="upstream-chip" title={`Upstream: ${config.upstreamUrl}`}>
                <Icon name="external" /> via upstream
              </span>
            )}
            <div className="capture-control">
              <span className={proxy.running ? "live-dot" : "idle-dot"} />
              <span>{proxy.running ? "Capturing" : "Idle"}</span>
              <small>
                {proxy.host}:{proxy.port}
              </small>
              <button
                className="icon-button"
                title={proxy.running ? "Stop proxy" : "Start proxy"}
                disabled={busy}
                onClick={toggleCapture}
              >
                <Icon name={proxy.running ? "stop" : "play"} />
              </button>
            </div>
            <button className="icon-button" title="Proxy settings" onClick={() => openSettings()}>
              <Icon name="settings" />
            </button>
            <button className="icon-button" title="Command palette" onClick={() => setPaletteOpen(true)}>
              <Icon name="command" />
            </button>
          </div>
        </header>


        {error && (
          <div className="global-error">
            <Icon name="error" />
            <span>{error}</span>
            <button className="text-button" onClick={() => setError("")}>Dismiss</button>
          </div>
        )}

        {view === "traffic" && draft && draftOriginal ? (
          <div className="content-grid draft-active">
            <DraftWorkspace
              key={draft.id}
              original={draftOriginal}
              draft={draft}
              onChange={updateDraft}
              onClose={closeDraft}
              onSave={() => void saveDraft()}
              onReplay={() => void replayDraft()}
              replaying={replaying}
              replayError={replayError}
              outcome={replayOutcome}
              saved={draftSaved}
              masked={masked}
              onToggleMasked={() => setMasked((value) => !value)}
              onNotice={notify}
            />
          </div>
        ) : view === "traffic" ? (
          <div
            className="content-grid"
            style={{ gridTemplateColumns: `minmax(360px, 1fr) 6px ${inspectorWidth}px` }}
          >
            <section className="traffic-area">
              <TrafficTable
                items={filtered}
                total={exchanges.length}
                filter={filter}
                onChangeFilter={setFilter}
                selectedId={selected?.id}
                onSelect={(exchange) => {
                  setSelectedId(exchange.id);
                  setTab("Overview");
                }}
                selectedIds={selectedIds}
                onToggleSelected={(id) =>
                  setSelectedIds((current) => {
                    const next = new Set(current);
                    if (next.has(id)) next.delete(id);
                    else next.add(id);
                    return next;
                  })
                }
                onSelectAll={(ids) => setSelectedIds(new Set(ids))}
                onSaveSelected={openFolderDialog}
                onDeleteSelected={() => void deleteSelected()}
                onExportHar={() => void exportHar()}
                proxyRunning={proxy.running}
                loading={loading}
                onOpenSettings={() => openSettings()}
                onClearFilters={() =>
                  setFilter({ ...emptyFilter(), groupByHost: filter.groupByHost })
                }
              />
              {loading && exchanges.length > 0 && (
                <div className="loading-overlay">
                  <span className="spinner" /> Reading session
                </div>
              )}
            </section>
            <div
              className={`splitter splitter-vertical inspector-splitter ${dragging === "inspector" ? "active" : ""}`}
              onMouseDown={() => setDragging("inspector")}
              role="separator"
              aria-orientation="vertical"
              aria-label="Resize inspector"
            />
            {renderInspector()}
          </div>
        ) : view === "drafts" ? (
          <DraftsView
            drafts={drafts}
            loading={draftsLoading}
            onOpen={(next) => void openDraftFromList(next)}
            onDelete={(next) => void deleteDraft(next)}
            onClose={() => setView("traffic")}
          />
        ) : view === "collections" ? (
          <CollectionsView
            collections={collections}
            loading={collectionsLoading}
            onOpen={(collection) => void openCollection(collection)}
            onCreate={() => setPromptKind("collection")}
            onDelete={(collection) => void deleteCollection(collection)}
            onClose={() => setView("traffic")}
          />
        ) : (
          <HistoryView
            sessions={sessions}
            currentSessionId={currentSessionId}
            proxyRunning={proxy.running}
            onOpen={(session) => void loadSession(session)}
            onDelete={(session) => void deleteSession(session)}
            onClearAll={() => void clearHistory()}
            onClearEmpty={() => void clearEmptySessions()}
            onClose={() => setView("traffic")}
          />
        )}

        <div
          className={`splitter splitter-horizontal curl-splitter ${dragging === "curl" ? "active" : ""}`}
          onMouseDown={() => setDragging("curl")}
          role="separator"
          aria-orientation="horizontal"
          aria-label="Resize curl panel"
        />
        <div className="curl-dock" style={{ height: curlHeight }}>
          <CurlPanel
            bundle={bundle}
            cleanBundle={cleanBundle}
            redact={curlRedact}
            onRedactChange={setCurlRedact}
            target={curlTarget}
            onTargetChange={setCurlTarget}
            onCopy={(value, label) => void copy(value, label)}
            loading={curlLoading}
            sourceLabel={curlSourceLabel}
          />
        </div>
      </main>

      <CommandPalette
        open={paletteOpen}
        commands={commands}
        onClose={() => setPaletteOpen(false)}
        onAction={runCommand}
      />

      <FolderDialog
        open={folderOpen}
        selectedCount={selectedIds.size}
        collections={collections}
        onClose={() => setFolderOpen(false)}
        onSaveToExisting={(collection) => void saveToExistingFolder(collection)}
        onCreate={(name) => void createFolderWithSelection(name)}
      />

      <PromptDialog
        open={promptKind !== null}
        title={promptKind === "filter" ? "Save filter" : "New collection"}
        description={
          promptKind === "filter"
            ? "Keep this filter in the sidebar for quick access."
            : "Group the currently visible requests into a folder."
        }
        label={promptKind === "filter" ? "FILTER NAME" : "COLLECTION NAME"}
        placeholder={promptKind === "filter" ? "e.g. API errors" : "e.g. Checkout flow"}
        initialValue={promptKind === "filter" ? filter.text || "Untitled filter" : `Collection ${collections.length + 1}`}
        confirmLabel={promptKind === "filter" ? "Save filter" : "Create collection"}
        onClose={() => setPromptKind(null)}
        onSubmit={(name) => {
          const kind = promptKind;
          setPromptKind(null);
          if (kind === "filter") void saveFilter(name);
          if (kind === "collection") void createCollection(name);
        }}
      />

      <CertificateGuide
        open={certGuideOpen}
        address={certificateAddress}
        proxyRunning={proxy.running}
        systemProxy={config.systemProxy}
        caSource={config.caSource}
        installing={installingCa}
        onClose={() => setCertGuideOpen(false)}
        onInstallPc={installCaOnPc}
        onOpenMitmIt={openMitmIt}
        onProxyAndOpen={proxyThisPcAndOpen}
        onAcknowledge={acknowledgeCertificate}
      />

      <SettingsDialog
        open={settingsOpen}
        config={config}
        proxy={proxy}
        busy={busy}
        error={error}
        upstreamCheck={upstreamCheck}
        checkingUpstream={checkingUpstream}
        onSaveUpstream={(url, username, password) => void saveUpstream(url, username, password)}
        onCheckUpstream={() => void checkUpstream()}
        onClose={() => setSettingsOpen(false)}
        onSave={(host, port) => void saveConfig(host, port)}
        onImportCa={(cert, key) => void importCa(cert, key)}
        onDiscover={() => void discoverCa()}
        onOpenCertificateGuide={() => setCertGuideOpen(true)}
        onToggleSystemProxy={(enabled) => void setSystemProxy(enabled)}
        onStart={(host, port) => void startProxy(host, port)}
        onStop={() => void stopProxy()}
      />

      {notice && (
        <div className="toast">
          <Icon name="check" />
          {notice}
        </div>
      )}
    </div>
  );
}















