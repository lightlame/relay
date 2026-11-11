import { useEffect, useState } from "react";
import { Icon, type IconName } from "./Icon";
import type { Filter, ProxyStatus, SavedFilter, Session, Theme, ViewMode } from "../types";
import { formatClock } from "../lib/format";

interface SidebarProps {
  view: ViewMode;
  setView: (view: ViewMode) => void;
  theme: Theme;
  onToggleTheme: () => void;
  onCommand: () => void;
  sessions: Session[];
  currentSessionId?: string | null;
  activeSessionId?: string | null;
  onOpenSession: (session: Session) => void;
  onDeleteSession: (session: Session) => void;
  filter: Filter;
  onChangeFilter: (filter: Filter) => void;
  hosts: string[];
  contentTypes: string[];
  proxy: ProxyStatus;
  lanIp?: string | null;
  onOpenSettings: () => void;
  savedFilters: SavedFilter[];
  onApplySavedFilter: (filter: SavedFilter) => void;
  onSaveFilter: () => void;
  onDeleteSavedFilter: (filter: SavedFilter) => void;
  counts: { traffic: number; drafts: number; collections: number };
}

const navItems: Array<[ViewMode, string, IconName]> = [
  ["traffic", "Traffic", "traffic"],
  ["drafts", "Drafts", "drafts"],
  ["collections", "Collections", "collections"],
  ["history", "History", "history"],
];

function toggle(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter((item) => item !== value) : [...list, value];
}

export function Sidebar(props: SidebarProps) {
  const {
    view,
    setView,
    theme,
    onToggleTheme,
    onCommand,
    sessions,
    currentSessionId,
    activeSessionId,
    onOpenSession,
    onDeleteSession,
    filter,
    onChangeFilter,
    hosts,
    contentTypes,
    proxy,
    lanIp,
    onOpenSettings,
    savedFilters,
    onApplySavedFilter,
    onSaveFilter,
    onDeleteSavedFilter,
    counts,
  } = props;

  const pageSize = 3;
  const visibleSessions = sessions;
  const pages = Math.max(1, Math.ceil(visibleSessions.length / pageSize));
  const [page, setPage] = useState(0);

  useEffect(() => {
    setPage((value) => Math.min(value, pages - 1));
  }, [pages]);

  useEffect(() => {
    setPage(0);
  }, [sessions[0]?.id]);

  const pageSessions = visibleSessions.slice(page * pageSize, page * pageSize + pageSize);

  const hasFilters =
    filter.text ||
    filter.methods.length > 0 ||
    filter.statuses.length > 0 ||
    filter.hosts.length > 0 ||
    filter.contentTypes.length > 0 ||
    filter.onlyErrors;

  const bindAllProxy =
    proxy.host === "0.0.0.0" || proxy.host === "::" || proxy.host === "[::]";

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">R</div>
        <strong className="brand-name">Relay</strong>
        <button className="icon-button" title="Toggle theme" onClick={onToggleTheme}>
          <Icon name={theme === "light" ? "moon" : "sun"} />
        </button>
      </div>

      <button className="command-trigger" onClick={onCommand}>
        <Icon name="search" />
        <span>Commands</span>
        <kbd>Ctrl K</kbd>
      </button>

      <nav className="primary-nav">
        {navItems.map(([id, label, icon]) => (
          <button key={id} className={view === id ? "selected" : ""} onClick={() => setView(id)}>
            <Icon name={icon} />
            <span>{label}</span>
            {id === "traffic" && <b className="nav-count">{counts.traffic}</b>}
            {id === "drafts" && <b className="nav-count">{counts.drafts}</b>}
            {id === "collections" && <b className="nav-count">{counts.collections}</b>}
          </button>
        ))}
      </nav>

      <div className="side-section sessions-section">
        <div className="side-title">
          <span>SESSIONS</span>
          <div className="session-pager">
            {pages > 1 && (
              <>
                <button
                  onClick={() => setPage((value) => Math.max(0, value - 1))}
                  disabled={page === 0}
                  title="Previous sessions"
                >
                  ‹
                </button>
                <span>
                  {page + 1}/{pages}
                </span>
                <button
                  onClick={() => setPage((value) => Math.min(pages - 1, value + 1))}
                  disabled={page >= pages - 1}
                  title="Next sessions"
                >
                  ›
                </button>
              </>
            )}
            <button onClick={() => setView("history")} title="All sessions">
              All
            </button>
          </div>
        </div>
        {visibleSessions.length === 0 && <div className="side-empty">No captures yet. Start the proxy to record traffic.</div>}
        {pageSessions.map((session) => (
          <div
            key={session.id}
            className={`session-card ${activeSessionId === session.id ? "selected" : ""}`}
            role="button"
            tabIndex={0}
            onClick={() => onOpenSession(session)}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") onOpenSession(session);
            }}
          >
            {currentSessionId === session.id && proxy.running ? <span className="live-dot" /> : <span className="session-dot" />}
            <div>
              <strong>{session.name}</strong>
              <small>
                {session.exchangeCount} requests · {formatClock(session.startedAt)}
              </small>
            </div>
            <button
              className="icon-button session-remove"
              title="Delete session"
              onClick={(event) => {
                event.stopPropagation();
                onDeleteSession(session);
              }}
            >
              <Icon name="trash" />
            </button>
          </div>
        ))}
      </div>

      {view === "traffic" && (
        <div className="side-section filters-section">
          <div className="side-title">
          <span>FILTERS</span>
          {hasFilters && (
            <button
              onClick={() =>
                onChangeFilter({
                  ...filter,
                  text: "",
                  methods: [],
                  statuses: [],
                  hosts: [],
                  contentTypes: [],
                  onlyErrors: false,
                })
              }
            >
              Reset
            </button>
          )}
        </div>
        <div className="filter-stack">
          <label>
            METHOD
            <select
              value={filter.methods[0] ?? "All"}
              onChange={(event) =>
                onChangeFilter({ ...filter, methods: event.target.value === "All" ? [] : [event.target.value] })
              }
            >
              <option>All</option>
              {["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].map((method) => (
                <option key={method}>{method}</option>
              ))}
            </select>
          </label>
          <label>
            RESULT
            <select
              value={filter.statuses[0] ?? "Any"}
              onChange={(event) => {
                const value = event.target.value;
                onChangeFilter({ ...filter, statuses: value === "Any" ? [] : [value] });
              }}
            >
              <option value="Any">Any</option>
              <option value="success">Success</option>
              <option value="redirect">Redirects</option>
              <option value="client">Client errors</option>
              <option value="server">Server errors</option>
              <option value="error">Errors</option>
            </select>
          </label>
          <label>
            HOST
            <select
              value={filter.hosts[0] ?? "All hosts"}
              onChange={(event) =>
                onChangeFilter({ ...filter, hosts: event.target.value === "All hosts" ? [] : [event.target.value] })
              }
            >
              <option>All hosts</option>
              {hosts.map((host) => (
                <option key={host}>{host}</option>
              ))}
            </select>
          </label>
          <label>
            CONTENT TYPE
            <select
              value={filter.contentTypes[0] ?? "Any type"}
              onChange={(event) =>
                onChangeFilter({
                  ...filter,
                  contentTypes: event.target.value === "Any type" ? [] : [event.target.value],
                })
              }
            >
              <option>Any type</option>
              {contentTypes.map((type) => (
                <option key={type}>{type}</option>
              ))}
            </select>
          </label>
          <label className="check-line side-check">
            <input
              type="checkbox"
              checked={filter.onlyErrors}
              onChange={(event) => onChangeFilter({ ...filter, onlyErrors: event.target.checked })}
            />
            Only errors
          </label>
          <label className="check-line side-check">
            <input
              type="checkbox"
              checked={filter.groupByHost}
              onChange={(event) => onChangeFilter({ ...filter, groupByHost: event.target.checked })}
            />
            Group by host
          </label>
        </div>
        <div className="saved-filter">
          <button onClick={onSaveFilter} title="Save current filter">
            <Icon name="plus" /> Save current
          </button>
          {savedFilters.length > 0 && <span>{savedFilters.length} saved</span>}
        </div>
        {savedFilters.map((saved) => (
          <div className="saved-filter" key={saved.id}>
            <button onClick={() => onApplySavedFilter(saved)}>{saved.name}</button>
            <button onClick={() => onDeleteSavedFilter(saved)} title="Remove saved filter">
              <Icon name="close" />
            </button>
          </div>
        ))}
        </div>
      )}

      <div className="sidebar-foot">
        <div className="proxy-state">
          <span className={proxy.running ? "live-dot" : "idle-dot"} />
          <div>
            <strong>{proxy.running ? "Proxy online" : "Proxy offline"}</strong>
            <small>
              {bindAllProxy ? lanIp || "127.0.0.1" : proxy.host}:{proxy.port}
              {proxy.lastError ? " · issue" : ""}
            </small>
          </div>
          <button className="icon-button" title="Proxy settings" onClick={onOpenSettings}>
            <Icon name="settings" />
          </button>
        </div>
      </div>
    </aside>
  );
}
