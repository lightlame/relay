import { useEffect, useMemo, useRef, useState } from "react";
import { Icon } from "./Icon";
import type { Exchange, Filter } from "../types";
import {
  clockOfSequence,
  formatBytes,
  formatDuration,
  groupByHost,
  isError,
  methodClass,
  shortContentType,
  statusClass,
} from "../lib/format";

interface TrafficTableProps {
  items: Exchange[];
  total: number;
  filter: Filter;
  onChangeFilter: (filter: Filter) => void;
  selectedId?: string;
  onSelect: (exchange: Exchange) => void;
  selectedIds: Set<string>;
  onToggleSelected: (id: string) => void;
  onSelectAll: (ids: string[]) => void;
  onSaveSelected: () => void;
  onDeleteSelected: () => void;
  onExportHar: () => void;
  proxyRunning: boolean;
  loading: boolean;
  onOpenSettings: () => void;
  onClearFilters: () => void;
}

export function TrafficTable(props: TrafficTableProps) {
  const {
    items,
    total,
    filter,
    onChangeFilter,
    selectedId,
    onSelect,
    selectedIds,
    onToggleSelected,
    onSelectAll,
    onSaveSelected,
    onDeleteSelected,
    onExportHar,
    proxyRunning,
    loading,
    onOpenSettings,
    onClearFilters,
  } = props;
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const tableRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (tableRef.current) tableRef.current.scrollTop = 0;
  }, [filter]);
  const groups = useMemo(() => (filter.groupByHost ? groupByHost(items) : []), [items, filter.groupByHost]);
  const allSelected = items.length > 0 && items.every((item) => selectedIds.has(item.id));
  const someSelected = items.some((item) => selectedIds.has(item.id));

  const statusLabels: Record<string, string> = {
    success: "2xx",
    redirect: "3xx",
    client: "4xx",
    server: "5xx",
    error: "errors",
  };
  const chips: Array<{ key: string; label: string; clear: () => void }> = [];
  if (filter.text) {
    chips.push({
      key: "text",
      label: `“${filter.text.length > 28 ? `${filter.text.slice(0, 28)}…` : filter.text}”`,
      clear: () => onChangeFilter({ ...filter, text: "" }),
    });
  }
  filter.methods.forEach((method) => {
    chips.push({
      key: `method-${method}`,
      label: method,
      clear: () => onChangeFilter({ ...filter, methods: filter.methods.filter((m) => m !== method) }),
    });
  });
  filter.statuses.forEach((status) => {
    chips.push({
      key: `status-${status}`,
      label: statusLabels[status] ?? status,
      clear: () => onChangeFilter({ ...filter, statuses: filter.statuses.filter((s) => s !== status) }),
    });
  });
  filter.hosts.forEach((host) => {
    chips.push({
      key: `host-${host}`,
      label: host,
      clear: () => onChangeFilter({ ...filter, hosts: filter.hosts.filter((h) => h !== host) }),
    });
  });
  filter.contentTypes.forEach((type) => {
    chips.push({
      key: `type-${type}`,
      label: type,
      clear: () => onChangeFilter({ ...filter, contentTypes: filter.contentTypes.filter((t) => t !== type) }),
    });
  });
  if (filter.onlyErrors) {
    chips.push({
      key: "errors",
      label: "errors only",
      clear: () => onChangeFilter({ ...filter, onlyErrors: false }),
    });
  }

  const toggleGroup = (host: string) => {
    setCollapsed((current) => {
      const next = new Set(current);
      if (next.has(host)) next.delete(host);
      else next.add(host);
      return next;
    });
  };

  const renderRow = (item: Exchange) => (
    <div
      role="row"
      tabIndex={0}
      className={`traffic-row ${selectedId === item.id ? "row-selected" : ""}`}
      key={item.id}
      onClick={() => onSelect(item)}
      onKeyDown={(event) => {
        if (event.target instanceof HTMLInputElement) return;
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect(item);
        }
      }}
    >
      <span className="row-check" onClick={(event) => event.stopPropagation()}>
        <input
          type="checkbox"
          aria-label={`Select ${item.method} ${item.path}`}
          checked={selectedIds.has(item.id)}
          onChange={() => onToggleSelected(item.id)}
        />
      </span>
      <span className="seq">{String(item.sequence).padStart(2, "0")}</span>
      <span className="time-cell">{clockOfSequence(item)}</span>
      <span className={`method ${methodClass(item.method)}`}>{item.method}</span>
      <span className={statusClass(item)}>
        {item.status || "ERR"}
        {isError(item) && <i>!</i>}
      </span>
      <span className="host-cell">{item.host}</span>
      <span className="path-cell" title={item.path}>
        {item.path}
      </span>
      <span className={item.durationMs >= 1000 ? "duration slow" : "duration"}>{formatDuration(item.durationMs)}</span>
      <span>{formatBytes(item.responseBytes || item.requestBytes)}</span>
      <span className="type-cell" title={item.contentType}>
        {shortContentType(item.contentType)}
      </span>
    </div>
  );

  return (
    <div className="table-wrap">
      <div className="table-toolbar">
        <div className="title-block">
          <h1>Traffic</h1>
          <span>
            {items.length}
            {items.length !== total ? ` / ${total}` : ""} exchanges
          </span>
        </div>
        <div className="toolbar-actions">
          <button
            className={`quiet-button ${filter.groupByHost ? "toggle-active" : ""}`}
            title="Group by host"
            onClick={() => onChangeFilter({ ...filter, groupByHost: !filter.groupByHost })}
          >
            <Icon name="layers" /> Groups
          </button>
          <div className="toolbar-search">
            <Icon name="search" />
            <input
              id="traffic-search"
              value={filter.text}
              onChange={(event) => onChangeFilter({ ...filter, text: event.target.value })}
              placeholder="Search URL, headers, query, body…"
            />
            {filter.text && (
              <button className="search-clear" onClick={() => onChangeFilter({ ...filter, text: "" })} title="Clear search">
                <Icon name="close" />
              </button>
            )}
          </div>
        </div>
      </div>

      {chips.length > 0 && (
        <div className="active-filters">
          <span className="active-filters-label">FILTERS</span>
          {chips.map((chip) => (
            <button className="filter-chip" key={chip.key} onClick={chip.clear} title="Remove filter">
              {chip.label}
              <Icon name="close" />
            </button>
          ))}
          <button
            className="text-button filter-clear-all"
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
            Clear all
          </button>
        </div>
      )}

      <div className="table-meta">
        <div>
          <span className={proxyRunning ? "live-dot" : "idle-dot"} />
          {proxyRunning ? "Live capture" : "Capture paused"}
          <span className="captured-time">
            {selectedIds.size > 0 ? `${selectedIds.size} selected` : "click a row to inspect"}
          </span>
        </div>
        <div className="meta-tools">
          <button
            className="text-button"
            onClick={() => onSelectAll(allSelected ? [] : items.map((item) => item.id))}
            disabled={!items.length}
          >
            {allSelected ? "Clear selection" : "Select all"}
          </button>
          <span className="divider" />
          {selectedIds.size > 0 && (
            <>
              <button className="text-button accent" onClick={onSaveSelected}>
                <Icon name="collections" /> Save to folder
              </button>
              <button className="text-button danger" onClick={onDeleteSelected}>
                <Icon name="trash" /> Delete
              </button>
              <span className="divider" />
            </>
          )}
          <button className="text-button" onClick={onExportHar} disabled={!items.length}>
            <Icon name="download" /> Export HAR
          </button>
        </div>
      </div>

      <div className="traffic-table" ref={tableRef} role="table" aria-label="Captured exchanges">
        <div className="traffic-row traffic-header" role="row">
          <span className="row-check">
            <input
              type="checkbox"
              aria-label="Select all visible exchanges"
              disabled={!items.length}
              checked={allSelected}
              ref={(element) => {
                if (element) {
                  element.indeterminate = items.length > 0 && someSelected && !allSelected;
                }
              }}
              onChange={() => onSelectAll(allSelected ? [] : items.map((item) => item.id))}
            />
          </span>
          <span>#</span>
          <span>TIME</span>
          <span>METHOD</span>
          <span>STATUS</span>
          <span>HOST</span>
          <span>PATH</span>
          <span>DUR</span>
          <span>SIZE</span>
          <span>TYPE</span>
        </div>
        <div className="traffic-body">
          {!filter.groupByHost && items.map(renderRow)}
          {filter.groupByHost &&
            groups.map((group) => (
              <div className="traffic-group" key={group.host}>
                <div
                  className="group-row"
                  role="button"
                  tabIndex={0}
                  onClick={() => toggleGroup(group.host)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") toggleGroup(group.host);
                  }}
                >
                  <Icon name="chevron" className={collapsed.has(group.host) ? "chevron-closed" : ""} />
                  <strong>{group.host}</strong>
                  <span>
                    {group.items.length} request{group.items.length === 1 ? "" : "s"}
                  </span>
                  {group.errors > 0 && <span className="group-errors">{group.errors} errors</span>}
                  <span className="group-tools">
                    <button
                      className="text-button"
                      onClick={(event) => {
                        event.stopPropagation();
                        onChangeFilter({ ...filter, hosts: [group.host] });
                      }}
                    >
                      Filter
                    </button>
                  </span>
                </div>
                {!collapsed.has(group.host) && group.items.map(renderRow)}
              </div>
            ))}
        </div>

        {items.length === 0 && (
          <div className="empty-state">
            <div className="empty-icon">
              <Icon name={loading ? "clock" : "empty"} />
            </div>
            <h3>{loading ? "Loading exchanges" : total === 0 ? "Waiting for traffic" : "No matching requests"}</h3>
            <p>
              {loading
                ? "Reading the current session from local storage."
                : total === 0
                  ? proxyRunning
                    ? "The proxy is live. Requests from the configured device will appear here."
                    : "Start the local proxy or open a saved session to review captured exchanges."
                  : "Adjust the search or filters to widen the result set."}
            </p>
            {!loading && total === 0 && !proxyRunning && (
              <button className="outline-button" onClick={onOpenSettings}>
                Configure capture
              </button>
            )}
            {!loading && total > 0 && (
              <button className="outline-button" onClick={onClearFilters}>
                Clear filters
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}



