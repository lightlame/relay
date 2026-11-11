import { Icon } from "./Icon";
import type { Collection, Draft, Session } from "../types";
import { formatDate, prettyBody } from "../lib/format";

interface DraftsViewProps {
  drafts: Draft[];
  loading: boolean;
  onOpen: (draft: Draft) => void;
  onDelete: (draft: Draft) => void;
  onClose: () => void;
}

export function DraftsView({ drafts, loading, onOpen, onDelete, onClose }: DraftsViewProps) {
  return (
    <div className="collection-view">
      <div className="collection-head">
        <div>
          <h1>Drafts</h1>
          <p>Editable copies derived from captured exchanges. Originals stay untouched.</p>
        </div>
        <div className="collection-head-actions">
          <button className="quiet-button" onClick={onClose}>
            <Icon name="back" /> Back to traffic
          </button>
        </div>
      </div>
      {loading && <div className="inline-loading"><span className="spinner" /> Loading drafts…</div>}
      {!loading && drafts.length === 0 && (
        <div className="empty-state">
          <div className="empty-icon"><Icon name="drafts" /></div>
          <h3>No drafts yet</h3>
          <p>Select an exchange and choose “Create draft” to prepare a replay.</p>
        </div>
      )}
      <div className="collection-list">
        {drafts.map((draft) => (
          <div className="collection-row" key={draft.id}>
            <div className="collection-main" role="button" tabIndex={0} onClick={() => onOpen(draft)} onKeyDown={(event) => event.key === "Enter" && onOpen(draft)}>
              <span className={`method m-${draft.method.toLowerCase()}`}>{draft.method}</span>
              <div>
                <strong>{draft.url}</strong>
                <small>
                  Source {draft.sourceExchangeId.slice(0, 8)} · updated {formatDate(draft.updatedAt)} ·{" "}
                  {prettyBody(draft.body).note}
                </small>
              </div>
            </div>
            <div className="collection-actions">
              <button className="text-button" onClick={() => onOpen(draft)}>Open</button>
              <button className="icon-button" title="Delete draft" onClick={() => onDelete(draft)}>
                <Icon name="trash" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

interface CollectionsViewProps {
  collections: Collection[];
  loading: boolean;
  onOpen: (collection: Collection) => void;
  onCreate: () => void;
  onDelete: (collection: Collection) => void;
  onClose: () => void;
}

export function CollectionsView({ collections, loading, onCreate, onOpen, onDelete, onClose }: CollectionsViewProps) {
  return (
    <div className="collection-view">
      <div className="collection-head">
        <div>
          <h1>Collections</h1>
          <p>Saved groups of exchanges kept in the local database.</p>
        </div>
        <div className="collection-head-actions">
          <button className="primary-button" onClick={onCreate}>
            <Icon name="plus" /> New collection
          </button>
          <button className="quiet-button" onClick={onClose}>
            <Icon name="back" /> Back to traffic
          </button>
        </div>
      </div>
      {loading && <div className="inline-loading"><span className="spinner" /> Loading collections…</div>}
      {!loading && collections.length === 0 && (
        <div className="empty-state">
          <div className="empty-icon"><Icon name="collections" /></div>
          <h3>No collections</h3>
          <p>Select exchanges in the traffic table and save them into a collection.</p>
        </div>
      )}
      <div className="collection-list">
        {collections.map((collection) => (
          <div className="collection-row" key={collection.id}>
            <div className="collection-main" role="button" tabIndex={0} onClick={() => onOpen(collection)} onKeyDown={(event) => event.key === "Enter" && onOpen(collection)}>
              <span className="collection-mark"><Icon name="collections" /></span>
              <div>
                <strong>{collection.name}</strong>
                <small>
                  {collection.exchangeIds.length} exchanges · created {formatDate(collection.createdAt)}
                </small>
              </div>
            </div>
            <div className="collection-actions">
              <button className="text-button" onClick={() => onOpen(collection)}>Open</button>
              <button className="icon-button" title="Delete collection" onClick={() => onDelete(collection)}>
                <Icon name="trash" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

interface HistoryViewProps {
  sessions: Session[];
  currentSessionId?: string | null;
  proxyRunning: boolean;
  onOpen: (session: Session) => void;
  onDelete: (session: Session) => void;
  onClearAll: () => void;
  onClearEmpty: () => void;
  onClose: () => void;
}

export function HistoryView({ sessions, currentSessionId, proxyRunning, onOpen, onDelete, onClearAll, onClearEmpty, onClose }: HistoryViewProps) {
  return (
    <div className="collection-view">
      <div className="collection-head">
        <div>
          <h1>History</h1>
          <p>Every capture session stored locally. Open a session to review its exchanges.</p>
        </div>
        <div className="collection-head-actions">
          <button
            className="quiet-button danger"
            onClick={onClearEmpty}
            disabled={sessions.every((session) => session.exchangeCount > 0 || (proxyRunning && session.id === currentSessionId))}
            title="Delete sessions with no captured requests"
          >
            <Icon name="trash" /> Remove empty
          </button>
          <button
            className="quiet-button danger"
            onClick={onClearAll}
            disabled={proxyRunning || sessions.length === 0}
            title={proxyRunning ? "Stop the proxy before clearing history" : "Delete all sessions"}
          >
            <Icon name="trash" /> Clear history
          </button>
          <button className="quiet-button" onClick={onClose}>
            <Icon name="back" /> Back to traffic
          </button>
        </div>
      </div>
      {sessions.length === 0 && (
        <div className="empty-state">
          <div className="empty-icon"><Icon name="history" /></div>
          <h3>No sessions</h3>
          <p>Start the proxy to create the first capture session.</p>
        </div>
      )}
      <div className="collection-list">
        {sessions.map((session) => (
          <div className="collection-row" key={session.id}>
            <div className="collection-main" role="button" tabIndex={0} onClick={() => onOpen(session)} onKeyDown={(event) => event.key === "Enter" && onOpen(session)}>
              <span className={currentSessionId === session.id && proxyRunning ? "live-dot" : "session-dot"} />
              <div>
                <strong>{session.name}</strong>
                <small>
                  {session.exchangeCount} exchanges · started {new Date(session.startedAt).toLocaleString()}
                  {session.endedAt ? ` · ended ${new Date(session.endedAt).toLocaleTimeString()}` : " · open"}
                </small>
              </div>
            </div>
            <div className="collection-actions">
              <button className="text-button" onClick={() => onOpen(session)}>Open</button>
              <button className="icon-button" title="Delete session" onClick={() => onDelete(session)}>
                <Icon name="trash" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
