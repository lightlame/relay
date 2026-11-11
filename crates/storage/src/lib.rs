use std::path::Path;

use domain::{BodyEncoding, Collection, Draft, Exchange, Header, KeyValue, SavedFilter, Session};
use rusqlite::{Connection, OptionalExtension, params};
use serde::de::DeserializeOwned;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("corrupt payload in table {table} row {id}: {source}")]
    CorruptPayload {
        table: &'static str,
        id: String,
        source: serde_json::Error,
    },
}

const SCHEMA_VERSION: i64 = 1;

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at   TEXT
);

CREATE TABLE IF NOT EXISTS exchanges (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    sequence    INTEGER NOT NULL,
    captured_at TEXT NOT NULL,
    method      TEXT NOT NULL,
    host        TEXT NOT NULL,
    url         TEXT NOT NULL,
    status      INTEGER NOT NULL,
    payload     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exchanges_session ON exchanges(session_id);
CREATE INDEX IF NOT EXISTS idx_exchanges_host ON exchanges(host);
CREATE INDEX IF NOT EXISTS idx_exchanges_method ON exchanges(method);

CREATE TABLE IF NOT EXISTS drafts (
    id                 TEXT PRIMARY KEY,
    session_id         TEXT NOT NULL,
    source_exchange_id TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    payload            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collections (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    payload    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS saved_filters (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    payload    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

const UPSERT_EXCHANGE: &str = r#"
INSERT INTO exchanges (id, session_id, sequence, captured_at, method, host, url, status, payload)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
ON CONFLICT(id) DO UPDATE SET
    session_id  = excluded.session_id,
    sequence    = excluded.sequence,
    captured_at = excluded.captured_at,
    method      = excluded.method,
    host        = excluded.host,
    url         = excluded.url,
    status      = excluded.status,
    payload     = excluded.payload
"#;

/// Persistent store backed by a single SQLite connection.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens (or creates) the database at `path`, enables WAL and foreign keys,
    /// and applies pending migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Opens a transient in-memory database, primarily for tests.
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, StorageError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;",
        )?;
        migrate(&conn)?;
        Ok(Self { conn })
    }

    pub fn upsert_session(&self, session: &Session) -> Result<(), StorageError> {
        self.conn.execute(
            r#"
            INSERT INTO sessions (id, name, started_at, ended_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(id) DO UPDATE SET
                name       = excluded.name,
                started_at = excluded.started_at,
                ended_at   = excluded.ended_at
            "#,
            params![
                session.id,
                session.name,
                session.started_at,
                session.ended_at
            ],
        )?;
        Ok(())
    }

    pub fn list_sessions(&self) -> Result<Vec<Session>, StorageError> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, name, started_at, ended_at,
                   (SELECT COUNT(*) FROM exchanges e WHERE e.session_id = sessions.id)
            FROM sessions
            ORDER BY started_at DESC, id ASC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Session {
                id: row.get(0)?,
                name: row.get(1)?,
                started_at: row.get(2)?,
                ended_at: row.get(3)?,
                exchange_count: row.get::<_, i64>(4)? as usize,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Deletes a session; foreign-key cascade removes its exchanges.
    pub fn delete_all_sessions(&self) -> Result<usize, StorageError> {
        let deleted = self.conn.execute("DELETE FROM sessions", [])?;
        Ok(deleted)
    }

    pub fn delete_session(&self, id: &str) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn insert_exchange(&self, exchange: &Exchange) -> Result<(), StorageError> {
        let payload = serde_json::to_string(exchange)?;
        self.conn.execute(
            UPSERT_EXCHANGE,
            params![
                exchange.id,
                exchange.session_id,
                exchange.sequence as i64,
                exchange.captured_at,
                exchange.method,
                exchange.host,
                exchange.url,
                exchange.status as i64,
                payload
            ],
        )?;
        Ok(())
    }

    /// Inserts or updates many exchanges atomically in a single transaction.
    pub fn insert_exchanges(&self, exchanges: &[Exchange]) -> Result<(), StorageError> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(UPSERT_EXCHANGE)?;
            for exchange in exchanges {
                let payload = serde_json::to_string(exchange)?;
                stmt.execute(params![
                    exchange.id,
                    exchange.session_id,
                    exchange.sequence as i64,
                    exchange.captured_at,
                    exchange.method,
                    exchange.host,
                    exchange.url,
                    exchange.status as i64,
                    payload
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_exchanges(&self, session_id: &str) -> Result<Vec<Exchange>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, payload FROM exchanges WHERE session_id = ?1 ORDER BY sequence ASC, id ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, payload) = row?;
            match decode::<Exchange>("exchanges", &id, &payload) {
                Ok(exchange) => out.push(exchange),
                // One damaged row must not make the whole session unreadable.
                Err(err) => {
                    tracing::warn!(exchange_id = %id, error = %err, "skipping corrupt exchange")
                }
            }
        }
        Ok(out)
    }

    pub fn get_exchange(&self, id: &str) -> Result<Option<Exchange>, StorageError> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT id, payload FROM exchanges WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            Some((id, payload)) => Ok(Some(decode::<Exchange>("exchanges", &id, &payload)?)),
            None => Ok(None),
        }
    }

    pub fn delete_exchange(&self, id: &str) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM exchanges WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Deletes many exchanges atomically; returns the number removed.
    pub fn delete_exchanges(&self, ids: &[String]) -> Result<usize, StorageError> {
        let tx = self.conn.unchecked_transaction()?;
        let mut deleted = 0;
        {
            let mut stmt = tx.prepare("DELETE FROM exchanges WHERE id = ?1")?;
            for id in ids {
                deleted += stmt.execute(params![id])?;
            }
        }
        tx.commit()?;
        Ok(deleted)
    }

    pub fn count_exchanges(&self, session_id: &str) -> Result<usize, StorageError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM exchanges WHERE session_id = ?1",
            params![session_id],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    pub fn save_draft(&self, draft: &Draft) -> Result<(), StorageError> {
        let payload = serde_json::to_string(draft)?;
        self.conn.execute(
            r#"
            INSERT INTO drafts (id, session_id, source_exchange_id, updated_at, payload)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(id) DO UPDATE SET
                session_id         = excluded.session_id,
                source_exchange_id = excluded.source_exchange_id,
                updated_at         = excluded.updated_at,
                payload            = excluded.payload
            "#,
            params![
                draft.id,
                draft.session_id,
                draft.source_exchange_id,
                draft.updated_at,
                payload
            ],
        )?;
        Ok(())
    }

    pub fn list_drafts(&self) -> Result<Vec<Draft>, StorageError> {
        self.list_payloads::<Draft>("drafts", "updated_at DESC, id ASC")
    }

    pub fn get_draft(&self, id: &str) -> Result<Option<Draft>, StorageError> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT id, payload FROM drafts WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            Some((id, payload)) => Ok(Some(decode::<Draft>("drafts", &id, &payload)?)),
            None => Ok(None),
        }
    }

    pub fn delete_draft(&self, id: &str) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM drafts WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn save_collection(&self, collection: &Collection) -> Result<(), StorageError> {
        let payload = serde_json::to_string(collection)?;
        self.conn.execute(
            r#"
            INSERT INTO collections (id, name, created_at, payload)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(id) DO UPDATE SET
                name       = excluded.name,
                created_at = excluded.created_at,
                payload    = excluded.payload
            "#,
            params![
                collection.id,
                collection.name,
                collection.created_at,
                payload
            ],
        )?;
        Ok(())
    }

    pub fn list_collections(&self) -> Result<Vec<Collection>, StorageError> {
        self.list_payloads::<Collection>("collections", "created_at DESC, id ASC")
    }

    pub fn delete_collection(&self, id: &str) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM collections WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn save_filter(&self, filter: &SavedFilter) -> Result<(), StorageError> {
        let payload = serde_json::to_string(filter)?;
        self.conn.execute(
            r#"
            INSERT INTO saved_filters (id, name, created_at, payload)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(id) DO UPDATE SET
                name       = excluded.name,
                created_at = excluded.created_at,
                payload    = excluded.payload
            "#,
            params![filter.id, filter.name, filter.created_at, payload],
        )?;
        Ok(())
    }

    pub fn list_filters(&self) -> Result<Vec<SavedFilter>, StorageError> {
        self.list_payloads::<SavedFilter>("saved_filters", "created_at DESC, id ASC")
    }

    pub fn delete_filter(&self, id: &str) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM saved_filters WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.conn.execute(
            r#"
            INSERT INTO settings (key, value) VALUES (?1, ?2)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            "#,
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>, StorageError> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn list_payloads<T: DeserializeOwned>(
        &self,
        table: &'static str,
        order: &str,
    ) -> Result<Vec<T>, StorageError> {
        let sql = format!("SELECT id, payload FROM {table} ORDER BY {order}");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, payload) = row?;
            out.push(decode::<T>(table, &id, &payload)?);
        }
        Ok(out)
    }
}

fn migrate(conn: &Connection) -> Result<(), StorageError> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < SCHEMA_VERSION {
        conn.execute_batch(SCHEMA_V1)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(())
}

fn decode<T: DeserializeOwned>(
    table: &'static str,
    id: &str,
    payload: &str,
) -> Result<T, StorageError> {
    serde_json::from_str(payload).map_err(|source| StorageError::CorruptPayload {
        table,
        id: id.to_owned(),
        source,
    })
}

/// Builds a single HAR 1.2 entry from an exchange.
pub fn har_from_exchange(exchange: &Exchange) -> Result<serde_json::Value, StorageError> {
    let mut request = serde_json::json!({
        "method": exchange.method,
        "url": exchange.url,
        "httpVersion": "HTTP/1.1",
        "headers": headers_json(&exchange.request_headers),
        "queryString": key_values_json(&exchange.query),
        "cookies": key_values_json(&exchange.cookies),
        "headersSize": -1,
        "bodySize": exchange.request_bytes,
    });
    if !exchange.request_body.is_empty() {
        let request_content_type = exchange
            .request_headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-type"))
            .map(|header| header.value.clone())
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let mut post_data = serde_json::json!({
            "mimeType": request_content_type,
            "text": exchange.request_body.text,
        });
        if exchange.request_body.encoding == BodyEncoding::Base64 {
            post_data["encoding"] = serde_json::Value::String("base64".to_owned());
        }
        request["postData"] = post_data;
    }

    let mut content = serde_json::json!({
        "size": exchange.response_bytes,
        "mimeType": exchange.content_type,
        "text": exchange.response_body.text,
    });
    if exchange.response_body.encoding == BodyEncoding::Base64 {
        content["encoding"] = serde_json::Value::String("base64".to_owned());
    }

    let redirect_url = exchange
        .response_headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("location"))
        .map(|h| h.value.clone())
        .unwrap_or_default();

    Ok(serde_json::json!({
        "startedDateTime": normalize_timestamp(&exchange.captured_at),
        "time": exchange.duration_ms,
        "request": request,
        "response": {
            "status": exchange.status,
            "statusText": status_text(exchange.status),
            "httpVersion": "HTTP/1.1",
            "headers": headers_json(&exchange.response_headers),
            "cookies": response_cookies_json(&exchange.response_headers),
            "content": content,
            "redirectURL": redirect_url,
            "headersSize": -1,
            "bodySize": exchange.response_bytes,
        },
        "cache": {},
        "timings": {
            "send": 0.0,
            "wait": exchange.duration_ms,
            "receive": 0.0,
        },
    }))
}

/// Exports exchanges as a HAR 1.2 document.
pub fn export_har(exchanges: &[Exchange], creator: &str) -> Result<String, StorageError> {
    let entries = exchanges
        .iter()
        .map(har_from_exchange)
        .collect::<Result<Vec<_>, _>>()?;
    let har = serde_json::json!({
        "log": {
            "version": "1.2",
            "creator": {
                "name": creator,
                "version": env!("CARGO_PKG_VERSION"),
            },
            "entries": entries,
        }
    });
    Ok(serde_json::to_string_pretty(&har)?)
}

fn headers_json(headers: &[Header]) -> Vec<serde_json::Value> {
    headers
        .iter()
        .map(|h| serde_json::json!({ "name": h.name, "value": h.value }))
        .collect()
}

fn key_values_json(items: &[KeyValue]) -> Vec<serde_json::Value> {
    items
        .iter()
        .map(|kv| serde_json::json!({ "name": kv.name, "value": kv.value }))
        .collect()
}

fn response_cookies_json(headers: &[Header]) -> Vec<serde_json::Value> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|header| {
            let pair = header.value.split(';').next()?.trim();
            let (name, value) = pair.split_once('=')?;
            Some(serde_json::json!({
                "name": name.trim(),
                "value": value.trim(),
            }))
        })
        .collect()
}

fn normalize_timestamp(raw: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|dt| {
            dt.with_timezone(&chrono::Utc)
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        })
        .unwrap_or_else(|_| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

fn status_text(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        418 => "I'm a teapot",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::{Body, Filter, ReplayOptions};

    fn sample_exchange(session_id: &str, id: &str, sequence: u64) -> Exchange {
        Exchange {
            id: id.to_owned(),
            session_id: session_id.to_owned(),
            sequence,
            captured_at: "2026-11-10T12:34:56.789Z".to_owned(),
            method: "POST".to_owned(),
            url: "https://api.example.com/v1/items?q=1".to_owned(),
            host: "api.example.com".to_owned(),
            path: "/v1/items".to_owned(),
            status: 201,
            duration_ms: 42.5,
            request_bytes: 17,
            response_bytes: 5,
            content_type: "application/json".to_owned(),
            error: None,
            request_headers: vec![
                Header::new("content-type", "application/json"),
                Header::new("x-trace", "abc123"),
            ],
            response_headers: vec![Header::new("content-type", "application/json")],
            query: vec![KeyValue {
                name: "q".to_owned(),
                value: "1".to_owned(),
            }],
            cookies: vec![KeyValue {
                name: "sid".to_owned(),
                value: "xyz".to_owned(),
            }],
            request_body: Body::from_utf8_text(
                "{\"hello\":\"world\"}".to_owned(),
                "application/json",
            ),
            response_body: Body::from_base64("aGVsbG8=".to_owned()),
            raw_request: "POST /v1/items HTTP/2".to_owned(),
            raw_response: "HTTP/2 201 Created".to_owned(),
            timing: vec![],
        }
    }

    fn sample_session(id: &str) -> Session {
        Session {
            id: id.to_owned(),
            name: "Session".to_owned(),
            started_at: "2026-11-10T12:00:00.000Z".to_owned(),
            ended_at: None,
            exchange_count: 0,
        }
    }

    fn sample_draft(exchange: &Exchange) -> Draft {
        Draft {
            id: "draft_1".to_owned(),
            session_id: exchange.session_id.clone(),
            source_exchange_id: exchange.id.clone(),
            method: exchange.method.clone(),
            url: exchange.url.clone(),
            headers: exchange.request_headers.clone(),
            cookies: exchange.cookies.clone(),
            body: exchange.request_body.clone(),
            options: ReplayOptions::default(),
            created_at: "2026-11-10T12:00:00.000Z".to_owned(),
            updated_at: "2026-11-10T12:01:00.000Z".to_owned(),
        }
    }

    #[test]
    fn sessions_and_exchanges_roundtrip() {
        let store = Store::open_in_memory().expect("open");
        let session = sample_session("s1");
        store.upsert_session(&session).expect("session");

        let exchange = sample_exchange("s1", "e1", 1);
        store.insert_exchange(&exchange).expect("exchange");

        let sessions = store.list_sessions().expect("list sessions");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "s1");
        assert_eq!(sessions[0].exchange_count, 1);

        let exchanges = store.list_exchanges("s1").expect("list exchanges");
        assert_eq!(exchanges, vec![exchange.clone()]);
        assert_eq!(exchanges[0].request_body.text, "{\"hello\":\"world\"}");
        assert_eq!(exchanges[0].response_body.text, "aGVsbG8=");
        assert_eq!(exchanges[0].request_headers, exchange.request_headers);

        assert_eq!(store.count_exchanges("s1").expect("count"), 1);
        store.delete_exchange("e1").expect("delete exchange");
        assert_eq!(store.count_exchanges("s1").expect("count"), 0);
    }

    #[test]
    fn batch_insert_orders_by_sequence() {
        let store = Store::open_in_memory().expect("open");
        store
            .upsert_session(&sample_session("s1"))
            .expect("session");
        let mut second = sample_exchange("s1", "e2", 2);
        second.method = "PUT".to_owned();
        let first = sample_exchange("s1", "e1", 1);
        store
            .insert_exchanges(&[second.clone(), first.clone()])
            .expect("batch");

        let exchanges = store.list_exchanges("s1").expect("list");
        assert_eq!(exchanges, vec![first, second]);
    }

    #[test]
    fn drafts_roundtrip() {
        let store = Store::open_in_memory().expect("open");
        let exchange = sample_exchange("s1", "e1", 1);
        let draft = sample_draft(&exchange);

        store.save_draft(&draft).expect("save draft");
        assert_eq!(
            store.get_draft("draft_1").expect("get"),
            Some(draft.clone())
        );
        assert_eq!(store.list_drafts().expect("list"), vec![draft.clone()]);
        assert_eq!(store.get_draft("missing").expect("missing"), None);

        store.delete_draft("draft_1").expect("delete");
        assert!(store.list_drafts().expect("list").is_empty());
    }

    #[test]
    fn collections_filters_settings_roundtrip() {
        let store = Store::open_in_memory().expect("open");

        let collection = Collection {
            id: "c1".to_owned(),
            name: "Collection".to_owned(),
            created_at: "2026-11-10T12:00:00.000Z".to_owned(),
            exchange_ids: vec!["e1".to_owned(), "e2".to_owned()],
        };
        store.save_collection(&collection).expect("save collection");
        assert_eq!(
            store.list_collections().expect("list"),
            vec![collection.clone()]
        );
        store.delete_collection("c1").expect("delete collection");
        assert!(store.list_collections().expect("list").is_empty());

        let filter = SavedFilter {
            id: "f1".to_owned(),
            name: "Errors".to_owned(),
            filter: Filter {
                text: "timeout".to_owned(),
                only_errors: true,
                ..Filter::default()
            },
            created_at: "2026-11-10T12:00:00.000Z".to_owned(),
        };
        store.save_filter(&filter).expect("save filter");
        assert_eq!(store.list_filters().expect("list"), vec![filter.clone()]);
        store.delete_filter("f1").expect("delete filter");
        assert!(store.list_filters().expect("list").is_empty());

        assert_eq!(store.get_setting("theme").expect("get"), None);
        store.set_setting("theme", "dark").expect("set");
        assert_eq!(
            store.get_setting("theme").expect("get"),
            Some("dark".to_owned())
        );
        store.set_setting("theme", "light").expect("update");
        assert_eq!(
            store.get_setting("theme").expect("get"),
            Some("light".to_owned())
        );
    }

    #[test]
    fn delete_session_cascades_exchanges() {
        let store = Store::open_in_memory().expect("open");
        store
            .upsert_session(&sample_session("s1"))
            .expect("session");
        store
            .upsert_session(&sample_session("s2"))
            .expect("session");
        store
            .insert_exchange(&sample_exchange("s1", "e1", 1))
            .expect("e1");
        store
            .insert_exchange(&sample_exchange("s1", "e2", 2))
            .expect("e2");
        store
            .insert_exchange(&sample_exchange("s2", "e3", 1))
            .expect("e3");

        store.delete_session("s1").expect("delete");
        assert!(store.list_exchanges("s1").expect("list").is_empty());
        assert_eq!(store.count_exchanges("s1").expect("count"), 0);
        assert_eq!(store.count_exchanges("s2").expect("count"), 1);
    }

    #[test]
    fn corrupt_payload_is_skipped_by_list_but_errors_on_get() {
        let store = Store::open_in_memory().expect("open");
        store
            .upsert_session(&sample_session("s1"))
            .expect("session");
        store
            .insert_exchange(&sample_exchange("s1", "e1", 1))
            .expect("exchange");
        store
            .conn
            .execute(
                "UPDATE exchanges SET payload = 'not json' WHERE id = 'e1'",
                [],
            )
            .expect("corrupt");

        let listed = store.list_exchanges("s1").expect("list");
        assert!(listed.is_empty());

        let err = store.get_exchange("e1").expect_err("should fail");
        assert!(matches!(
            err,
            StorageError::CorruptPayload {
                table: "exchanges",
                ..
            }
        ));
    }

    #[test]
    fn export_har_is_valid_and_preserves_bodies() {
        let mut first = sample_exchange("s1", "e1", 1);
        first.status = 404;
        first.method = "GET".to_owned();
        first.response_body = Body::from_utf8_text("not found".to_owned(), "text/plain");
        first.request_body = Body::empty();
        let mut second = sample_exchange("s1", "e2", 2);
        second
            .response_headers
            .push(Header::new("Set-Cookie", "theme=dark; Path=/; HttpOnly"));

        let json = export_har(&[first, second], "Capture").expect("har");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");

        assert_eq!(parsed["log"]["version"], "1.2");
        assert_eq!(parsed["log"]["creator"]["name"], "Capture");
        let entries = parsed["log"]["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0]["request"]["method"], "GET");
        assert_eq!(entries[0]["response"]["status"], 404);
        assert_eq!(entries[0]["response"]["statusText"], "Not Found");
        assert!(entries[0]["request"].get("postData").is_none());
        assert_eq!(entries[0]["response"]["content"]["text"], "not found");

        assert_eq!(entries[1]["request"]["method"], "POST");
        assert_eq!(entries[1]["request"]["httpVersion"], "HTTP/1.1");
        assert_eq!(entries[1]["response"]["httpVersion"], "HTTP/1.1");
        assert_eq!(entries[1]["response"]["cookies"][0]["name"], "theme");
        assert_eq!(entries[1]["response"]["cookies"][0]["value"], "dark");
        assert_eq!(
            entries[1]["request"]["postData"]["text"],
            "{\"hello\":\"world\"}"
        );
        assert_eq!(entries[1]["response"]["content"]["encoding"], "base64");
        assert_eq!(entries[1]["response"]["content"]["text"], "aGVsbG8=");
        assert_eq!(entries[1]["request"]["headers"][1]["name"], "x-trace");
        assert_eq!(entries[1]["timings"]["wait"], 42.5);
        assert!(
            entries[1]["startedDateTime"]
                .as_str()
                .unwrap()
                .ends_with('Z')
        );
    }
}
