//! #776: durable per-tunnel session history -- the foundation for owner-facing
//! uptime, usage, receipts, and alerts.
//!
//! [`EdgeState`](crate::state::EdgeState) keeps `tunnel_bytes`/`connected_since`/
//! `last_seen` in memory only: every redeploy wiped them, and the maps grew by one entry
//! per token ever seen with no eviction. This module adds the missing persistence: one
//! `tunnel_sessions` row per unbroken connection streak (opened by the first
//! registration on either transport, closed by the teardown paths), with the byte
//! counters flushed into the open row periodically and on close. The in-memory maps stay
//! the hot-path counters they are today -- `note_relay` never touches SQLite -- and the
//! flush task in [`run_tunnel_history_flush_loop`] is what finally lets them evict tokens
//! with no live session.
//!
//! Disclosure bound (ADR-0016 posture, same as the presence routes of #763): a session row
//! is METADATA ONLY -- routing token, transport, timestamps, a disconnect reason, and byte
//! volume. Never a hostname, source IP, request path, or any payload. The routing token is
//! stored as the same lowercase hex the admin API already uses for it.
//!
//! A separate DB file from `audit_log.rs`'s `conn_audit` (#603): that store is a host-only
//! evidentiary record with its own legal-floor retention argument; this one is served
//! over the admin listener to the control plane, so mixing the two in one file would blur
//! which access posture applies to which table. Same SQLite shape as `audit_log.rs`
//! (`open`/`open_in_memory`, a plain `Mutex<Connection>`, WAL + busy_timeout, owner-only
//! file mode), duplicated rather than shared for the same reason that file gives.
//!
//! Enabled by DEFAULT (unlike the audit log): the default path is `tunnel-history.sqlite`
//! beside the persisted CA key (`edge-ca-key.pem`, the edge's one durable volume);
//! `CT_EDGE_TUNNEL_HISTORY_PATH` overrides it and `CT_EDGE_TUNNEL_HISTORY=off` disables
//! it. A path that cannot be opened falls back to an in-memory store with a loud warning
//! -- the feature keeps working for the process lifetime, it just isn't durable.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ct_common::sync::MutexExt;
use ct_common::RoutingToken;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::shutdown::ShutdownSignal;
use crate::state::EdgeState;

/// Transport label recorded for a session opened by a QUIC registration.
pub const TRANSPORT_QUIC: &str = "quic";
/// Transport label recorded for a session opened by a TLS-TCP fallback park.
pub const TRANSPORT_TCP_FALLBACK: &str = "tcp-fallback";

/// Default file name, placed beside the persisted CA key.
pub const DEFAULT_FILE_NAME: &str = "tunnel-history.sqlite";
/// `CT_EDGE_TUNNEL_IDLE_EVICT_SECS` default: a token with no live registration and no
/// activity for a day is dropped from the in-memory maps (its history is on disk).
pub const DEFAULT_IDLE_EVICT_SECS: u64 = 24 * 60 * 60;
/// `CT_EDGE_TUNNEL_HISTORY_RETENTION_SECS` default: closed sessions are kept 90 days --
/// the longest window the owner-facing uptime summary reports is 30 days, and a
/// quarter's worth of receipts is the longest lookback the feature program names.
pub const DEFAULT_RETENTION_SECS: i64 = 90 * 24 * 60 * 60;
/// How often the flush loop writes byte deltas and runs the in-memory eviction.
const FLUSH_INTERVAL_SECS: u64 = 60;
/// Retention prune cadence, in flush ticks (60 x 60 s = hourly).
const PRUNE_EVERY_TICKS: u64 = 60;

const WINDOW_24H: i64 = 24 * 60 * 60;
const WINDOW_7D: i64 = 7 * WINDOW_24H;
const WINDOW_30D: i64 = 30 * WINDOW_24H;

/// One `tunnel_sessions` row as disclosed over the admin API. `bytes_in` is the
/// client->agent direction, `bytes_out` agent->client -- the same split as
/// `EdgeState::tunnel_bytes` / the tunnel-status route's `bytes_received`/`bytes_sent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRow {
    pub transport: String,
    pub connected_at: i64,
    pub disconnected_at: Option<i64>,
    pub reason: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Uptime percentages (`0.0..=100.0`) over the trailing 24 h / 7 d / 30 d, computed from
/// how much of each window the token's sessions cover (see [`uptime_percent`]).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct UptimeSummary {
    pub h24: f64,
    pub d7: f64,
    pub d30: f64,
}

/// SQLite-backed per-tunnel session history. See the module doc for scope/rationale.
pub struct SqliteTunnelHistory {
    conn: Mutex<Connection>,
}

impl SqliteTunnelHistory {
    /// Open (creating if needed) a durable store at `path` on a tuned WAL connection.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        Self::from_connection(open_tuned(path)?)
    }

    /// Open an ephemeral in-memory store (tests, and the fallback when the configured
    /// path is not writable -- see [`open_with_fallback`]).
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tunnel_sessions (
                 id              INTEGER PRIMARY KEY,
                 routing_token   TEXT NOT NULL,
                 transport       TEXT NOT NULL,
                 connected_at    INTEGER NOT NULL,
                 disconnected_at INTEGER,
                 reason          TEXT,
                 bytes_in        INTEGER NOT NULL DEFAULT 0,
                 bytes_out       INTEGER NOT NULL DEFAULT 0,
                 last_flush      INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_tunnel_sessions_token_connected
                 ON tunnel_sessions (routing_token, connected_at);
             CREATE INDEX IF NOT EXISTS idx_tunnel_sessions_disconnected
                 ON tunnel_sessions (disconnected_at);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open a session for `token_hex` at `now` and return its row id. **One open session
    /// per token at a time**: if an open row already exists it is returned instead of
    /// opening a second, with its `transport` updated to the caller's (a tunnel can move
    /// between QUIC and the TCP fallback mid-streak; the row records the latest).
    pub fn open_session(&self, token_hex: &str, transport: &str, now: i64) -> rusqlite::Result<i64> {
        let conn = self.conn.lock_safe();
        let existing: Option<(i64, String)> = conn
            .query_row(
                "SELECT id, transport FROM tunnel_sessions
                 WHERE routing_token = ?1 AND disconnected_at IS NULL ORDER BY id DESC LIMIT 1",
                params![token_hex],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((id, current)) = existing {
            // Only touch the row when the transport actually changed: a re-parking
            // TCP-fallback pool calls this on every park, so the common case is a
            // single indexed SELECT with no write.
            if current != transport {
                conn.execute(
                    "UPDATE tunnel_sessions SET transport = ?1 WHERE id = ?2",
                    params![transport, id],
                )?;
            }
            return Ok(id);
        }
        conn.execute(
            "INSERT INTO tunnel_sessions (routing_token, transport, connected_at, last_flush)
             VALUES (?1, ?2, ?3, ?3)",
            params![token_hex, transport, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Close the open session for `token_hex` (if any) at `now` with `reason`. Returns
    /// whether a row was actually closed -- `false` when none was open, which is a normal
    /// outcome for a teardown of a token that never opened one.
    pub fn close_session(&self, token_hex: &str, now: i64, reason: &str) -> rusqlite::Result<bool> {
        let n = self.conn.lock_safe().execute(
            "UPDATE tunnel_sessions SET disconnected_at = ?1, reason = ?2, last_flush = ?1
             WHERE routing_token = ?3 AND disconnected_at IS NULL",
            params![now, reason, token_hex],
        )?;
        Ok(n > 0)
    }

    /// Add byte deltas to the open session for `token_hex`. No-op (returns `false`) when
    /// none is open -- bytes relayed while no session is open belong to no row.
    pub fn add_session_bytes(
        &self,
        token_hex: &str,
        delta_in: u64,
        delta_out: u64,
        now: i64,
    ) -> rusqlite::Result<bool> {
        let n = self.conn.lock_safe().execute(
            "UPDATE tunnel_sessions
             SET bytes_in = bytes_in + ?1, bytes_out = bytes_out + ?2, last_flush = ?3
             WHERE routing_token = ?4 AND disconnected_at IS NULL",
            params![clamp_i64(delta_in), clamp_i64(delta_out), now, token_hex],
        )?;
        Ok(n > 0)
    }

    /// The most recent `limit` sessions for `token_hex`, newest first (open one, if any,
    /// first of all since it is the latest by `connected_at`).
    pub fn sessions_for(&self, token_hex: &str, limit: usize) -> rusqlite::Result<Vec<SessionRow>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT transport, connected_at, disconnected_at, reason, bytes_in, bytes_out
             FROM tunnel_sessions WHERE routing_token = ?1
             ORDER BY connected_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![token_hex, clamp_i64(limit as u64)], |r| {
            Ok(SessionRow {
                transport: r.get(0)?,
                connected_at: r.get(1)?,
                disconnected_at: r.get(2)?,
                reason: r.get(3)?,
                bytes_in: r.get::<_, i64>(4)?.max(0) as u64,
                bytes_out: r.get::<_, i64>(5)?.max(0) as u64,
            })
        })?;
        rows.collect()
    }

    /// Uptime over the trailing 24 h / 7 d / 30 d ending at `now`, from every session that
    /// overlaps the 30-day window (an open session counts up to `now`). Computed in Rust
    /// over at most 30 days of rows -- see [`uptime_percent`] for the math.
    pub fn uptime_summary(&self, token_hex: &str, now: i64) -> rusqlite::Result<UptimeSummary> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT connected_at, disconnected_at FROM tunnel_sessions
             WHERE routing_token = ?1 AND (disconnected_at IS NULL OR disconnected_at >= ?2)",
        )?;
        let spans: Vec<(i64, Option<i64>)> = stmt
            .query_map(params![token_hex, now - WINDOW_30D], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(UptimeSummary {
            h24: uptime_percent(&spans, now, WINDOW_24H),
            d7: uptime_percent(&spans, now, WINDOW_7D),
            d30: uptime_percent(&spans, now, WINDOW_30D),
        })
    }

    /// Delete CLOSED sessions that ended before `cutoff`; open rows are never pruned
    /// (a still-connected tunnel's streak start must survive however old it is). Returns
    /// the count removed.
    pub fn prune_closed_older_than(&self, cutoff: i64) -> rusqlite::Result<usize> {
        self.conn.lock_safe().execute(
            "DELETE FROM tunnel_sessions WHERE disconnected_at IS NOT NULL AND disconnected_at < ?1",
            params![cutoff],
        )
    }

    /// Whether `token_hex` currently has an open session row.
    pub fn open_session_exists(&self, token_hex: &str) -> rusqlite::Result<bool> {
        let id: Option<i64> = self
            .conn
            .lock_safe()
            .query_row(
                "SELECT id FROM tunnel_sessions WHERE routing_token = ?1 AND disconnected_at IS NULL LIMIT 1",
                params![token_hex],
                |r| r.get(0),
            )
            .optional()?;
        Ok(id.is_some())
    }

    /// Boot-time repair: close EVERY open row at `now` with `reason`. A row left open by
    /// the previous process (crash, redeploy -- nothing runs the close paths then) would
    /// otherwise be adopted by [`open_session`](Self::open_session)'s one-open-row rule on
    /// the token's next registration, and the whole restart gap would count as uptime.
    /// Returns how many rows were closed.
    pub fn close_stale_open_sessions(&self, now: i64, reason: &str) -> rusqlite::Result<usize> {
        self.conn.lock_safe().execute(
            "UPDATE tunnel_sessions SET disconnected_at = ?1, reason = ?2, last_flush = ?1
             WHERE disconnected_at IS NULL",
            params![now, reason],
        )
    }

    #[cfg(test)]
    fn row_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .lock_safe()
            .query_row("SELECT COUNT(*) FROM tunnel_sessions", [], |r| r.get(0))
    }
}

/// Percentage (`0.0..=100.0`) of the `window`-second interval ending at `now` that the
/// given `(connected_at, disconnected_at)` spans cover. An open span (`None`) runs to
/// `now`; a span entirely before the window contributes nothing; a span straddling the
/// window's start counts only its overlap. Spans are assumed non-overlapping (the
/// one-open-session-per-token invariant), and the result is clamped regardless.
pub fn uptime_percent(spans: &[(i64, Option<i64>)], now: i64, window: i64) -> f64 {
    if window <= 0 {
        return 0.0;
    }
    let window_start = now - window;
    let mut covered: i64 = 0;
    for &(start, end) in spans {
        let end = end.unwrap_or(now).min(now);
        let overlap = end - start.max(window_start);
        if overlap > 0 {
            covered = covered.saturating_add(overlap);
        }
    }
    let pct = covered as f64 / window as f64 * 100.0;
    pct.clamp(0.0, 100.0)
}

/// Lowercase hex of a routing token -- the key `tunnel_sessions.routing_token` uses, the
/// same encoding `admin.rs`'s routes and `serve::hex_of_bytes` produce.
pub(crate) fn routing_token_hex(token: &RoutingToken) -> String {
    token.0.iter().map(|b| format!("{b:02x}")).collect()
}

fn clamp_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Same WAL + busy_timeout tuning and owner-only file mode as `audit_log.rs`'s
/// `open_tuned` (#603/#608) -- see that function for the rationale. Duplicated rather
/// than shared because the two stores are deliberately separate files with separate
/// access postures (module doc), and neither module should depend on the other.
fn open_tuned(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    let _mode: String = conn.query_row("PRAGMA journal_mode=WAL;", [], |row| row.get(0))?;
    conn.busy_timeout(Duration::from_secs(5))?;
    restrict_db_file_permissions(path);
    Ok(conn)
}

#[cfg(unix)]
fn restrict_db_file_permissions(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    for candidate in [path.to_string(), format!("{path}-wal"), format!("{path}-shm")] {
        if std::path::Path::new(&candidate).exists() {
            let _ = std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600));
        }
    }
}

#[cfg(not(unix))]
fn restrict_db_file_permissions(_path: &str) {}

/// Resolve where the history lives from `CT_EDGE_TUNNEL_HISTORY` (`off`/`0`/`false`
/// disables -> `None`), `CT_EDGE_TUNNEL_HISTORY_PATH` (a non-empty value wins), and
/// otherwise [`DEFAULT_FILE_NAME`] in the directory of `ca_key_path` (`edge-ca-key.pem`,
/// the edge's one durable volume). Compose's `"${VAR:-}"` convention hands an unset var
/// to the process as `Some("")`, so empty is treated as absent (same as #603's
/// `audit_log_path_from`).
pub fn resolve_history_path(toggle: Option<&str>, path: Option<&str>, ca_key_path: &str) -> Option<String> {
    if let Some(v) = toggle.map(str::trim) {
        if v == "0" || v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("false") {
            return None;
        }
    }
    if let Some(p) = path.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(p.to_string());
    }
    let ca = std::path::Path::new(ca_key_path);
    Some(match ca.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(DEFAULT_FILE_NAME).to_string_lossy().into_owned(),
        _ => DEFAULT_FILE_NAME.to_string(),
    })
}

/// `CT_EDGE_TUNNEL_IDLE_EVICT_SECS`, defaulting to [`DEFAULT_IDLE_EVICT_SECS`] for
/// unset/empty/non-positive input.
pub fn idle_evict_secs_from(v: Option<&str>) -> u64 {
    v.and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_IDLE_EVICT_SECS)
}

/// `CT_EDGE_TUNNEL_HISTORY_RETENTION_SECS`, defaulting to [`DEFAULT_RETENTION_SECS`] for
/// unset/empty/non-positive input.
pub fn retention_secs_from(v: Option<&str>) -> i64 {
    v.and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_RETENTION_SECS)
}

/// Open the durable store at `path`, falling back to an in-memory store (with a loud
/// warning: the history then survives only until the next restart) when the file cannot
/// be opened -- a read-only or missing directory is a deployment mistake, not a reason to
/// lose the feature entirely or refuse tunnel service. `None` only if even the in-memory
/// store fails to initialise. The returned flag is `true` for the durable store.
pub fn open_with_fallback(path: &str) -> Option<(SqliteTunnelHistory, bool)> {
    match SqliteTunnelHistory::open(path) {
        Ok(h) => Some((h, true)),
        Err(e) => {
            eprintln!(
                "ct-edge: WARNING — tunnel session history at {path} failed to open ({e}); \
                 falling back to an IN-MEMORY store: session history and uptime will NOT \
                 survive a restart. Fix the volume or set CT_EDGE_TUNNEL_HISTORY_PATH (#776)"
            );
            match SqliteTunnelHistory::open_in_memory() {
                Ok(h) => Some((h, false)),
                Err(e) => {
                    eprintln!("ct-edge: WARNING — in-memory tunnel session history failed too ({e}); disabled (#776)");
                    None
                }
            }
        }
    }
}

/// Current wall-clock time in Unix seconds, `0` on a clock error (the codebase's
/// `SystemTime::now()` convention, e.g. `audit_log.rs::now_secs`).
pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// #776: the periodic flush + eviction task, spawned from `serve::run_edge` next to the
/// audit retention loop. Every 60 s it (a) writes each token's byte delta since the last
/// flush into its open session row, and (b) evicts from the in-memory maps every token
/// with no live registration whose last activity is older than `idle_evict_secs` (both
/// via [`EdgeState::flush_tunnel_history`]); once an hour it also prunes closed sessions
/// older than `retention_secs`. Raced against `shutdown` like `run_audit_retention_loop`.
/// The final byte flush of a session happens on the close paths themselves, not here, so
/// nothing relayed in the last minute of a session is lost to shutdown timing.
pub async fn run_tunnel_history_flush_loop<H: Clone + Send + Sync + 'static>(
    state: Arc<EdgeState<H>>,
    history: Arc<SqliteTunnelHistory>,
    idle_evict_secs: u64,
    retention_secs: i64,
    shutdown: ShutdownSignal,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(FLUSH_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ticks: u64 = 0;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tick.tick() => {
                let now = now_secs();
                let (flushed, evicted) = state.flush_tunnel_history(now.max(0) as u64, idle_evict_secs);
                if evicted > 0 {
                    eprintln!(
                        "ct-edge: tunnel history flushed {flushed} token(s), evicted {evicted} idle token(s) \
                         from the in-memory maps (#776)"
                    );
                }
                if ticks % PRUNE_EVERY_TICKS == 0 {
                    let cutoff = now.saturating_sub(retention_secs);
                    match history.prune_closed_older_than(cutoff) {
                        Ok(n) if n > 0 => eprintln!(
                            "ct-edge: tunnel-history retention pruned {n} closed session(s) older than {retention_secs}s (#776)"
                        ),
                        Ok(_) => {}
                        Err(e) => eprintln!("ct-edge: tunnel-history retention sweep failed: {e} (#776)"),
                    }
                }
                ticks = ticks.wrapping_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SqliteTunnelHistory {
        SqliteTunnelHistory::open_in_memory().unwrap()
    }

    fn hex(b: u8) -> String {
        format!("{b:02x}").repeat(32)
    }

    /// Mirrors `audit_log.rs`'s `temp_db_path` test helper.
    fn temp_db_path() -> String {
        use rand::RngCore;
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let name: String = b.iter().map(|x| format!("{x:02x}")).collect();
        std::env::temp_dir().join(format!("ct_tunnel_history_{name}.db")).to_string_lossy().into_owned()
    }

    #[test]
    fn open_then_close_records_one_session_with_reason_and_timestamps() {
        let s = store();
        let t = hex(0x01);
        let id = s.open_session(&t, TRANSPORT_QUIC, 1_000).unwrap();
        assert!(id > 0);
        assert!(s.open_session_exists(&t).unwrap());
        assert!(s.close_session(&t, 1_500, "removed").unwrap(), "an open row was closed");
        assert!(!s.open_session_exists(&t).unwrap());
        assert_eq!(
            s.sessions_for(&t, 10).unwrap(),
            vec![SessionRow {
                transport: TRANSPORT_QUIC.into(),
                connected_at: 1_000,
                disconnected_at: Some(1_500),
                reason: Some("removed".into()),
                bytes_in: 0,
                bytes_out: 0,
            }]
        );
        // Closing again finds nothing open -- a normal teardown-of-nothing outcome.
        assert!(!s.close_session(&t, 1_600, "removed").unwrap());
    }

    #[test]
    fn one_open_session_per_token_and_transport_follows_the_latest_registration() {
        let s = store();
        let t = hex(0x02);
        let first = s.open_session(&t, TRANSPORT_QUIC, 100).unwrap();
        // A second registration while the first is still open (a redundant agent, a
        // fallback park) must NOT start a second streak -- same row, transport updated.
        let again = s.open_session(&t, TRANSPORT_TCP_FALLBACK, 200).unwrap();
        assert_eq!(first, again, "the open row is reused");
        assert_eq!(s.row_count().unwrap(), 1);
        let rows = s.sessions_for(&t, 10).unwrap();
        assert_eq!(rows[0].transport, TRANSPORT_TCP_FALLBACK);
        assert_eq!(rows[0].connected_at, 100, "the streak start is the FIRST registration's");

        // Once closed, the next open is a genuinely new session.
        s.close_session(&t, 300, "removed").unwrap();
        let third = s.open_session(&t, TRANSPORT_QUIC, 400).unwrap();
        assert_ne!(third, first);
        assert_eq!(s.row_count().unwrap(), 2);

        // A different token is independent.
        let other = hex(0x03);
        assert_ne!(s.open_session(&other, TRANSPORT_QUIC, 400).unwrap(), third);
        assert_eq!(s.row_count().unwrap(), 3);
    }

    #[test]
    fn add_session_bytes_accumulates_into_the_open_row_and_is_a_noop_without_one() {
        let s = store();
        let t = hex(0x04);
        assert!(!s.add_session_bytes(&t, 10, 20, 50).unwrap(), "no open session -> no-op");
        assert_eq!(s.row_count().unwrap(), 0, "and no row is fabricated");

        s.open_session(&t, TRANSPORT_QUIC, 100).unwrap();
        assert!(s.add_session_bytes(&t, 100, 40, 160).unwrap());
        assert!(s.add_session_bytes(&t, 25, 5, 220).unwrap());
        s.close_session(&t, 300, "removed").unwrap();
        let row = &s.sessions_for(&t, 1).unwrap()[0];
        assert_eq!((row.bytes_in, row.bytes_out), (125, 45), "deltas accumulate");

        // Bytes after the close belong to no session.
        assert!(!s.add_session_bytes(&t, 1, 1, 400).unwrap());
        let row = &s.sessions_for(&t, 1).unwrap()[0];
        assert_eq!((row.bytes_in, row.bytes_out), (125, 45));
    }

    #[test]
    fn sessions_for_is_newest_first_and_honours_the_limit() {
        let s = store();
        let t = hex(0x05);
        for (start, end) in [(100, 200), (300, 400), (500, 600)] {
            s.open_session(&t, TRANSPORT_QUIC, start).unwrap();
            s.close_session(&t, end, "registration-closed").unwrap();
        }
        s.open_session(&t, TRANSPORT_TCP_FALLBACK, 700).unwrap(); // still open
        let rows = s.sessions_for(&t, 10).unwrap();
        let starts: Vec<i64> = rows.iter().map(|r| r.connected_at).collect();
        assert_eq!(starts, vec![700, 500, 300, 100]);
        assert_eq!(rows[0].disconnected_at, None, "the open one leads");
        assert_eq!(s.sessions_for(&t, 2).unwrap().len(), 2);
        assert!(s.sessions_for(&hex(0x06), 10).unwrap().is_empty(), "unknown token -> empty, not an error");
    }

    #[test]
    fn uptime_percent_math() {
        let now = 1_000_000;
        let day = WINDOW_24H;
        // A 12 h session fully inside the last 24 h -> 50 %.
        assert_eq!(uptime_percent(&[(now - 18 * 3600, Some(now - 6 * 3600))], now, day), 50.0);
        // An OPEN session counts up to `now`: opened 6 h ago -> 25 %.
        assert_eq!(uptime_percent(&[(now - 6 * 3600, None)], now, day), 25.0);
        // A session entirely before the window contributes nothing.
        assert_eq!(uptime_percent(&[(now - 3 * day, Some(now - 2 * day))], now, day), 0.0);
        // A session straddling the window start counts only its overlap: ended 18 h ago,
        // started long before -> 6 h of the 24 h window -> 25 %.
        assert_eq!(uptime_percent(&[(now - 3 * day, Some(now - 18 * 3600))], now, day), 25.0);
        // Several sessions add up; a session covering the whole window is 100 %, and the
        // result never exceeds it even if spans overlap.
        assert_eq!(
            uptime_percent(&[(now - 24 * 3600, Some(now - 12 * 3600)), (now - 12 * 3600, None)], now, day),
            100.0
        );
        assert_eq!(uptime_percent(&[(now - 2 * day, None), (now - day, None)], now, day), 100.0);
        // No sessions -> 0 %; a degenerate window -> 0 %, not a division by zero.
        assert_eq!(uptime_percent(&[], now, day), 0.0);
        assert_eq!(uptime_percent(&[(now - 10, None)], now, 0), 0.0);
        // A disconnected_at in the future (clock skew) is capped at `now`.
        assert_eq!(uptime_percent(&[(now - 12 * 3600, Some(now + 3600))], now, day), 50.0);
    }

    #[test]
    fn uptime_summary_reads_the_three_windows_from_the_rows() {
        let s = store();
        let t = hex(0x07);
        let now: i64 = 2_000_000_000;
        // 12 h, closed, inside the last 24 h.
        s.open_session(&t, TRANSPORT_QUIC, now - 18 * 3600).unwrap();
        s.close_session(&t, now - 6 * 3600, "removed").unwrap();
        // A 3-day session that ended 2 days ago: inside 7 d and 30 d, outside 24 h.
        s.open_session(&t, TRANSPORT_QUIC, now - 5 * WINDOW_24H).unwrap();
        s.close_session(&t, now - 2 * WINDOW_24H, "removed").unwrap();
        // A session that ended 40 days ago: outside every window, not even fetched.
        s.open_session(&t, TRANSPORT_QUIC, now - 45 * WINDOW_24H).unwrap();
        s.close_session(&t, now - 40 * WINDOW_24H, "removed").unwrap();

        let u = s.uptime_summary(&t, now).unwrap();
        assert_eq!(u.h24, 50.0);
        let expect_7d = (12.0 * 3600.0 + 3.0 * WINDOW_24H as f64) / WINDOW_7D as f64 * 100.0;
        assert!((u.d7 - expect_7d).abs() < 1e-9, "{} vs {expect_7d}", u.d7);
        let expect_30d = (12.0 * 3600.0 + 3.0 * WINDOW_24H as f64) / WINDOW_30D as f64 * 100.0;
        assert!((u.d30 - expect_30d).abs() < 1e-9, "{} vs {expect_30d}", u.d30);

        // An unknown token is 0/0/0, not an error.
        let z = s.uptime_summary(&hex(0x08), now).unwrap();
        assert_eq!((z.h24, z.d7, z.d30), (0.0, 0.0, 0.0));
    }

    #[test]
    fn prune_removes_only_closed_rows_older_than_the_cutoff_and_keeps_open_ones() {
        let s = store();
        let old = hex(0x09);
        s.open_session(&old, TRANSPORT_QUIC, 100).unwrap();
        s.close_session(&old, 200, "removed").unwrap();
        let recent = hex(0x0a);
        s.open_session(&recent, TRANSPORT_QUIC, 900).unwrap();
        s.close_session(&recent, 950, "removed").unwrap();
        let ancient_but_open = hex(0x0b);
        s.open_session(&ancient_but_open, TRANSPORT_QUIC, 1).unwrap();

        assert_eq!(s.prune_closed_older_than(500).unwrap(), 1, "exactly the old closed row");
        assert_eq!(s.row_count().unwrap(), 2);
        assert!(s.open_session_exists(&ancient_but_open).unwrap(), "an open row is never pruned");
        assert_eq!(s.sessions_for(&recent, 1).unwrap().len(), 1);
        assert_eq!(s.prune_closed_older_than(500).unwrap(), 0, "idempotent");
    }

    #[test]
    fn close_stale_open_sessions_closes_every_open_row_for_a_restart() {
        let s = store();
        s.open_session(&hex(0x0c), TRANSPORT_QUIC, 100).unwrap();
        s.open_session(&hex(0x0d), TRANSPORT_TCP_FALLBACK, 150).unwrap();
        s.open_session(&hex(0x0e), TRANSPORT_QUIC, 50).unwrap();
        s.close_session(&hex(0x0e), 80, "removed").unwrap();
        assert_eq!(s.close_stale_open_sessions(500, "edge-restart").unwrap(), 2);
        assert!(!s.open_session_exists(&hex(0x0c)).unwrap());
        let row = &s.sessions_for(&hex(0x0d), 1).unwrap()[0];
        assert_eq!((row.disconnected_at, row.reason.as_deref()), (Some(500), Some("edge-restart")));
        // The already-closed row keeps its own reason.
        let row = &s.sessions_for(&hex(0x0e), 1).unwrap()[0];
        assert_eq!((row.disconnected_at, row.reason.as_deref()), (Some(80), Some("removed")));
        // And the next registration after the restart starts a NEW session.
        let id = s.open_session(&hex(0x0c), TRANSPORT_QUIC, 600).unwrap();
        assert_eq!(s.sessions_for(&hex(0x0c), 10).unwrap().len(), 2);
        assert!(id > 0);
    }

    #[test]
    fn resolve_history_path_toggle_override_and_default_beside_the_ca_key() {
        let ca = "/shared/edge-ca-key.pem";
        assert_eq!(resolve_history_path(None, None, ca), Some("/shared/tunnel-history.sqlite".into()));
        assert_eq!(resolve_history_path(Some(""), Some(""), ca), Some("/shared/tunnel-history.sqlite".into()));
        assert_eq!(resolve_history_path(Some("on"), None, ca), Some("/shared/tunnel-history.sqlite".into()));
        assert_eq!(resolve_history_path(None, Some(" /data/h.sqlite "), ca), Some("/data/h.sqlite".into()));
        for off in ["off", "OFF", "0", "false"] {
            assert_eq!(resolve_history_path(Some(off), Some("/data/h.sqlite"), ca), None, "{off}");
        }
        // A bare cert file name (no directory) -> a bare default file name.
        assert_eq!(resolve_history_path(None, None, "edge-ca-key.pem"), Some(DEFAULT_FILE_NAME.into()));
    }

    #[test]
    fn env_seconds_parsers_default_on_unset_empty_or_nonpositive() {
        assert_eq!(idle_evict_secs_from(None), DEFAULT_IDLE_EVICT_SECS);
        assert_eq!(idle_evict_secs_from(Some("")), DEFAULT_IDLE_EVICT_SECS);
        assert_eq!(idle_evict_secs_from(Some("0")), DEFAULT_IDLE_EVICT_SECS);
        assert_eq!(idle_evict_secs_from(Some("x")), DEFAULT_IDLE_EVICT_SECS);
        assert_eq!(idle_evict_secs_from(Some(" 3600 ")), 3_600);
        assert_eq!(retention_secs_from(None), DEFAULT_RETENTION_SECS);
        assert_eq!(retention_secs_from(Some("-1")), DEFAULT_RETENTION_SECS);
        assert_eq!(retention_secs_from(Some("86400")), 86_400);
    }

    #[test]
    fn routing_token_hex_is_lowercase_64_chars() {
        let h = routing_token_hex(&RoutingToken([0xab; 32]));
        assert_eq!(h, "ab".repeat(32));
    }

    #[cfg(unix)]
    #[test]
    fn open_restricts_the_file_and_its_wal_shm_sidecars_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_db_path();
        let s = SqliteTunnelHistory::open(&path).unwrap();
        s.open_session(&hex(0x0f), TRANSPORT_QUIC, 1).unwrap();
        let mode = |p: &str| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "main db file must be owner-only");
        for suffix in ["-wal", "-shm"] {
            let sidecar = format!("{path}{suffix}");
            if std::path::Path::new(&sidecar).exists() {
                assert_eq!(mode(&sidecar), 0o600, "{sidecar} must be owner-only too");
            }
        }
        drop(s);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn open_with_fallback_degrades_to_in_memory_when_the_path_is_unusable() {
        let (h, durable) = open_with_fallback("/nonexistent-dir-776/sub/tunnel-history.sqlite").expect("in-memory fallback");
        assert!(!durable);
        h.open_session(&hex(0x10), TRANSPORT_QUIC, 1).unwrap();
        assert!(h.open_session_exists(&hex(0x10)).unwrap());
    }

    #[tokio::test]
    async fn flush_loop_stops_on_shutdown() {
        let state: Arc<EdgeState<u32>> = Arc::new(EdgeState::new());
        let history = Arc::new(store());
        state.set_tunnel_history(history.clone());
        let (ctl, signal) = crate::shutdown::ShutdownController::new();
        let handle = tokio::spawn(run_tunnel_history_flush_loop(
            state,
            history,
            DEFAULT_IDLE_EVICT_SECS,
            DEFAULT_RETENTION_SECS,
            signal,
        ));
        ctl.trigger();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("flush loop must stop promptly on shutdown")
            .unwrap();
    }
}
