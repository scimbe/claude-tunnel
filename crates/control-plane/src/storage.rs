//! SQLite-backed persistence (M18.1, productionization).
//!
//! Production requires durable state: the in-memory control-plane services lose
//! everything on restart. This module provides a SQLite-backed enrollment store
//! with the same semantics as [`crate::enrollment::Enrollment`], so it can
//! replace the in-memory version behind the HTTP layer. `rusqlite` with the
//! `bundled` SQLite (no system dependency) is called synchronously behind a
//! `Mutex`; the axum handlers already lock without holding the guard across an
//! `await`, so this fits the existing pattern.
//!
//! The store is deliberately backend-shaped (open / issue / redeem / binding) so
//! a Postgres backend for the hosted deployment can follow behind the same
//! surface.

use std::sync::Mutex;

use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};

use crate::enrollment::{AgentPublicKey, EnrollError, JoinToken};
use ct_common::{AgentId, TenantId};

/// Why a persisted redemption failed: an enrollment rule or the database.
#[derive(Debug)]
pub enum RedeemError {
    /// The redemption violated an enrollment rule (unknown / already-used token).
    Enroll(EnrollError),
    /// The underlying database operation failed.
    Db(rusqlite::Error),
}

impl std::fmt::Display for RedeemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedeemError::Enroll(e) => write!(f, "{e}"),
            RedeemError::Db(e) => write!(f, "storage error: {e}"),
        }
    }
}

impl std::error::Error for RedeemError {}

impl From<rusqlite::Error> for RedeemError {
    fn from(e: rusqlite::Error) -> Self {
        RedeemError::Db(e)
    }
}

/// SQLite-backed enrollment store (durable equivalent of [`crate::enrollment::Enrollment`]).
pub struct SqliteEnrollment {
    conn: Mutex<Connection>,
}

impl SqliteEnrollment {
    /// Open (creating if needed) a durable store at `path`.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open(path)?)
    }

    /// Open an ephemeral in-memory store (for tests / stateless runs).
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS join_tokens (
                 token    BLOB PRIMARY KEY,
                 tenant   TEXT NOT NULL,
                 redeemed INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS agent_bindings (
                 agent  TEXT PRIMARY KEY,
                 tenant TEXT NOT NULL,
                 pubkey BLOB NOT NULL
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Issue a fresh single-use join token for `tenant`, persisting it.
    pub fn issue_join_token(&self, tenant: &TenantId) -> rusqlite::Result<JoinToken> {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        self.conn.lock().unwrap().execute(
            "INSERT INTO join_tokens (token, tenant, redeemed) VALUES (?1, ?2, 0)",
            params![&bytes[..], tenant.0],
        )?;
        Ok(JoinToken(bytes))
    }

    /// Redeem a join token, binding `agent`'s public key to the token's tenant.
    /// Single-use: a second redemption of the same token is rejected, and the
    /// consumption is persisted so it survives a restart.
    pub fn redeem(
        &self,
        token: &JoinToken,
        agent: &AgentId,
        pubkey: AgentPublicKey,
    ) -> Result<TenantId, RedeemError> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT tenant, redeemed FROM join_tokens WHERE token = ?1",
                params![&token.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (tenant, redeemed) = row.ok_or(RedeemError::Enroll(EnrollError::UnknownToken))?;
        if redeemed != 0 {
            return Err(RedeemError::Enroll(EnrollError::TokenAlreadyUsed));
        }
        conn.execute(
            "UPDATE join_tokens SET redeemed = 1 WHERE token = ?1",
            params![&token.0[..]],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO agent_bindings (agent, tenant, pubkey) VALUES (?1, ?2, ?3)",
            params![agent.0, tenant, &pubkey[..]],
        )?;
        Ok(TenantId(tenant))
    }

    /// The binding recorded for `agent`, if enrolled.
    pub fn binding(
        &self,
        agent: &AgentId,
    ) -> rusqlite::Result<Option<(TenantId, AgentPublicKey)>> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT tenant, pubkey FROM agent_bindings WHERE agent = ?1",
                params![agent.0],
                |r| {
                    let tenant: String = r.get(0)?;
                    let pk: Vec<u8> = r.get(1)?;
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&pk);
                    Ok((TenantId(tenant), key))
                },
            )
            .optional()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantId {
        TenantId("tenant-1".into())
    }

    /// A unique temp DB path (no wall-clock / process helpers needed).
    fn temp_db_path() -> String {
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let name: String = b.iter().map(|x| format!("{x:02x}")).collect();
        std::env::temp_dir()
            .join(format!("ct_enroll_{name}.db"))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn issue_then_redeem_binds_public_key() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let token = store.issue_join_token(&tenant()).unwrap();
        let agent = AgentId("agent-1".into());
        let pubkey = [7u8; 32];

        let bound = store.redeem(&token, &agent, pubkey).unwrap();
        assert_eq!(bound, tenant());
        assert_eq!(store.binding(&agent).unwrap(), Some((tenant(), pubkey)));
    }

    #[test]
    fn join_token_is_single_use() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let token = store.issue_join_token(&tenant()).unwrap();
        store.redeem(&token, &AgentId("a1".into()), [1u8; 32]).unwrap();
        let second = store.redeem(&token, &AgentId("a2".into()), [2u8; 32]);
        assert!(
            matches!(second, Err(RedeemError::Enroll(EnrollError::TokenAlreadyUsed))),
            "second redemption rejected"
        );
    }

    #[test]
    fn unknown_token_is_rejected() {
        let store = SqliteEnrollment::open_in_memory().unwrap();
        let result = store.redeem(&JoinToken([0u8; 32]), &AgentId("a1".into()), [3u8; 32]);
        assert!(matches!(
            result,
            Err(RedeemError::Enroll(EnrollError::UnknownToken))
        ));
    }

    /// The production requirement: state survives a restart. Issue + redeem
    /// against a file-backed store, drop it (simulating a shutdown), reopen the
    /// same file, and confirm the binding persisted and the token stays consumed.
    #[test]
    fn state_survives_reopen() {
        let path = temp_db_path();
        let agent = AgentId("agent-persist".into());
        let token;
        {
            let store = SqliteEnrollment::open(&path).unwrap();
            token = store.issue_join_token(&tenant()).unwrap();
            store.redeem(&token, &agent, [9u8; 32]).unwrap();
        } // store dropped -> connection closed

        let reopened = SqliteEnrollment::open(&path).unwrap();
        assert_eq!(
            reopened.binding(&agent).unwrap(),
            Some((tenant(), [9u8; 32])),
            "binding persisted across reopen"
        );
        let replay = reopened.redeem(&token, &AgentId("other".into()), [1u8; 32]);
        assert!(
            matches!(replay, Err(RedeemError::Enroll(EnrollError::TokenAlreadyUsed))),
            "token stays consumed across reopen"
        );

        let _ = std::fs::remove_file(&path);
    }
}
