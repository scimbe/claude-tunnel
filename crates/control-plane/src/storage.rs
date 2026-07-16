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

use crate::accounts::{AccountId, LedgerError};
use crate::enrollment::{AgentPublicKey, EnrollError, JoinToken};
use crate::payment::{PaymentError, PaymentId};
use crate::registry::TunnelInfo;
use ct_common::{AgentId, RoutingToken, TenantId};
use ct_common::sync::MutexExt;

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
        self.conn.lock_safe().execute(
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
        let conn = self.conn.lock_safe();
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
            .lock_safe()
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

    /// Number of enrolled agents (bound public keys) — for the status view (F4.1).
    pub fn agent_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .lock_safe()
            .query_row("SELECT COUNT(*) FROM agent_bindings", [], |r| r.get(0))
    }
}

/// SQLite-backed tunnel registry (durable equivalent of
/// [`crate::registry::TunnelRegistry`]). Can share the same database file as
/// [`SqliteEnrollment`] — each store owns its tables and its own connection.
pub struct SqliteRegistry {
    conn: Mutex<Connection>,
}

impl SqliteRegistry {
    /// Open (creating if needed) a durable registry at `path`.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open(path)?)
    }

    /// Open an ephemeral in-memory registry (for tests / stateless runs).
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tunnels (
                 token  BLOB PRIMARY KEY,
                 tenant TEXT NOT NULL,
                 agent  TEXT NOT NULL
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Register (or replace) the tunnel served by `token`.
    pub fn register(&self, token: &RoutingToken, info: &TunnelInfo) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "INSERT OR REPLACE INTO tunnels (token, tenant, agent) VALUES (?1, ?2, ?3)",
            params![&token.0[..], info.tenant.0, info.agent.0],
        )?;
        Ok(())
    }

    /// Resolve `token` to its tunnel, if registered (the Rendezvous lookup).
    pub fn lookup(&self, token: &RoutingToken) -> rusqlite::Result<Option<TunnelInfo>> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT tenant, agent FROM tunnels WHERE token = ?1",
                params![&token.0[..]],
                |r| {
                    Ok(TunnelInfo {
                        tenant: TenantId(r.get(0)?),
                        agent: AgentId(r.get(1)?),
                    })
                },
            )
            .optional()
    }

    /// Remove the tunnel for `token` (idempotent).
    pub fn unregister(&self, token: &RoutingToken) -> rusqlite::Result<()> {
        self.conn.lock_safe().execute(
            "DELETE FROM tunnels WHERE token = ?1",
            params![&token.0[..]],
        )?;
        Ok(())
    }

    /// Number of registered tunnels — for the status view (F4.1).
    pub fn tunnel_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .lock_safe()
            .query_row("SELECT COUNT(*) FROM tunnels", [], |r| r.get(0))
    }
}

/// Why a persisted ledger operation failed: a ledger rule or the database.
#[derive(Debug)]
pub enum LedgerOpError {
    Ledger(LedgerError),
    Db(rusqlite::Error),
}

impl std::fmt::Display for LedgerOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerOpError::Ledger(e) => write!(f, "{e}"),
            LedgerOpError::Db(e) => write!(f, "storage error: {e}"),
        }
    }
}
impl std::error::Error for LedgerOpError {}
impl From<rusqlite::Error> for LedgerOpError {
    fn from(e: rusqlite::Error) -> Self {
        LedgerOpError::Db(e)
    }
}

/// Why a persisted payment confirmation failed: a payment rule or the database.
#[derive(Debug)]
pub enum PaymentOpError {
    Payment(PaymentError),
    Db(rusqlite::Error),
}

impl std::fmt::Display for PaymentOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentOpError::Payment(e) => write!(f, "{e}"),
            PaymentOpError::Db(e) => write!(f, "storage error: {e}"),
        }
    }
}
impl std::error::Error for PaymentOpError {}
impl From<rusqlite::Error> for PaymentOpError {
    fn from(e: rusqlite::Error) -> Self {
        PaymentOpError::Db(e)
    }
}

/// SQLite-backed prepaid-credit ledger + payment intake (durable equivalent of
/// [`crate::accounts::Ledger`] and [`crate::payment::PaymentIntake`]).
///
/// Balances are stored as SQLite `INTEGER` (i64); credit amounts far below
/// `i64::MAX` are the realistic case for a prepaid ledger. The confirm path runs
/// in a transaction so a crash cannot leave a payment confirmed without the
/// matching credit (or vice versa).
pub struct SqliteLedger {
    conn: Mutex<Connection>,
}

impl SqliteLedger {
    /// Open (creating if needed) a durable ledger at `path`.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open(path)?)
    }

    /// Open an ephemeral in-memory ledger (for tests / stateless runs).
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS accounts (
                 account BLOB PRIMARY KEY,
                 balance INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS payments (
                 payment   BLOB PRIMARY KEY,
                 account   BLOB NOT NULL,
                 credits   INTEGER NOT NULL,
                 confirmed INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS account_subjects (
                 subject TEXT PRIMARY KEY,
                 account BLOB NOT NULL
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn balance_of(conn: &Connection, id: &AccountId) -> rusqlite::Result<Option<i64>> {
        conn.query_row(
            "SELECT balance FROM accounts WHERE account = ?1",
            params![&id.0[..]],
            |r| r.get(0),
        )
        .optional()
    }

    /// Open a fresh account with a zero balance; returns its id.
    pub fn open_account(&self) -> rusqlite::Result<AccountId> {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        self.conn.lock_safe().execute(
            "INSERT INTO accounts (account, balance) VALUES (?1, 0)",
            params![&bytes[..]],
        )?;
        Ok(AccountId(bytes))
    }

    /// Return the account bound to an OIDC `subject` (e.g. a Keycloak `sub`
    /// claim), creating it with a zero balance on first use (M19.1). Idempotent:
    /// the same subject always maps to the same account, so conventional
    /// authenticated users have one stable account. The lookup + creation run in
    /// a transaction so a subject can never end up with two accounts.
    pub fn account_for_subject(&self, subject: &str) -> Result<AccountId, LedgerOpError> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT account FROM account_subjects WHERE subject = ?1",
                params![subject],
                |r| r.get(0),
            )
            .optional()?;
        let account = if let Some(bytes) = existing {
            let mut a = [0u8; 32];
            a.copy_from_slice(&bytes);
            AccountId(a)
        } else {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            tx.execute(
                "INSERT INTO accounts (account, balance) VALUES (?1, 0)",
                params![&bytes[..]],
            )?;
            tx.execute(
                "INSERT INTO account_subjects (subject, account) VALUES (?1, ?2)",
                params![subject, &bytes[..]],
            )?;
            AccountId(bytes)
        };
        tx.commit()?;
        Ok(account)
    }

    /// Cheap liveness check that the database is reachable (readiness probe).
    pub fn ping(&self) -> rusqlite::Result<()> {
        self.conn
            .lock_safe()
            .query_row("SELECT 1", [], |_| Ok(()))
    }

    /// Number of open accounts — for the status view (F4.1).
    pub fn account_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .lock_safe()
            .query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))
    }

    /// Number of confirmed payments — for the status view (F4.1).
    pub fn confirmed_payment_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .lock_safe()
            .query_row("SELECT COUNT(*) FROM payments WHERE confirmed = 1", [], |r| {
                r.get(0)
            })
    }

    /// Current balance, or [`LedgerError::UnknownAccount`].
    pub fn balance(&self, id: &AccountId) -> Result<u64, LedgerOpError> {
        let conn = self.conn.lock_safe();
        Self::balance_of(&conn, id)?
            .map(|b| b as u64)
            .ok_or(LedgerOpError::Ledger(LedgerError::UnknownAccount))
    }

    /// Add prepaid credit (saturating); returns the new balance.
    pub fn credit(&self, id: &AccountId, amount: u64) -> Result<u64, LedgerOpError> {
        let conn = self.conn.lock_safe();
        let bal = Self::balance_of(&conn, id)?
            .ok_or(LedgerOpError::Ledger(LedgerError::UnknownAccount))?;
        let new = bal.saturating_add(amount as i64);
        conn.execute(
            "UPDATE accounts SET balance = ?1 WHERE account = ?2",
            params![new, &id.0[..]],
        )?;
        Ok(new as u64)
    }

    /// Spend credit; fails with [`LedgerError::InsufficientCredit`] and leaves
    /// the balance unchanged when the account cannot cover `amount`.
    pub fn debit(&self, id: &AccountId, amount: u64) -> Result<u64, LedgerOpError> {
        let conn = self.conn.lock_safe();
        let bal = Self::balance_of(&conn, id)?
            .ok_or(LedgerOpError::Ledger(LedgerError::UnknownAccount))?;
        let bal_u = bal as u64;
        if bal_u < amount {
            return Err(LedgerOpError::Ledger(LedgerError::InsufficientCredit {
                balance: bal_u,
                requested: amount,
            }));
        }
        let new = bal - amount as i64;
        conn.execute(
            "UPDATE accounts SET balance = ?1 WHERE account = ?2",
            params![new, &id.0[..]],
        )?;
        Ok(new as u64)
    }

    /// Register a payment intent (top-up of `credits` against `account`);
    /// returns an opaque [`PaymentId`]. Unconfirmed until [`Self::confirm_payment`].
    pub fn create_intent(&self, account: &AccountId, credits: u64) -> rusqlite::Result<PaymentId> {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        self.conn.lock_safe().execute(
            "INSERT INTO payments (payment, account, credits, confirmed) VALUES (?1, ?2, ?3, 0)",
            params![&bytes[..], &account.0[..], credits as i64],
        )?;
        Ok(PaymentId(bytes))
    }

    /// Confirm a payment and credit the account, atomically. Idempotent: a
    /// second confirmation returns [`PaymentError::AlreadyConfirmed`] and does
    /// not credit again. Returns the new balance.
    pub fn confirm_payment(&self, payment: &PaymentId) -> Result<u64, PaymentOpError> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        let row: Option<(Vec<u8>, i64, i64)> = tx
            .query_row(
                "SELECT account, credits, confirmed FROM payments WHERE payment = ?1",
                params![&payment.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (account, credits, confirmed) =
            row.ok_or(PaymentOpError::Payment(PaymentError::UnknownPayment))?;
        if confirmed != 0 {
            return Err(PaymentOpError::Payment(PaymentError::AlreadyConfirmed));
        }
        let bal: i64 = tx
            .query_row(
                "SELECT balance FROM accounts WHERE account = ?1",
                params![&account[..]],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(PaymentOpError::Payment(PaymentError::Ledger(
                LedgerError::UnknownAccount,
            )))?;
        let new_balance = bal.saturating_add(credits);
        tx.execute(
            "UPDATE accounts SET balance = ?1 WHERE account = ?2",
            params![new_balance, &account[..]],
        )?;
        tx.execute(
            "UPDATE payments SET confirmed = 1 WHERE payment = ?1",
            params![&payment.0[..]],
        )?;
        tx.commit()?;
        Ok(new_balance as u64)
    }
}

/// One tunnel owned by a customer, as shown in the portal listing (#27). Holds
/// **no secret**: the routing token and capability are minted and shown once at
/// creation (a later sub-packet) and never persisted here, so listing a tunnel
/// can never leak credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectTunnel {
    /// Opaque per-tunnel id (not a secret) used to address it for revoke.
    pub id: String,
    /// Customer-chosen display name.
    pub name: String,
    /// Optional Browser-Plane hostname (#23) this tunnel serves.
    pub hostname: Option<String>,
    /// Unix seconds at creation.
    pub created_at: i64,
    /// Hex routing token the tunnel's agent registers under at the edge. Held
    /// **server-side only** — never rendered in a listing — so a revocation can
    /// invalidate the live registration (#27 RB1). It is a routing identifier,
    /// not the Noise capability (which is still never persisted).
    pub routing_token: String,
}

/// Why a tunnel-grant operation failed: the caller is not the tunnel's owner, or
/// the database errored (#29).
#[derive(Debug)]
pub enum GrantError {
    /// The caller does not own the tunnel (or it does not exist) — only the
    /// owner may manage its grants.
    NotOwner,
    /// The underlying database operation failed.
    Db(rusqlite::Error),
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantError::NotOwner => write!(f, "not the tunnel owner"),
            GrantError::Db(e) => write!(f, "storage error: {e}"),
        }
    }
}

impl std::error::Error for GrantError {}

impl From<rusqlite::Error> for GrantError {
    fn from(e: rusqlite::Error) -> Self {
        GrantError::Db(e)
    }
}

/// SQLite-backed per-subject tunnel store (#27): a customer creates, lists and
/// revokes their **own** tunnels. Every operation is scoped by `subject` (from
/// the verified token), so one customer can never see or revoke another's tunnel.
///
/// It also holds per-tunnel access **grants** (#29): the owner shares a tunnel
/// with other subjects, and [`is_authorized`](Self::is_authorized) answers
/// whether a subject may use it.
pub struct SqliteTunnelStore {
    conn: Mutex<Connection>,
}

impl SqliteTunnelStore {
    /// Open (creating if needed) a durable tunnel store at `path`.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open(path)?)
    }

    /// Open an ephemeral in-memory store (for tests / stateless runs).
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS subject_tunnels (
                 id            TEXT PRIMARY KEY,
                 subject       TEXT NOT NULL,
                 name          TEXT NOT NULL,
                 hostname      TEXT,
                 created_at    INTEGER NOT NULL,
                 routing_token TEXT NOT NULL DEFAULT ''
             );
             CREATE INDEX IF NOT EXISTS idx_subject_tunnels_subject
                 ON subject_tunnels (subject);
             CREATE TABLE IF NOT EXISTS tunnel_grants (
                 tunnel_id TEXT NOT NULL,
                 grantee   TEXT NOT NULL,
                 PRIMARY KEY (tunnel_id, grantee)
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create a tunnel owned by `subject`; returns its metadata. A fresh routing
    /// token is minted and persisted server-side so a revocation can later find
    /// and invalidate the tunnel's edge registration (#27 RB1). The `id` is a
    /// random hex string; `created_at` is the current Unix time.
    pub fn create(
        &self,
        subject: &str,
        name: &str,
        hostname: Option<&str>,
    ) -> rusqlite::Result<SubjectTunnel> {
        let mut idb = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut idb);
        let id: String = idb.iter().map(|b| format!("{b:02x}")).collect();
        let mut tokb = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut tokb);
        let routing_token: String = tokb.iter().map(|b| format!("{b:02x}")).collect();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.conn.lock_safe().execute(
            "INSERT INTO subject_tunnels (id, subject, name, hostname, created_at, routing_token)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, subject, name, hostname, created_at, routing_token],
        )?;
        Ok(SubjectTunnel {
            id,
            name: name.to_string(),
            hostname: hostname.map(str::to_string),
            created_at,
            routing_token,
        })
    }

    /// List `subject`'s own tunnels, newest first.
    pub fn list_for_subject(&self, subject: &str) -> rusqlite::Result<Vec<SubjectTunnel>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT id, name, hostname, created_at, routing_token FROM subject_tunnels
             WHERE subject = ?1 ORDER BY created_at DESC, id",
        )?;
        let rows = stmt.query_map(params![subject], |r| {
            Ok(SubjectTunnel {
                id: r.get(0)?,
                name: r.get(1)?,
                hostname: r.get(2)?,
                created_at: r.get(3)?,
                routing_token: r.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Revoke a tunnel by id, but only if it belongs to `subject`. Returns the
    /// removed tunnel's **routing token** (so the caller can invalidate its edge
    /// registration — #27 RB3/RB4), or `None` when the id is unknown or owned by
    /// someone else (no cross-subject deletion). Also clears the tunnel's access
    /// grants (#29) so none are orphaned.
    pub fn revoke(&self, subject: &str, id: &str) -> rusqlite::Result<Option<String>> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
        let token: Option<String> = tx
            .query_row(
                "SELECT routing_token FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![id, subject],
                |r| r.get(0),
            )
            .optional()?;
        if token.is_some() {
            tx.execute(
                "DELETE FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![id, subject],
            )?;
            tx.execute("DELETE FROM tunnel_grants WHERE tunnel_id = ?1", params![id])?;
        }
        tx.commit()?;
        Ok(token)
    }

    /// Whether `subject` is the owner of `tunnel_id` (not merely a grantee).
    /// Used to gate agent onboarding — only the owner installs an agent for a
    /// tunnel (#28).
    pub fn owns(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<bool> {
        Ok(Self::owner_of(&self.conn.lock_safe(), tunnel_id)?.as_deref() == Some(subject))
    }

    /// The routing token of a tunnel the caller owns, or `None` if the id is
    /// unknown or owned by someone else (#27 RB2). Owner-scoped so a non-owner
    /// cannot read another customer's routing token.
    pub fn routing_token(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .lock_safe()
            .query_row(
                "SELECT routing_token FROM subject_tunnels WHERE id = ?1 AND subject = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()
    }

    /// The owner subject of a tunnel, or `None` if the id is unknown.
    fn owner_of(conn: &Connection, tunnel_id: &str) -> rusqlite::Result<Option<String>> {
        conn.query_row(
            "SELECT subject FROM subject_tunnels WHERE id = ?1",
            params![tunnel_id],
            |r| r.get(0),
        )
        .optional()
    }

    /// Grant `grantee` access to a tunnel the caller owns (#29). Idempotent —
    /// re-granting the same subject is a no-op. Fails with
    /// [`GrantError::NotOwner`] unless `owner` actually owns `tunnel_id`.
    pub fn grant(&self, owner: &str, tunnel_id: &str, grantee: &str) -> Result<(), GrantError> {
        let conn = self.conn.lock_safe();
        match Self::owner_of(&conn, tunnel_id)? {
            Some(s) if s == owner => {}
            _ => return Err(GrantError::NotOwner),
        }
        conn.execute(
            "INSERT OR IGNORE INTO tunnel_grants (tunnel_id, grantee) VALUES (?1, ?2)",
            params![tunnel_id, grantee],
        )?;
        Ok(())
    }

    /// Revoke a subject's grant on a tunnel the caller owns. Returns `true` if a
    /// grant was removed. Fails with [`GrantError::NotOwner`] for non-owners.
    pub fn revoke_grant(
        &self,
        owner: &str,
        tunnel_id: &str,
        grantee: &str,
    ) -> Result<bool, GrantError> {
        let conn = self.conn.lock_safe();
        match Self::owner_of(&conn, tunnel_id)? {
            Some(s) if s == owner => {}
            _ => return Err(GrantError::NotOwner),
        }
        let affected = conn.execute(
            "DELETE FROM tunnel_grants WHERE tunnel_id = ?1 AND grantee = ?2",
            params![tunnel_id, grantee],
        )?;
        Ok(affected > 0)
    }

    /// List the subjects granted access to a tunnel the caller owns, sorted.
    /// Fails with [`GrantError::NotOwner`] for non-owners (so a non-owner cannot
    /// even enumerate who a tunnel is shared with).
    pub fn list_grants(&self, owner: &str, tunnel_id: &str) -> Result<Vec<String>, GrantError> {
        let conn = self.conn.lock_safe();
        match Self::owner_of(&conn, tunnel_id)? {
            Some(s) if s == owner => {}
            _ => return Err(GrantError::NotOwner),
        }
        let mut stmt = conn.prepare(
            "SELECT grantee FROM tunnel_grants WHERE tunnel_id = ?1 ORDER BY grantee",
        )?;
        let rows = stmt.query_map(params![tunnel_id], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<Vec<String>>>().map_err(GrantError::Db)
    }

    /// Whether `subject` may use `tunnel_id`: `true` if it is the owner or holds
    /// a grant (#29). This is the authorization gate for capability access to a
    /// shared tunnel — `false` for an unknown tunnel.
    pub fn is_authorized(&self, subject: &str, tunnel_id: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock_safe();
        if Self::owner_of(&conn, tunnel_id)?.as_deref() == Some(subject) {
            return Ok(true);
        }
        let granted: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM tunnel_grants WHERE tunnel_id = ?1 AND grantee = ?2",
                params![tunnel_id, subject],
                |r| r.get(0),
            )
            .optional()?;
        Ok(granted.is_some())
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
    fn subject_tunnel_store_is_self_scoped_for_create_list_revoke() {
        // #27 PP1: a customer creates, lists and revokes only their OWN tunnels.
        let store = SqliteTunnelStore::open_in_memory().unwrap();

        let a1 = store.create("alice", "web", Some("app.example")).unwrap();
        let _a2 = store.create("alice", "ssh", None).unwrap();
        let b1 = store.create("bob", "db", None).unwrap();

        // Listing is scoped to the subject — alice sees her two, bob sees his one.
        let alice = store.list_for_subject("alice").unwrap();
        assert_eq!(alice.len(), 2, "alice sees only her own tunnels");
        assert!(alice.iter().any(|t| t.name == "web" && t.hostname.as_deref() == Some("app.example")));
        assert_eq!(store.list_for_subject("bob").unwrap().len(), 1);

        // Cross-subject revoke is refused: bob cannot delete alice's tunnel.
        assert!(store.revoke("bob", &a1.id).unwrap().is_none(), "no cross-subject revoke");
        assert_eq!(store.list_for_subject("alice").unwrap().len(), 2, "alice's tunnel survives");

        // Owner revoke removes exactly that tunnel and returns its routing token.
        assert_eq!(store.revoke("alice", &a1.id).unwrap(), Some(a1.routing_token.clone()));
        let alice = store.list_for_subject("alice").unwrap();
        assert_eq!(alice.len(), 1);
        assert!(alice.iter().all(|t| t.id != a1.id));

        // Revoking an unknown id is a no-op false; bob's tunnel is untouched.
        assert!(store.revoke("alice", "deadbeef").unwrap().is_none());
        assert_eq!(store.list_for_subject("bob").unwrap(), vec![b1]);
    }

    #[test]
    fn each_tunnel_binds_a_persistent_routing_token_returned_on_revoke() {
        // #27 RB1: creation mints a distinct 32-byte (64-hex) routing token that
        // persists (survives a re-read) and is returned when the tunnel is revoked
        // — the linkage a later cycle uses to invalidate the edge registration.
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        let a = store.create("alice", "web", None).unwrap();
        let b = store.create("alice", "ssh", None).unwrap();
        assert_eq!(a.routing_token.len(), 64, "32-byte hex routing token");
        assert_ne!(a.routing_token, b.routing_token, "distinct per tunnel");

        // The token persists (list re-reads it from the row).
        let listed = store.list_for_subject("alice").unwrap();
        assert!(listed.iter().any(|t| t.routing_token == a.routing_token));

        // Revoke returns exactly that token so the caller can act on it.
        assert_eq!(store.revoke("alice", &a.id).unwrap(), Some(a.routing_token));
        // A second revoke of the same id yields nothing.
        assert_eq!(store.revoke("alice", &a.id).unwrap(), None);
    }

    #[test]
    fn tunnel_grants_are_owner_managed_and_gate_authorization() {
        // #29 PP1: only the owner manages grants; is_authorized = owner or grantee.
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        let t = store.create("alice", "web", None).unwrap();

        // Owner is authorized; strangers are not.
        assert!(store.is_authorized("alice", &t.id).unwrap(), "owner authorized");
        assert!(!store.is_authorized("bob", &t.id).unwrap());
        assert!(!store.is_authorized("bob", "no-such-tunnel").unwrap());

        // Only the owner may grant — bob (a stranger) cannot.
        assert!(matches!(
            store.grant("bob", &t.id, "carol"),
            Err(GrantError::NotOwner)
        ));
        assert!(matches!(
            store.list_grants("bob", &t.id),
            Err(GrantError::NotOwner),
        ), "non-owner cannot even enumerate grants");

        // Owner grants bob -> bob becomes authorized; carol still is not.
        store.grant("alice", &t.id, "bob").unwrap();
        store.grant("alice", &t.id, "bob").unwrap(); // idempotent
        assert!(store.is_authorized("bob", &t.id).unwrap());
        assert!(!store.is_authorized("carol", &t.id).unwrap());
        assert_eq!(store.list_grants("alice", &t.id).unwrap(), vec!["bob".to_string()]);

        // Owner revokes bob's grant -> no longer authorized.
        assert!(store.revoke_grant("alice", &t.id, "bob").unwrap());
        assert!(!store.is_authorized("bob", &t.id).unwrap());
        assert!(!store.revoke_grant("alice", &t.id, "bob").unwrap(), "second revoke is a no-op");

        // Revoking the tunnel clears its grants (no orphans).
        store.grant("alice", &t.id, "bob").unwrap();
        assert!(store.revoke("alice", &t.id).unwrap().is_some());
        assert!(!store.is_authorized("bob", &t.id).unwrap(), "grant gone with the tunnel");
        assert!(!store.is_authorized("alice", &t.id).unwrap(), "owner gone with the tunnel");
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

    fn info() -> TunnelInfo {
        TunnelInfo {
            tenant: TenantId("t".into()),
            agent: AgentId("a".into()),
        }
    }

    #[test]
    fn register_then_lookup() {
        let reg = SqliteRegistry::open_in_memory().unwrap();
        let token = RoutingToken([0x5a; 32]);
        reg.register(&token, &info()).unwrap();
        assert_eq!(reg.lookup(&token).unwrap(), Some(info()));
        assert_eq!(reg.lookup(&RoutingToken([0x11; 32])).unwrap(), None, "unknown token");
    }

    #[test]
    fn unregister_removes_and_reregister_overwrites() {
        let reg = SqliteRegistry::open_in_memory().unwrap();
        let token = RoutingToken([0x5a; 32]);
        reg.register(&token, &info()).unwrap();
        reg.unregister(&token).unwrap();
        assert_eq!(reg.lookup(&token).unwrap(), None);
        reg.unregister(&token).unwrap(); // idempotent

        reg.register(&token, &info()).unwrap();
        let other = TunnelInfo {
            tenant: TenantId("t2".into()),
            agent: AgentId("a2".into()),
        };
        reg.register(&token, &other).unwrap();
        assert_eq!(reg.lookup(&token).unwrap(), Some(other), "re-register overwrites");
    }

    #[test]
    fn registry_state_survives_reopen() {
        let path = temp_db_path();
        let token = RoutingToken([0x7c; 32]);
        {
            let reg = SqliteRegistry::open(&path).unwrap();
            reg.register(&token, &info()).unwrap();
        }
        let reopened = SqliteRegistry::open(&path).unwrap();
        assert_eq!(
            reopened.lookup(&token).unwrap(),
            Some(info()),
            "registration persisted across reopen"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ledger_open_credit_debit() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        assert_eq!(ledger.balance(&acct).unwrap(), 0, "new account starts empty");
        assert_eq!(ledger.credit(&acct, 100).unwrap(), 100);
        assert_eq!(ledger.credit(&acct, 50).unwrap(), 150, "top-ups accumulate");
        assert_eq!(ledger.debit(&acct, 30).unwrap(), 120);
        assert_eq!(ledger.balance(&acct).unwrap(), 120);
    }

    #[test]
    fn debit_beyond_balance_is_refused_without_mutation() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        ledger.credit(&acct, 10).unwrap();
        let refused = ledger.debit(&acct, 25);
        assert!(matches!(
            refused,
            Err(LedgerOpError::Ledger(LedgerError::InsufficientCredit { balance: 10, requested: 25 }))
        ));
        assert_eq!(ledger.balance(&acct).unwrap(), 10, "balance intact");
    }

    #[test]
    fn unknown_account_errors() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let ghost = AccountId([9u8; 32]);
        assert!(matches!(
            ledger.balance(&ghost),
            Err(LedgerOpError::Ledger(LedgerError::UnknownAccount))
        ));
        assert!(matches!(
            ledger.debit(&ghost, 1),
            Err(LedgerOpError::Ledger(LedgerError::UnknownAccount))
        ));
    }

    #[test]
    fn payment_confirmation_is_idempotent() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let acct = ledger.open_account().unwrap();
        let payment = ledger.create_intent(&acct, 100).unwrap();

        assert_eq!(ledger.confirm_payment(&payment).unwrap(), 100);
        assert!(
            matches!(
                ledger.confirm_payment(&payment),
                Err(PaymentOpError::Payment(PaymentError::AlreadyConfirmed))
            ),
            "second confirmation rejected"
        );
        assert_eq!(ledger.balance(&acct).unwrap(), 100, "credited exactly once");
    }

    /// Production requirement: billing state survives a restart. Open + credit +
    /// confirm against a file-backed ledger, drop it, reopen, and confirm the
    /// balance persisted and the payment stays confirmed (no double-credit).
    #[test]
    fn ledger_state_survives_reopen() {
        let path = temp_db_path();
        let acct;
        let payment;
        {
            let ledger = SqliteLedger::open(&path).unwrap();
            acct = ledger.open_account().unwrap();
            ledger.credit(&acct, 5).unwrap();
            payment = ledger.create_intent(&acct, 3).unwrap();
            ledger.confirm_payment(&payment).unwrap(); // balance -> 8
        }
        let reopened = SqliteLedger::open(&path).unwrap();
        assert_eq!(reopened.balance(&acct).unwrap(), 8, "balance persisted across reopen");
        assert!(
            matches!(
                reopened.confirm_payment(&payment),
                Err(PaymentOpError::Payment(PaymentError::AlreadyConfirmed))
            ),
            "payment stays confirmed across reopen (no double-credit)"
        );
        assert_eq!(reopened.balance(&acct).unwrap(), 8, "no double-credit after reopen");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn account_for_subject_is_idempotent() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let a1 = ledger.account_for_subject("keycloak-sub-1").unwrap();
        let a2 = ledger.account_for_subject("keycloak-sub-1").unwrap();
        assert_eq!(a1, a2, "same subject maps to the same account");
        let b = ledger.account_for_subject("keycloak-sub-2").unwrap();
        assert_ne!(a1, b, "distinct subjects get distinct accounts");
        // The bound account is a real, usable account.
        ledger.credit(&a1, 10).unwrap();
        assert_eq!(ledger.balance(&a1).unwrap(), 10);
    }

    #[test]
    fn subject_account_survives_reopen() {
        let path = temp_db_path();
        let acct;
        {
            let ledger = SqliteLedger::open(&path).unwrap();
            acct = ledger.account_for_subject("sub-persist").unwrap();
            ledger.credit(&acct, 7).unwrap();
        }
        let reopened = SqliteLedger::open(&path).unwrap();
        assert_eq!(
            reopened.account_for_subject("sub-persist").unwrap(),
            acct,
            "subject maps to the same account after reopen"
        );
        assert_eq!(reopened.balance(&acct).unwrap(), 7);
        let _ = std::fs::remove_file(&path);
    }
}
