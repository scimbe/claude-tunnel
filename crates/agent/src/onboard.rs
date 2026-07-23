//! One-command onboarding (M22.1).
//!
//! Collapses the manual agent bring-up into a single call. Bringing an agent
//! online used to mean, by hand: generate an identity keypair, learn your agent
//! id, redeem a join token to bind the key to the tenant, then assemble a
//! runnable config. [`onboard`] does all of that from just a control-plane URL
//! and a single-use join token — the fewest steps possible for the operator
//! (the user's "easy setup, as few steps as possible" requirement).
//!
//! The join token is the only secret the operator handles; the identity keypair
//! is generated locally and only its public key ever leaves the agent (bound to
//! the tenant by the control plane). The data path is unchanged — onboarding is
//! identity/enrollment only, never payload access.

use crate::config::AgentConfig;
use crate::identity::AgentIdentity;
use ct_common::{AgentId, TenantId};
use ct_control_plane::client::{ControlPlaneClient, CpError};
use std::path::Path;

/// Decode exactly 64 lowercase/uppercase hex chars into 32 bytes.
fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Inputs for one-command onboarding, gathered so the agent can be brought up
/// with a single command plus a join token. [`OnboardEnv::from_env`] reads them
/// from the environment; [`OnboardEnv::parse`] builds them from explicit
/// strings (used by the binary's dispatch and by tests).
pub struct OnboardEnv {
    /// Control-plane base URL to enroll against.
    pub cp_url: String,
    /// Single-use join token (decoded from hex).
    pub join_token: [u8; 32],
    /// Agent id to enroll under.
    pub agent_id: AgentId,
    /// Runnable edge/origin config for the serve path.
    pub config: AgentConfig,
}

impl OnboardEnv {
    /// Build onboarding inputs from explicit strings, validating each field:
    /// a non-empty control-plane URL, a 64-char hex join token, a non-empty
    /// agent id, and a parseable edge/origin config.
    pub fn parse(
        cp_url: &str,
        join_token_hex: &str,
        agent_id: &str,
        config: AgentConfig,
    ) -> Result<OnboardEnv, String> {
        let cp_url = cp_url.trim();
        if cp_url.is_empty() {
            return Err("CT_AGENT_CP_URL must not be empty".to_string());
        }
        let join_token = hex_decode_32(join_token_hex)
            .ok_or_else(|| "CT_AGENT_JOIN_TOKEN must be 64 hex chars (32 bytes)".to_string())?;
        let agent_id = agent_id.trim();
        if agent_id.is_empty() {
            return Err("CT_AGENT_ID must not be empty".to_string());
        }
        Ok(OnboardEnv {
            cp_url: cp_url.to_string(),
            join_token,
            agent_id: AgentId(agent_id.to_string()),
            config,
        })
    }

    /// Read onboarding inputs from the environment:
    /// `CT_AGENT_CP_URL`, `CT_AGENT_JOIN_TOKEN` (hex), `CT_AGENT_ID`, plus the
    /// usual edge/origin variables consumed by [`AgentConfig::from_env`].
    pub fn from_env() -> Result<OnboardEnv, String> {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    /// Read onboarding inputs from a variable lookup (`from_env` passes
    /// `std::env::var`). Split out so the required-var branches — and the
    /// delegated [`AgentConfig::from_env_with`] — are testable without mutating
    /// the global process environment.
    pub(crate) fn from_env_with(
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<OnboardEnv, String> {
        let cp_url = get("CT_AGENT_CP_URL")
            .ok_or_else(|| "CT_AGENT_CP_URL is required for onboarding".to_string())?;
        let token = get("CT_AGENT_JOIN_TOKEN")
            .ok_or_else(|| "CT_AGENT_JOIN_TOKEN is required for onboarding".to_string())?;
        let agent_id = get("CT_AGENT_ID")
            .ok_or_else(|| "CT_AGENT_ID is required for onboarding".to_string())?;
        let config = AgentConfig::from_env_with(&get)?;
        Self::parse(&cp_url, &token, &agent_id, config)
    }

    /// Onboard using these inputs (generate identity, redeem the token, bind).
    pub async fn onboard(self) -> Result<OnboardedAgent, CpError> {
        onboard(&self.cp_url, &self.join_token, self.agent_id, self.config).await
    }
}

/// A fully onboarded agent: a fresh identity bound to its tenant plus a
/// ready-to-serve [`AgentConfig`]. The caller hands these to the serve path to
/// run the tunnel; no further enrollment step is required.
pub struct OnboardedAgent {
    /// The freshly generated identity keypair (private key never leaves here).
    pub identity: AgentIdentity,
    /// The agent id this identity was enrolled under.
    pub agent_id: AgentId,
    /// The tenant the control plane bound the identity to.
    pub tenant: TenantId,
    /// A runnable configuration (edge/origin) for the serve path.
    pub config: AgentConfig,
}

/// Onboard in one step.
///
/// Generates a fresh identity, redeems `join_token` against the control plane at
/// `cp_url` — which binds the new public key to the token's tenant — and returns
/// a runnable [`OnboardedAgent`]. The join token is single-use: a second call
/// with the same token is rejected by the control plane and surfaces as an
/// error here.
pub async fn onboard(
    cp_url: &str,
    join_token: &[u8; 32],
    agent_id: AgentId,
    config: AgentConfig,
) -> Result<OnboardedAgent, CpError> {
    let identity = AgentIdentity::generate();
    let cp = ControlPlaneClient::new(cp_url);
    // #88 SEC88c: prove possession of the identity key being bound by signing the
    // join token, so the control plane won't bind a key we don't control.
    let proof = identity.sign(join_token).to_bytes();
    let tenant = cp
        .redeem(join_token, &agent_id, &identity.public_key_bytes(), &proof)
        .await?;
    Ok(OnboardedAgent {
        identity,
        agent_id,
        tenant,
        config,
    })
}

/// Failure onboarding-or-restoring: either the control-plane redeem failed
/// ([`CpError`]) or persisting/restoring the local onboarding state failed
/// (I/O). Kept distinct so the caller can tell "the CP rejected us" from "the
/// state directory is unwritable".
#[derive(Debug)]
pub enum OnboardError {
    /// The control-plane enrollment call failed (e.g. a spent join token).
    Cp(CpError),
    /// Reading/writing the persisted onboarding state failed.
    Io(std::io::Error),
}

impl std::fmt::Display for OnboardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OnboardError::Cp(e) => write!(f, "control-plane onboarding failed: {e}"),
            OnboardError::Io(e) => write!(f, "onboarding-state I/O failed: {e}"),
        }
    }
}

impl std::error::Error for OnboardError {}

impl From<CpError> for OnboardError {
    fn from(e: CpError) -> Self {
        OnboardError::Cp(e)
    }
}

impl From<std::io::Error> for OnboardError {
    fn from(e: std::io::Error) -> Self {
        OnboardError::Io(e)
    }
}

impl OnboardedAgent {
    /// File names under the state directory. Kept separate (not one delimited
    /// record) so operator-supplied `agent_id`/`tenant` strings need no escaping.
    const IDENTITY_FILE: &'static str = "identity.key";
    const AGENT_FILE: &'static str = "agent";
    const TENANT_FILE: &'static str = "tenant";

    /// Persist just enough to resume WITHOUT re-enrolling: the identity keypair
    /// the control plane bound, the agent id it was bound under, and the tenant it
    /// was bound to. Writes into `state_dir` (created if absent). The single-use
    /// join token is deliberately NOT stored — it is spent and must never be
    /// replayed (#141).
    pub fn persist(&self, state_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(state_dir)?;
        self.identity.save_secret_to(&state_dir.join(Self::IDENTITY_FILE))?;
        std::fs::write(state_dir.join(Self::AGENT_FILE), &self.agent_id.0)?;
        std::fs::write(state_dir.join(Self::TENANT_FILE), &self.tenant.0)?;
        Ok(())
    }

    /// Restore the bound identity + tenant from `state_dir`, if a prior onboarding
    /// for THIS `agent_id` is persisted there. Returns `Ok(None)` when there is no
    /// persisted identity yet (first boot) or it was written for a different agent
    /// id (stale/foreign state — fall back to a fresh enrollment). Only the
    /// identity + tenant are returned; the caller pairs them with its live config.
    fn restore(state_dir: &Path, agent_id: &AgentId) -> std::io::Result<Option<(AgentIdentity, TenantId)>> {
        let key_path = state_dir.join(Self::IDENTITY_FILE);
        if !key_path.exists() {
            return Ok(None);
        }
        let persisted_agent = std::fs::read_to_string(state_dir.join(Self::AGENT_FILE))?;
        if persisted_agent != agent_id.0 {
            return Ok(None);
        }
        let identity = AgentIdentity::load_secret_from(&key_path)?;
        let tenant = TenantId(std::fs::read_to_string(state_dir.join(Self::TENANT_FILE))?);
        Ok(Some((identity, tenant)))
    }
}

/// Restart-safe onboarding (#141). On first boot this redeems the single-use
/// join token like [`onboard`] and persists the bound identity/tenant under
/// `state_dir`; on every subsequent boot it RESTORES that persisted state and
/// serves without touching the control plane — so a container restart never
/// replays the spent token into a crash-loop. A `state_dir` with no persisted
/// identity (or one written for a different agent id) falls back to a fresh
/// enrollment.
pub async fn onboard_or_restore(
    cp_url: &str,
    join_token: &[u8; 32],
    agent_id: AgentId,
    config: AgentConfig,
    state_dir: &Path,
) -> Result<OnboardedAgent, OnboardError> {
    if let Some((identity, tenant)) = OnboardedAgent::restore(state_dir, &agent_id)? {
        return Ok(OnboardedAgent {
            identity,
            agent_id,
            tenant,
            config,
        });
    }
    let onboarded = onboard(cp_url, join_token, agent_id, config).await?;
    onboarded.persist(state_dir)?;
    Ok(onboarded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_control_plane::service::enrollment_router_sqlite;
    use ct_control_plane::storage::SqliteEnrollment;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    /// Serve an enrollment router backed by `store` on an ephemeral port and
    /// return its base URL.
    async fn serve(store: Arc<SqliteEnrollment>) -> String {
        let app = enrollment_router_sqlite(store);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn onboard_enrolls_and_binds_a_fresh_identity() {
        let store = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let tenant = TenantId("tenant-1".into());
        let token = store.issue_join_token(&tenant).unwrap();
        let url = serve(store.clone()).await;

        let cfg = AgentConfig::parse("127.0.0.1:4433", "127.0.0.1:8080").unwrap();
        let agent_id = AgentId("agent-1".into());
        let onboarded = onboard(&url, &token.0, agent_id.clone(), cfg.clone())
            .await
            .expect("one-command onboard succeeds");

        // The control plane bound us to the token's tenant, and the runnable
        // config came straight back for the serve path.
        assert_eq!(onboarded.tenant, tenant);
        assert_eq!(onboarded.config, cfg);

        // The freshly generated public key is what got bound in the store.
        assert_eq!(
            store.binding(&agent_id).unwrap(),
            Some((tenant, onboarded.identity.public_key_bytes())),
            "the generated identity is bound to the agent id"
        );
    }

    #[tokio::test]
    async fn onboard_or_restore_is_restart_safe_and_never_replays_the_spent_token() {
        // #141: the help-agent crash-looped because every container restart re-redeemed
        // a single-use join token. onboard_or_restore fixes it: first boot redeems +
        // persists; a restart RESTORES the bound identity/tenant and never touches the CP.
        let store = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let tenant = TenantId("tenant-help".into());
        let token = store.issue_join_token(&tenant).unwrap();
        let url = serve(store.clone()).await;
        let cfg = AgentConfig::parse("127.0.0.1:4433", "127.0.0.1:8080").unwrap();
        let agent_id = AgentId("help-agent".into());
        let dir = std::env::temp_dir().join(format!("ct-onboard-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // First boot: redeems the single-use token and persists the binding.
        let first = onboard_or_restore(&url, &token.0, agent_id.clone(), cfg.clone(), &dir)
            .await
            .expect("first boot onboards");
        let bound_pk = first.identity.public_key_bytes();
        assert_eq!(first.tenant, tenant);

        // Restart with the SAME (now-spent) token: must RESTORE from disk, not re-redeem.
        let restart = onboard_or_restore(&url, &token.0, agent_id.clone(), cfg.clone(), &dir)
            .await
            .expect("restart restores without re-redeeming the spent token");
        assert_eq!(restart.identity.public_key_bytes(), bound_pk, "same bound identity after restart");
        assert_eq!(restart.tenant, tenant, "same tenant binding after restart");
        assert_eq!(restart.config, cfg, "the live config is paired back in on restore");

        // Proof this is what saved us: a plain re-onboard with the spent token DOES fail —
        // exactly the crash the persistence sidesteps.
        let replay = onboard(&url, &token.0, agent_id.clone(), cfg.clone()).await;
        assert!(replay.is_err(), "re-redeeming a spent single-use token fails (#141 crash-loop)");

        // Foreign/stale state (different agent id) falls back to a fresh enrollment, not a restore.
        assert!(
            OnboardedAgent::restore(&dir, &AgentId("other-agent".into())).unwrap().is_none(),
            "persisted state for one agent id is not restored for another"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_accepts_valid_inputs_and_decodes_the_hex_token() {
        let token_hex = "aa".repeat(32); // 64 hex chars -> 32 bytes of 0xaa
        let cfg = AgentConfig::parse("127.0.0.1:4433", "127.0.0.1:8080").unwrap();
        let env = OnboardEnv::parse("http://cp:8090/", &token_hex, "agent-1", cfg.clone())
            .expect("valid onboarding inputs parse");
        assert_eq!(env.cp_url, "http://cp:8090/");
        assert_eq!(env.join_token, [0xaa; 32]);
        assert_eq!(env.agent_id, AgentId("agent-1".into()));
        assert_eq!(env.config, cfg);
    }

    // #20 TC2: cover OnboardEnv::from_env via the from_env_with getter seam.
    fn getter<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn onboard_from_env_reads_required_vars_and_delegates_config() {
        let hex = "aa".repeat(32);
        let env = OnboardEnv::from_env_with(getter(&[
            ("CT_AGENT_CP_URL", "http://cp:8090"),
            ("CT_AGENT_JOIN_TOKEN", hex.as_str()),
            ("CT_AGENT_ID", "agent-1"),
            ("CT_AGENT_ORIGIN_PROTO", "udp"),
        ]))
        .unwrap();
        assert_eq!(env.cp_url, "http://cp:8090");
        assert_eq!(env.join_token, [0xaa; 32]);
        assert_eq!(env.agent_id, AgentId("agent-1".into()));
        // The edge/origin config is parsed via the same getter (defaults here),
        // and CT_AGENT_ORIGIN_PROTO flows through to the delegated config.
        assert_eq!(env.config.edge, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(env.config.origin_proto, crate::config::OriginProto::Udp);
    }

    #[test]
    fn onboard_from_env_requires_each_var() {
        let hex = "bb".repeat(32);
        let full = [
            ("CT_AGENT_CP_URL", "http://cp:8090"),
            ("CT_AGENT_JOIN_TOKEN", hex.as_str()),
            ("CT_AGENT_ID", "a"),
        ];
        for missing in ["CT_AGENT_CP_URL", "CT_AGENT_JOIN_TOKEN", "CT_AGENT_ID"] {
            let subset: Vec<(&str, &str)> =
                full.iter().copied().filter(|(k, _)| *k != missing).collect();
            let err = OnboardEnv::from_env_with(getter(&subset))
                .err()
                .expect("a missing required var must error");
            assert!(err.contains(missing), "missing {missing}: {err}");
        }
    }

    #[test]
    fn from_env_wrapper_surfaces_a_missing_required_var() {
        // Exercise the thin from_env() wrapper against the real environment; no
        // test sets CT_AGENT_CP_URL, so it must surface the required-var error.
        let err = OnboardEnv::from_env()
            .err()
            .expect("missing CT_AGENT_CP_URL must error");
        assert!(err.contains("CT_AGENT_CP_URL"), "{err}");
    }

    #[test]
    fn parse_rejects_bad_inputs() {
        let cfg = AgentConfig::parse("127.0.0.1:4433", "127.0.0.1:8080").unwrap();
        let good = "aa".repeat(32);
        // empty control-plane URL
        assert!(OnboardEnv::parse("", &good, "agent-1", cfg.clone()).is_err());
        // token too short
        assert!(OnboardEnv::parse("http://cp", "aabb", "agent-1", cfg.clone()).is_err());
        // token not hex
        assert!(OnboardEnv::parse("http://cp", &"zz".repeat(32), "agent-1", cfg.clone()).is_err());
        // empty agent id
        assert!(OnboardEnv::parse("http://cp", &good, "  ", cfg).is_err());
    }

    #[tokio::test]
    async fn onboard_env_drives_the_full_flow() {
        let store = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let tenant = TenantId("tenant-1".into());
        let token = store.issue_join_token(&tenant).unwrap();
        let url = serve(store.clone()).await;
        let token_hex: String = token.0.iter().map(|b| format!("{b:02x}")).collect();
        let cfg = AgentConfig::parse("127.0.0.1:4433", "127.0.0.1:8080").unwrap();

        let env = OnboardEnv::parse(&url, &token_hex, "agent-1", cfg).expect("parse");
        let onboarded = env.onboard().await.expect("onboard from env inputs");

        assert_eq!(onboarded.tenant, tenant);
        assert_eq!(
            store.binding(&AgentId("agent-1".into())).unwrap(),
            Some((tenant, onboarded.identity.public_key_bytes()))
        );
    }

    #[tokio::test]
    async fn join_token_is_single_use() {
        let store = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let tenant = TenantId("tenant-1".into());
        let token = store.issue_join_token(&tenant).unwrap();
        let url = serve(store).await;
        let cfg = AgentConfig::parse("127.0.0.1:4433", "127.0.0.1:8080").unwrap();

        onboard(&url, &token.0, AgentId("agent-1".into()), cfg.clone())
            .await
            .expect("first onboard consumes the token");

        let second = onboard(&url, &token.0, AgentId("agent-2".into()), cfg).await;
        assert!(second.is_err(), "a single-use join token cannot be reused");
    }
}
