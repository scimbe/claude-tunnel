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
    let tenant = cp
        .redeem(join_token, &agent_id, &identity.public_key_bytes())
        .await?;
    Ok(OnboardedAgent {
        identity,
        agent_id,
        tenant,
        config,
    })
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
