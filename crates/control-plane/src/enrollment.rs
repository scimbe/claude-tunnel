//! Agent enrollment (ADR-0005).
//!
//! Issue single-use join tokens; redeeming one binds an Agent's public key to
//! its Tenant. In-memory service; the wire API and persistence are later
//! packets. The service never holds any Agent private key — only the public
//! key an Agent presents at redemption (P1.3a).

use std::collections::HashMap;

use ct_common::{AgentId, TenantId};
use rand::RngCore;

/// An Agent's public identity key (ed25519 verifying-key bytes).
pub type AgentPublicKey = [u8; 32];

/// A single-use join token that bootstraps one Agent's enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinToken(pub [u8; 32]);

/// Why a redemption was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum EnrollError {
    /// The token was never issued (or already forgotten).
    UnknownToken,
    /// The token was already redeemed once; join tokens are single-use.
    TokenAlreadyUsed,
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollError::UnknownToken => write!(f, "unknown join token"),
            EnrollError::TokenAlreadyUsed => write!(f, "join token already used"),
        }
    }
}

impl std::error::Error for EnrollError {}

/// In-memory enrollment service.
#[derive(Default)]
pub struct Enrollment {
    /// token bytes -> (owning tenant, consumed?)
    tokens: HashMap<[u8; 32], (TenantId, bool)>,
    /// agent -> (tenant, bound public key)
    bindings: HashMap<AgentId, (TenantId, AgentPublicKey)>,
}

impl Enrollment {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a fresh single-use join token for `tenant`.
    pub fn issue_join_token(&mut self, tenant: TenantId) -> JoinToken {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        self.tokens.insert(bytes, (tenant, false));
        JoinToken(bytes)
    }

    /// Redeem a join token, binding `agent`'s public key to the token's tenant.
    /// The token is consumed; a second redemption is rejected.
    pub fn redeem(
        &mut self,
        token: &JoinToken,
        agent: AgentId,
        pubkey: AgentPublicKey,
    ) -> Result<TenantId, EnrollError> {
        let entry = self
            .tokens
            .get_mut(&token.0)
            .ok_or(EnrollError::UnknownToken)?;
        if entry.1 {
            return Err(EnrollError::TokenAlreadyUsed);
        }
        entry.1 = true;
        let tenant = entry.0.clone();
        self.bindings.insert(agent, (tenant.clone(), pubkey));
        Ok(tenant)
    }

    /// The binding recorded for `agent`, if enrolled.
    pub fn binding(&self, agent: &AgentId) -> Option<&(TenantId, AgentPublicKey)> {
        self.bindings.get(agent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantId {
        TenantId("tenant-1".into())
    }

    #[test]
    fn issue_then_redeem_binds_public_key() {
        let mut e = Enrollment::new();
        let token = e.issue_join_token(tenant());
        let agent = AgentId("agent-1".into());
        let pubkey = [7u8; 32];

        let bound_tenant = e.redeem(&token, agent.clone(), pubkey).expect("redeem");
        assert_eq!(bound_tenant, tenant());
        assert_eq!(e.binding(&agent), Some(&(tenant(), pubkey)));
    }

    #[test]
    fn join_token_is_single_use() {
        let mut e = Enrollment::new();
        let token = e.issue_join_token(tenant());
        e.redeem(&token, AgentId("a1".into()), [1u8; 32])
            .expect("first redeem");
        let second = e.redeem(&token, AgentId("a2".into()), [2u8; 32]);
        assert_eq!(second, Err(EnrollError::TokenAlreadyUsed));
    }

    #[test]
    fn unknown_token_is_rejected() {
        let mut e = Enrollment::new();
        let bogus = JoinToken([0u8; 32]);
        let result = e.redeem(&bogus, AgentId("a1".into()), [3u8; 32]);
        assert_eq!(result, Err(EnrollError::UnknownToken));
    }
}
