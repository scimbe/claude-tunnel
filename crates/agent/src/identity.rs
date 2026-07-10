//! Agent identity (ADR-0005).
//!
//! The Agent generates an ed25519 identity keypair at enrollment. Only the
//! public key ever leaves the Agent (it is bound to the Tenant by the control
//! plane); the signing key is held privately and exposed by no accessor.

use ed25519_dalek::{Signature, Signer, SigningKey};

/// An Agent's identity keypair. The signing (private) key never leaves the Agent.
pub struct AgentIdentity {
    signing: SigningKey,
}

impl AgentIdentity {
    /// Generate a fresh random identity keypair.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }

    /// The public identity key (ed25519 verifying-key bytes) to present at
    /// enrollment.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign `message` with the identity key (proof of possession; used by the
    /// short-lived-credential flow in P1.4).
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    #[test]
    fn generate_produces_distinct_32_byte_public_keys() {
        let a = AgentIdentity::generate();
        let b = AgentIdentity::generate();
        assert_eq!(a.public_key_bytes().len(), 32);
        assert_ne!(
            a.public_key_bytes(),
            b.public_key_bytes(),
            "fresh identities must differ"
        );
    }

    #[test]
    fn signature_verifies_against_public_key() {
        let id = AgentIdentity::generate();
        let msg = b"proof-of-possession";
        let sig = id.sign(msg);
        let vk = VerifyingKey::from_bytes(&id.public_key_bytes()).expect("valid key");
        assert!(vk.verify(msg, &sig).is_ok(), "signature must verify");
    }

    #[test]
    fn enroll_binds_agent_identity() {
        use ct_common::{AgentId, TenantId};
        use ct_control_plane::enrollment::Enrollment;

        let mut enrollment = Enrollment::new();
        let tenant = TenantId("tenant-1".into());
        let token = enrollment.issue_join_token(tenant.clone());

        let identity = AgentIdentity::generate();
        let agent = AgentId("agent-1".into());
        let pubkey = identity.public_key_bytes();

        let bound = enrollment
            .redeem(&token, agent.clone(), pubkey)
            .expect("redeem");
        assert_eq!(bound, tenant);
        assert_eq!(enrollment.binding(&agent), Some(&(tenant, pubkey)));
    }
}
