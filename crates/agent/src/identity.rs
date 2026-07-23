//! Agent identity (ADR-0005).
//!
//! The Agent generates an ed25519 identity keypair at enrollment. Only the
//! public key ever leaves the Agent (it is bound to the Tenant by the control
//! plane); the signing key is held privately and exposed by no accessor.

use ed25519_dalek::{Signature, Signer, SigningKey};
use std::io;
use std::path::Path;

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

    /// Persist the signing key to `path` as its raw 32 secret bytes, owner-only
    /// (`0600`) on Unix. This is the one seam that touches the secret — it is
    /// written to disk but never RETURNED, so the "exposed by no accessor"
    /// invariant holds. Enables restart-safe onboarding (#141): the identity that
    /// redeemed the single-use join token is reloaded on restart instead of
    /// re-redeeming a spent token.
    pub fn save_secret_to(&self, path: &Path) -> io::Result<()> {
        std::fs::write(path, self.signing.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Reload an identity previously written by [`save_secret_to`]. Rejects any
    /// file that is not exactly 32 bytes.
    pub fn load_secret_from(path: &Path) -> io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "identity key must be exactly 32 bytes")
        })?;
        Ok(Self {
            signing: SigningKey::from_bytes(&arr),
        })
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
    fn save_and_reload_round_trips_the_same_signing_key() {
        // #141 restart-safety: the persisted identity reloads to the SAME keypair,
        // so a restart presents the key the control plane already bound — no
        // re-redeem of the spent single-use join token.
        let id = AgentIdentity::generate();
        let dir = std::env::temp_dir().join(format!("ct-identity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.key");
        id.save_secret_to(&path).expect("save");
        let reloaded = AgentIdentity::load_secret_from(&path).expect("reload");
        assert_eq!(
            reloaded.public_key_bytes(),
            id.public_key_bytes(),
            "reloaded identity is the same keypair"
        );
        // And it still signs as the same key (the private half survived, not just the public).
        let msg = b"post-restart proof-of-possession";
        let vk = VerifyingKey::from_bytes(&id.public_key_bytes()).unwrap();
        assert!(vk.verify(msg, &reloaded.sign(msg)).is_ok(), "reloaded key signs verifiably");
        assert!(
            AgentIdentity::load_secret_from(&dir.join("nope.key")).is_err(),
            "a missing key file is an error, not a silent fresh identity"
        );
        let _ = std::fs::remove_dir_all(&dir);
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
