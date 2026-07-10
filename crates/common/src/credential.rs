//! Short-lived credential wire type and verification (ADR-0005).
//!
//! Shared by the control plane (which mints via its `CredentialIssuer`) and the
//! Edge (which verifies presented credentials). The issuer signing key lives
//! only in the control plane; this module holds the claims, the wire form, and
//! the stateless verification. Time is caller-supplied so this stays
//! deterministic and wall-clock-free.

use crate::{AgentId, TenantId};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Unix timestamp in whole seconds, supplied by the caller.
pub type UnixSeconds = u64;

/// The claims of a short-lived credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub tenant: TenantId,
    pub agent: AgentId,
    pub expires_at: UnixSeconds,
}

impl Credential {
    /// Canonical bytes covered by the issuer signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "ct-cred:v1|{}|{}|{}",
            self.tenant.0, self.agent.0, self.expires_at
        )
        .into_bytes()
    }
}

/// A credential together with the issuer's signature over its claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCredential {
    pub credential: Credential,
    pub signature: [u8; 64],
}

/// Why credential verification failed.
#[derive(Debug, PartialEq, Eq)]
pub enum CredError {
    BadSignature,
    Expired,
    BadKey,
}

impl std::fmt::Display for CredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredError::BadSignature => write!(f, "credential signature invalid"),
            CredError::Expired => write!(f, "credential expired"),
            CredError::BadKey => write!(f, "issuer public key invalid"),
        }
    }
}

impl std::error::Error for CredError {}

/// Verify a signed credential against `issuer_pubkey` at time `now`.
pub fn verify(
    issuer_pubkey: &[u8; 32],
    signed: &SignedCredential,
    now: UnixSeconds,
) -> Result<(), CredError> {
    let vk = VerifyingKey::from_bytes(issuer_pubkey).map_err(|_| CredError::BadKey)?;
    let sig = Signature::from_bytes(&signed.signature);
    vk.verify(&signed.credential.signing_bytes(), &sig)
        .map_err(|_| CredError::BadSignature)?;
    if now >= signed.credential.expires_at {
        return Err(CredError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Sign a credential with a deterministic key (no rng needed in tests).
    fn signed_cred(expires_at: UnixSeconds) -> ([u8; 32], SignedCredential) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let credential = Credential {
            tenant: TenantId("tenant-1".into()),
            agent: AgentId("agent-1".into()),
            expires_at,
        };
        let signature = sk.sign(&credential.signing_bytes()).to_bytes();
        (
            sk.verifying_key().to_bytes(),
            SignedCredential {
                credential,
                signature,
            },
        )
    }

    #[test]
    fn verify_ok_before_expiry() {
        let (pk, signed) = signed_cred(1_000);
        assert_eq!(verify(&pk, &signed, 999), Ok(()));
    }

    #[test]
    fn verify_rejects_expired() {
        let (pk, signed) = signed_cred(1_000);
        assert_eq!(verify(&pk, &signed, 1_000), Err(CredError::Expired));
    }

    #[test]
    fn verify_rejects_tampered_claims() {
        let (pk, mut signed) = signed_cred(1_000);
        signed.credential.expires_at = 9_999;
        assert_eq!(verify(&pk, &signed, 500), Err(CredError::BadSignature));
    }
}
