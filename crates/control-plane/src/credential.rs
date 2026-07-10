//! Short-lived credentials (ADR-0005).
//!
//! The control plane mints short-lived, issuer-signed credentials that an Agent
//! presents to the Edge; the Edge verifies the issuer signature and expiry
//! without contacting the control plane. P1.4a is the credential primitive
//! (mint + verify); enrollment-gating and Edge wiring are P1.4b/c.
//!
//! Time is passed in as a caller-supplied Unix timestamp so the library holds no
//! wall-clock and stays deterministic under test.

use ct_common::{AgentId, TenantId};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

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
    fn signing_bytes(&self) -> Vec<u8> {
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

/// Mints signed credentials. The issuer signing key lives only in the control
/// plane; the Edge only needs [`CredentialIssuer::public_key_bytes`].
pub struct CredentialIssuer {
    signing: SigningKey,
}

impl CredentialIssuer {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }

    /// The issuer public key the Edge uses to verify credentials.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Mint a signed credential over `credential`'s claims.
    pub fn mint(&self, credential: Credential) -> SignedCredential {
        let signature = self.signing.sign(&credential.signing_bytes()).to_bytes();
        SignedCredential {
            credential,
            signature,
        }
    }
}

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

    fn cred(expires_at: UnixSeconds) -> Credential {
        Credential {
            tenant: TenantId("tenant-1".into()),
            agent: AgentId("agent-1".into()),
            expires_at,
        }
    }

    #[test]
    fn mint_then_verify_ok_before_expiry() {
        let issuer = CredentialIssuer::generate();
        let signed = issuer.mint(cred(1_000));
        assert_eq!(verify(&issuer.public_key_bytes(), &signed, 999), Ok(()));
    }

    #[test]
    fn expired_credential_rejected() {
        let issuer = CredentialIssuer::generate();
        let signed = issuer.mint(cred(1_000));
        assert_eq!(
            verify(&issuer.public_key_bytes(), &signed, 1_000),
            Err(CredError::Expired)
        );
    }

    #[test]
    fn wrong_issuer_rejected() {
        let issuer = CredentialIssuer::generate();
        let other = CredentialIssuer::generate();
        let signed = issuer.mint(cred(1_000));
        assert_eq!(
            verify(&other.public_key_bytes(), &signed, 500),
            Err(CredError::BadSignature)
        );
    }

    #[test]
    fn tampered_claims_rejected() {
        let issuer = CredentialIssuer::generate();
        let mut signed = issuer.mint(cred(1_000));
        signed.credential.expires_at = 9_999; // extend lifetime after signing
        assert_eq!(
            verify(&issuer.public_key_bytes(), &signed, 500),
            Err(CredError::BadSignature)
        );
    }
}
