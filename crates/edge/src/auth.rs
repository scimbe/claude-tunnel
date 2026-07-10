//! Edge-side credential verification (ADR-0005).
//!
//! The Edge trusts the control plane's issuer public key and verifies presented
//! credentials statelessly — without contacting the control plane. P1.4c.

use ct_common::credential::{verify, CredError, SignedCredential, UnixSeconds};

/// Verify a credential an Agent presents, against the trusted `issuer_pubkey`
/// at time `now`.
pub fn verify_presented_credential(
    issuer_pubkey: &[u8; 32],
    presented: &SignedCredential,
    now: UnixSeconds,
) -> Result<(), CredError> {
    verify(issuer_pubkey, presented, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::{AgentId, TenantId};
    use ct_control_plane::credential::{Credential, CredentialIssuer};

    #[test]
    fn edge_accepts_valid_and_rejects_expired() {
        let issuer = CredentialIssuer::generate();
        let signed = issuer.mint(Credential {
            tenant: TenantId("tenant-1".into()),
            agent: AgentId("agent-1".into()),
            expires_at: 1_000,
        });

        assert_eq!(
            verify_presented_credential(&issuer.public_key_bytes(), &signed, 500),
            Ok(())
        );
        assert_eq!(
            verify_presented_credential(&issuer.public_key_bytes(), &signed, 1_000),
            Err(CredError::Expired)
        );
    }
}
