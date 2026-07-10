//! Edge-side credential verification (ADR-0005).
//!
//! The Edge trusts the control plane's issuer public key and verifies presented
//! credentials statelessly — without contacting the control plane. P1.4c.

use ct_common::credential::{verify, CredError, SignedCredential, UnixSeconds};
use quinn::{Connection, Endpoint};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Verify a credential an Agent presents, against the trusted `issuer_pubkey`
/// at time `now`.
pub fn verify_presented_credential(
    issuer_pubkey: &[u8; 32],
    presented: &SignedCredential,
    now: UnixSeconds,
) -> Result<(), CredError> {
    verify(issuer_pubkey, presented, now)
}

/// Accept one connection, read the credential the Agent presents on a
/// bidirectional stream, verify it against `issuer_pubkey` at `now`, and reply
/// `OK`/`NO`. Returns the authenticated connection on success.
pub async fn accept_and_authenticate(
    endpoint: &Endpoint,
    issuer_pubkey: &[u8; 32],
    now: UnixSeconds,
) -> Result<Connection, BoxError> {
    let incoming = endpoint
        .accept()
        .await
        .ok_or("endpoint closed with no incoming")?;
    let conn = incoming.await?;
    let (mut send, mut recv) = conn.accept_bi().await?;
    let bytes = recv.read_to_end(64 * 1024).await?;
    let signed = SignedCredential::decode(&bytes)?;
    match verify(issuer_pubkey, &signed, now) {
        Ok(()) => {
            send.write_all(b"OK").await?;
            send.finish()?;
            Ok(conn)
        }
        Err(e) => {
            let _ = send.write_all(b"NO").await;
            let _ = send.finish();
            Err(Box::new(e))
        }
    }
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
