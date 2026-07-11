//! Origin Noise static key (ADR-0013, M8.1).
//!
//! The Agent is custodian of the Origin's static Noise keypair. Only the public
//! half — the Origin Identity — leaves the Agent (carried in the Capability the
//! customer distributes out of band); the private half stays in this process and
//! is used to terminate the Client↔Origin Noise handshake on the Origin's
//! behalf (M8.3).

use ct_common::noise::{generate_static_keypair, StaticKeypair};
use ct_common::OriginIdentity;

/// The Origin's static Noise keypair, held by the Agent.
pub struct OriginKey {
    keypair: StaticKeypair,
}

impl OriginKey {
    /// Generate a fresh Origin static keypair.
    pub fn generate() -> Self {
        Self {
            keypair: generate_static_keypair(),
        }
    }

    /// The Origin Identity (public key) to embed in a Capability for Clients to
    /// pin.
    pub fn origin_identity(&self) -> OriginIdentity {
        self.keypair.origin_identity()
    }

    /// The private key, used to build the responder (Origin) Noise handshake.
    /// Never leaves the Agent process.
    pub fn private_bytes(&self) -> [u8; 32] {
        self.keypair.private
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::mint_capability;
    use ct_common::noise::{client_handshake_for, generate_static_keypair, origin_handshake};

    #[test]
    fn generate_produces_distinct_32_byte_identities() {
        let a = OriginKey::generate();
        let b = OriginKey::generate();
        assert_eq!(a.origin_identity().0.len(), 32);
        assert_ne!(
            a.origin_identity(),
            b.origin_identity(),
            "fresh Origin keys must differ"
        );
    }

    #[test]
    fn capability_carries_the_origin_identity() {
        let key = OriginKey::generate();
        let cap = mint_capability(key.origin_identity(), "edge:443".into());
        assert_eq!(cap.origin, key.origin_identity());
    }

    #[test]
    fn minted_identity_and_retained_private_complete_a_handshake() {
        // The public Origin Identity placed in the Capability and the private
        // key kept by the Agent must be a consistent Noise pair: a Client that
        // pins the cap's Origin Identity and the Agent's responder must be able
        // to complete the Noise_IK handshake.
        let origin_key = OriginKey::generate();
        let cap = mint_capability(origin_key.origin_identity(), "edge:443".into());

        let client_static = generate_static_keypair();
        let mut client =
            client_handshake_for(&client_static.private, &cap).expect("initiator builds");
        let mut origin = origin_handshake(&origin_key.private_bytes()).expect("responder builds");

        let (mut m1, mut m2, mut tmp) = ([0u8; 1024], [0u8; 1024], [0u8; 1024]);
        let n1 = client.write_message(&[], &mut m1).expect("msg1");
        origin.read_message(&m1[..n1], &mut tmp).expect("read msg1");
        let n2 = origin.write_message(&[], &mut m2).expect("msg2");
        client.read_message(&m2[..n2], &mut tmp).expect("read msg2");

        assert!(
            client.is_handshake_finished() && origin.is_handshake_finished(),
            "both sides finish the handshake"
        );
        assert!(client.into_transport_mode().is_ok());
        assert!(origin.into_transport_mode().is_ok());
    }
}
