//! Noise Protocol handshake primitives (ADR-0013).
//!
//! Provider-blind Client↔Origin E2E crypto. P3.1 generates the Origin's static
//! X25519 keypair; its public half is the Origin Identity a Client pins. The
//! handshake (P3.2) and QUIC wiring (P3.3) follow.

use crate::OriginIdentity;

/// The Noise parameter set for Claude Tunnel's mesh handshake (ADR-0013).
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// A Noise static keypair (X25519). The public half is the Origin Identity;
/// the private half never leaves the Agent.
pub struct StaticKeypair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

impl StaticKeypair {
    /// The Origin Identity (public key) a Client pins.
    pub fn origin_identity(&self) -> OriginIdentity {
        OriginIdentity(self.public)
    }
}

/// Generate a fresh Noise static keypair.
pub fn generate_static_keypair() -> StaticKeypair {
    let params: snow::params::NoiseParams =
        NOISE_PARAMS.parse().expect("valid noise params");
    let kp = snow::Builder::new(params)
        .generate_keypair()
        .expect("keypair generation");
    let mut public = [0u8; 32];
    let mut private = [0u8; 32];
    public.copy_from_slice(&kp.public);
    private.copy_from_slice(&kp.private);
    StaticKeypair { public, private }
}

/// Build the Client (initiator) Noise_IK handshake state: it holds its own
/// static key and the Origin's pinned public key (the Origin Identity).
pub fn client_handshake(
    client_private: &[u8; 32],
    origin_public: &[u8; 32],
) -> Result<snow::HandshakeState, snow::Error> {
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().expect("valid noise params");
    snow::Builder::new(params)
        .local_private_key(client_private)
        .remote_public_key(origin_public)
        .build_initiator()
}

/// Build the Origin (responder) Noise_IK handshake state.
pub fn origin_handshake(origin_private: &[u8; 32]) -> Result<snow::HandshakeState, snow::Error> {
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().expect("valid noise params");
    snow::Builder::new(params)
        .local_private_key(origin_private)
        .build_responder()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_32_byte_keys() {
        let kp = generate_static_keypair();
        assert_eq!(kp.public.len(), 32);
        assert_eq!(kp.private.len(), 32);
    }

    #[test]
    fn keypairs_are_distinct() {
        let a = generate_static_keypair();
        let b = generate_static_keypair();
        assert_ne!(a.public, b.public, "fresh public keys must differ");
        assert_ne!(a.private, b.private, "fresh private keys must differ");
    }

    #[test]
    fn public_is_origin_identity() {
        let kp = generate_static_keypair();
        assert_eq!(kp.origin_identity(), OriginIdentity(kp.public));
    }

    #[test]
    fn noise_ik_handshake_establishes_e2e() {
        let origin = generate_static_keypair();
        let client = generate_static_keypair();

        let mut ini = client_handshake(&client.private, &origin.public).unwrap();
        let mut resp = origin_handshake(&origin.private).unwrap();

        // Two-message Noise_IK handshake.
        let mut buf = [0u8; 1024];
        let mut scratch = [0u8; 1024];
        let n = ini.write_message(&[], &mut buf).unwrap();
        resp.read_message(&buf[..n], &mut scratch).unwrap();
        let n = resp.write_message(&[], &mut buf).unwrap();
        ini.read_message(&buf[..n], &mut scratch).unwrap();

        assert!(ini.is_handshake_finished());
        assert!(resp.is_handshake_finished());

        let mut ini_t = ini.into_transport_mode().unwrap();
        let mut resp_t = resp.into_transport_mode().unwrap();

        // client -> origin
        let mut ct = [0u8; 1024];
        let mut pt = [0u8; 1024];
        let n = ini_t.write_message(b"secret payload", &mut ct).unwrap();
        let m = resp_t.read_message(&ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], b"secret payload");

        // origin -> client
        let n = resp_t.write_message(b"reply", &mut ct).unwrap();
        let m = ini_t.read_message(&ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], b"reply");
    }

    #[test]
    fn wrong_origin_key_fails_handshake() {
        let origin = generate_static_keypair();
        let wrong = generate_static_keypair();
        let client = generate_static_keypair();

        // Client pins the WRONG Origin public key.
        let mut ini = client_handshake(&client.private, &wrong.public).unwrap();
        let mut resp = origin_handshake(&origin.private).unwrap();

        let mut buf = [0u8; 1024];
        let mut scratch = [0u8; 1024];
        let n = ini.write_message(&[], &mut buf).unwrap();
        let result = resp.read_message(&buf[..n], &mut scratch);
        assert!(
            result.is_err(),
            "handshake must fail when the client pins the wrong Origin key"
        );
    }
}
