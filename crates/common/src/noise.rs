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

/// Build a Client (initiator) handshake that pins the Origin Identity carried
/// by `cap` (P3.4). The Client imports a Capability out of band, then uses its
/// Origin Identity as the handshake's pinned remote static key.
pub fn client_handshake_for(
    client_private: &[u8; 32],
    cap: &crate::Capability,
) -> Result<snow::HandshakeState, snow::Error> {
    client_handshake(client_private, &cap.origin.0)
}

/// Length-prefix a message for streaming over a byte transport (2-byte
/// big-endian length + body). Noise messages are variable-length and capped at
/// 65535 bytes, so they are framed before being relayed (P3.3).
pub fn frame(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + msg.len());
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// Split one framed message off the front of `buf`, returning
/// `(message, bytes_consumed)` if a complete frame is present, else `None`.
pub fn take_frame(buf: &[u8]) -> Option<(&[u8], usize)> {
    if buf.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + n {
        return None;
    }
    Some((&buf[2..2 + n], 2 + n))
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

    #[test]
    fn frame_take_roundtrip() {
        let framed = frame(b"noise-msg");
        let (msg, consumed) = take_frame(&framed).unwrap();
        assert_eq!(msg, b"noise-msg");
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn take_frame_needs_full_frame() {
        let framed = frame(b"hello");
        assert!(take_frame(&framed[..1]).is_none(), "fewer than 2 length bytes");
        assert!(take_frame(&framed[..4]).is_none(), "body incomplete");
    }

    #[test]
    fn take_frame_leaves_remainder() {
        let mut buf = frame(b"a");
        buf.extend_from_slice(&frame(b"bb"));
        let (m1, c1) = take_frame(&buf).unwrap();
        assert_eq!(m1, b"a");
        let (m2, _c2) = take_frame(&buf[c1..]).unwrap();
        assert_eq!(m2, b"bb");
    }

    #[test]
    fn handshake_from_imported_capability_completes_with_origin() {
        use crate::{Capability, OriginIdentity, RoutingToken};

        let origin = generate_static_keypair();
        let client = generate_static_keypair();

        // Import a Capability carrying the Origin's public key (round-tripped).
        let cap = Capability {
            token: RoutingToken([1u8; 32]),
            origin: OriginIdentity(origin.public),
            edge_addr: "edge:443".into(),
        };
        let cap = Capability::decode(&cap.encode()).unwrap();

        let mut ini = client_handshake_for(&client.private, &cap).unwrap();
        let mut resp = origin_handshake(&origin.private).unwrap();

        let mut buf = [0u8; 1024];
        let mut scratch = [0u8; 1024];
        let n = ini.write_message(&[], &mut buf).unwrap();
        resp.read_message(&buf[..n], &mut scratch).unwrap();
        let n = resp.write_message(&[], &mut buf).unwrap();
        ini.read_message(&buf[..n], &mut scratch).unwrap();

        assert!(
            ini.is_handshake_finished() && resp.is_handshake_finished(),
            "handshake pinned from the imported Capability completes with the matching Origin"
        );
    }
}
