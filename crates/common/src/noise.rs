//! Noise Protocol handshake primitives (ADR-0013).
//!
//! Provider-blind Client↔Origin E2E crypto. P3.1 generates the Origin's static
//! X25519 keypair; its public half is the Origin Identity a Client pins. The
//! handshake (P3.2) and QUIC wiring (P3.3) follow.

use crate::OriginIdentity;
use std::io;
use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

/// Try each candidate Origin private key as the responder against the Client's
/// handshake message 1, returning the handshake state (with `msg1` already read)
/// for whichever key **authenticates** it. In Noise_IK the initiator encrypts to
/// the responder's static key, so only the matching private key decrypts `msg1`;
/// a wrong key fails the AEAD tag. This lets one Agent terminate handshakes for
/// **multiple Origin identities at once** — the basis for zero-downtime key
/// rotation (#12): during the window the Agent holds both the old and new keys.
/// Returns `None` if no candidate matches.
pub fn origin_handshake_any(
    candidates: &[[u8; 32]],
    msg1: &[u8],
) -> Option<snow::HandshakeState> {
    let mut scratch = [0u8; 1024];
    for key in candidates {
        if let Ok(mut hs) = origin_handshake(key) {
            if hs.read_message(msg1, &mut scratch).is_ok() {
                return Some(hs);
            }
        }
    }
    None
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

/// Read exactly one length-prefixed frame (2-byte big-endian length + body) into a
/// **reusable** buffer, returning the body length `n` (the body is `buf[..n]`). `buf`
/// is resized to the frame body, so its capacity is retained across calls and the
/// bulk inbound path allocates no per-frame `Vec` (#114). Returns an error (typically
/// `UnexpectedEof`) when the source closes between frames.
pub async fn read_frame_into<R: AsyncRead + Unpin>(
    recv: &mut R,
    buf: &mut Vec<u8>,
) -> io::Result<usize> {
    let mut len = [0u8; 2];
    recv.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    buf.resize(n, 0);
    recv.read_exact(&mut buf[..n]).await?;
    Ok(n)
}

/// Read exactly one length-prefixed frame (2-byte big-endian length + body) from
/// an async byte source, returning a freshly-allocated body. Convenience wrapper over
/// [`read_frame_into`] for the low-rate handshake paths; the bulk data path in
/// [`noise_pump`] uses `read_frame_into` with a hoisted buffer instead. Returns an
/// error (typically `UnexpectedEof`) when the source closes between frames.
pub async fn read_frame<R: AsyncRead + Unpin>(recv: &mut R) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    read_frame_into(recv, &mut body).await?;
    Ok(body)
}

/// Pump a bidirectional plaintext stream over an established Noise transport
/// session (M9.1). Plaintext read from `plain` is encrypted, framed, and written
/// to `cipher`; frames read from `cipher` are decrypted and written to `plain`.
/// Runs until either side closes, propagating the half-close each way.
///
/// The two directions run concurrently; the `TransportState` is shared under a
/// short-held mutex — the send and receive nonces are independent, so
/// serialising only the (synchronous, fast) crypto step is correct and never
/// blocks on I/O.
pub async fn noise_pump<C, P>(
    transport: snow::TransportState,
    cipher: C,
    plain: P,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    const CHUNK: usize = 16 * 1024; // well under Noise's 65519-byte plaintext cap
    let ts = Mutex::new(transport);
    let (mut c_read, mut c_write) = tokio::io::split(cipher);
    let (mut p_read, mut p_write) = tokio::io::split(plain);

    let noise_err = |e: snow::Error| io::Error::new(io::ErrorKind::Other, e.to_string());

    // plaintext -> encrypt -> ciphertext frames
    let outbound = async {
        let mut buf = vec![0u8; CHUNK];
        // Reserve the 2-byte length prefix at the FRONT of `ct`, so `write_message`
        // encrypts in place after it and the frame is sent as one `ct[..2+len]` slice
        // — no per-frame `Vec` alloc and no full-ciphertext copy on the bulk path
        // (#114 #1). The wire bytes are byte-identical to `frame(&ct[..len])`.
        let mut ct = vec![0u8; 2 + CHUNK + 256];
        loop {
            let n = p_read.read(&mut buf).await?;
            if n == 0 {
                let _ = c_write.shutdown().await;
                return Ok::<(), io::Error>(());
            }
            let len = ts
                .lock()
                .unwrap()
                .write_message(&buf[..n], &mut ct[2..])
                .map_err(noise_err)?;
            ct[0..2].copy_from_slice(&(len as u16).to_be_bytes());
            c_write.write_all(&ct[..2 + len]).await?;
            c_write.flush().await?;
        }
    };

    // ciphertext frames -> decrypt -> plaintext
    let inbound = async {
        let mut pt = vec![0u8; CHUNK + 256];
        // One reusable ciphertext-frame buffer for the whole inbound loop, so no
        // per-frame `Vec` is allocated on the bulk path (#114 #2).
        let mut fr = Vec::with_capacity(CHUNK + 256);
        loop {
            let n = match read_frame_into(&mut c_read, &mut fr).await {
                Ok(n) => n,
                Err(_) => {
                    let _ = p_write.shutdown().await;
                    return Ok::<(), io::Error>(());
                }
            };
            let len = ts.lock().unwrap().read_message(&fr[..n], &mut pt).map_err(noise_err)?;
            p_write.write_all(&pt[..len]).await?;
            p_write.flush().await?;
        }
    };

    let (o, i) = tokio::join!(outbound, inbound);
    o?;
    i?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_handshake_any_selects_the_pinned_identity() {
        // #12 K1: a client pins origin A; an agent holding {B, A} (a rotation
        // window) must terminate the handshake with A, and reject a candidate set
        // that lacks the pinned identity.
        let a = generate_static_keypair();
        let b = generate_static_keypair();
        let client = generate_static_keypair();

        let mut ini = client_handshake(&client.private, &a.public).unwrap();
        let mut buf = [0u8; 1024];
        let n = ini.write_message(&[], &mut buf).unwrap();
        let msg1 = buf[..n].to_vec();

        // Candidate set contains A (in second position) → matches, and the
        // returned responder state completes the handshake with the client.
        let mut resp = origin_handshake_any(&[b.private, a.private], &msg1)
            .expect("matches the pinned origin key among candidates");
        let mut out = [0u8; 1024];
        let m = resp.write_message(&[], &mut out).unwrap();
        ini.read_message(&out[..m], &mut buf).unwrap();
        assert!(
            resp.into_transport_mode().is_ok() && ini.into_transport_mode().is_ok(),
            "handshake completes on the selected identity"
        );

        // No candidate is the pinned identity → None.
        assert!(
            origin_handshake_any(&[b.private, client.private], &msg1).is_none(),
            "rejects when the pinned origin key is absent"
        );
    }

    #[tokio::test]
    async fn noise_pump_streams_bidirectionally() {
        // Establish two transport states via a real Noise_IK handshake.
        let origin = generate_static_keypair();
        let client = generate_static_keypair();
        let mut ini = client_handshake(&client.private, &origin.public).unwrap();
        let mut resp = origin_handshake(&origin.private).unwrap();
        let mut b = [0u8; 1024];
        let mut s = [0u8; 1024];
        let n = ini.write_message(&[], &mut b).unwrap();
        resp.read_message(&b[..n], &mut s).unwrap();
        let n = resp.write_message(&[], &mut b).unwrap();
        ini.read_message(&b[..n], &mut s).unwrap();
        let ini_t = ini.into_transport_mode().unwrap();
        let resp_t = resp.into_transport_mode().unwrap();

        let (a_cipher, b_cipher) = tokio::io::duplex(64 * 1024);
        let (a_plain, a_app) = tokio::io::duplex(1024 * 1024);
        let (b_plain, b_app) = tokio::io::duplex(1024 * 1024);

        // Peer B's app is a plaintext echo — reads all, echoes back, closes.
        let echo = async move {
            let (mut r, mut w) = tokio::io::split(b_app);
            let mut all = Vec::new();
            r.read_to_end(&mut all).await.unwrap();
            w.write_all(&all).await.unwrap();
            w.shutdown().await.unwrap();
        };

        // 200 KB → many 16 KB Noise frames, both directions.
        let expected: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let payload = expected.clone();
        let (mut ar, mut aw) = tokio::io::split(a_app);
        let writer = async move {
            aw.write_all(&payload).await.unwrap();
            aw.shutdown().await.unwrap();
        };
        let reader = async move {
            let mut got = Vec::new();
            ar.read_to_end(&mut got).await.unwrap();
            got
        };

        let (pa, pb, _, _, got) = tokio::join!(
            noise_pump(ini_t, a_cipher, a_plain),
            noise_pump(resp_t, b_cipher, b_plain),
            echo,
            writer,
            reader,
        );
        pa.unwrap();
        pb.unwrap();
        assert_eq!(got.len(), expected.len(), "all 200 KB echoed back");
        assert_eq!(got, expected, "payload streams both ways through two Noise pumps");
    }

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

    #[tokio::test]
    async fn read_frame_into_reuses_one_buffer_across_varied_frames() {
        // #114 #2 (frozen): the bulk inbound path reads each frame into ONE reused
        // buffer via `read_frame_into` instead of allocating a fresh Vec per frame. It
        // must return exactly the framed bodies across a large -> small -> mid size
        // sequence (so the reused buffer both grows and shrinks), byte-for-byte
        // identical to what `frame()` wrote, and signal EOF cleanly after the last
        // frame. `&[u8]` is an `AsyncRead`, so it stands in for the ciphertext stream.
        let big = vec![0xABu8; 4096];
        let small = vec![0xCDu8; 3];
        let mid = vec![0xEFu8; 1500];
        let mut wire = Vec::new();
        for m in [&big, &small, &mid] {
            wire.extend_from_slice(&frame(m));
        }

        let mut src: &[u8] = &wire;
        let mut buf = Vec::with_capacity(16);
        for want in [&big, &small, &mid] {
            let n = read_frame_into(&mut src, &mut buf).await.expect("frame present");
            assert_eq!(n, want.len(), "reports the body length");
            assert_eq!(&buf[..n], &want[..], "body matches frame() input via the reused buffer");
        }
        assert!(
            read_frame_into(&mut src, &mut buf).await.is_err(),
            "drained source -> EOF, the clean between-frames close signal"
        );

        // The fresh-Vec wrapper `read_frame` still yields identical bodies (handshake path).
        let mut src2: &[u8] = &wire;
        assert_eq!(read_frame(&mut src2).await.unwrap(), big, "read_frame wrapper unchanged");
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
