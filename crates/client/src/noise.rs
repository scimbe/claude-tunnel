//! Client-side Noise initiator over the tunnel stream (M8.2).
//!
//! After the PoW-gated rendezvous has bridged the Client's stream to the Agent
//! (the Origin's custodian), the Client runs the `Noise_IK` initiator handshake
//! and then exchanges *encrypted* frames. The Edge only ever relays these
//! frames and never sees the plaintext — the provider-blind property.
//!
//! The exchange is generic over the byte transport (`AsyncRead`/`AsyncWrite`),
//! so it works over a QUIC stream in the live path and over an in-memory duplex
//! in tests.

use ct_common::noise::{client_handshake_for, frame};
use ct_common::Capability;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Read one length-prefixed frame (2-byte big-endian length + body).
async fn read_frame<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Vec<u8>, BoxError> {
    let mut len = [0u8; 2];
    recv.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body).await?;
    Ok(body)
}

/// Run the Client (initiator) `Noise_IK` handshake against the Origin responder,
/// pinning the Origin Identity in `cap`, then send `payload` encrypted and
/// return the decrypted response.
pub async fn client_noise_exchange<S, R>(
    send: &mut S,
    recv: &mut R,
    client_private: &[u8; 32],
    cap: &Capability,
    payload: &[u8],
) -> Result<Vec<u8>, BoxError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut hs = client_handshake_for(client_private, cap)?;
    let mut buf = vec![0u8; 65535];
    let mut tmp = vec![0u8; 65535];

    // -> handshake message 1 (e, es, s, ss)
    let n = hs.write_message(&[], &mut buf)?;
    send.write_all(&frame(&buf[..n])).await?;
    send.flush().await?;

    // <- handshake message 2 (e, ee, se)
    let msg2 = read_frame(recv).await?;
    hs.read_message(&msg2, &mut tmp)?;

    let mut transport = hs.into_transport_mode()?;

    // -> encrypted payload
    let n = transport.write_message(payload, &mut buf)?;
    send.write_all(&frame(&buf[..n])).await?;
    send.flush().await?;

    // <- encrypted response
    let resp = read_frame(recv).await?;
    let n = transport.read_message(&resp, &mut tmp)?;
    Ok(tmp[..n].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::noise::{generate_static_keypair, origin_handshake};
    use ct_common::{OriginIdentity, RoutingToken};

    #[tokio::test]
    async fn client_completes_noise_roundtrip_with_responder() {
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        let (client_io, server_io) = tokio::io::duplex(8192);
        let (mut c_read, mut c_write) = tokio::io::split(client_io);

        // Responder: origin handshake, then decrypt one frame and echo it back
        // encrypted — standing in for the Agent-side bridge (M8.3).
        let origin_priv = origin_kp.private;
        let responder = tokio::spawn(async move {
            let (mut s_read, mut s_write) = tokio::io::split(server_io);
            let mut hs = origin_handshake(&origin_priv).unwrap();
            let mut buf = vec![0u8; 65535];
            let mut tmp = vec![0u8; 65535];

            let m1 = read_frame(&mut s_read).await.unwrap();
            hs.read_message(&m1, &mut tmp).unwrap();
            let n = hs.write_message(&[], &mut buf).unwrap();
            s_write.write_all(&frame(&buf[..n])).await.unwrap();

            let mut transport = hs.into_transport_mode().unwrap();
            let ct = read_frame(&mut s_read).await.unwrap();
            let n = transport.read_message(&ct, &mut tmp).unwrap();
            let plaintext = tmp[..n].to_vec();
            let n = transport.write_message(&plaintext, &mut buf).unwrap();
            s_write.write_all(&frame(&buf[..n])).await.unwrap();
        });

        let resp = client_noise_exchange(
            &mut c_write,
            &mut c_read,
            &client_kp.private,
            &cap,
            b"secret-payload",
        )
        .await
        .expect("noise exchange");

        assert_eq!(resp, b"secret-payload", "decrypted echo matches the payload");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_origin_identity_fails_the_handshake() {
        // Pinning a different Origin Identity than the responder's key must not
        // yield a completed handshake.
        let real_origin = generate_static_keypair();
        let wrong_origin = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(wrong_origin.public), // mismatched pin
            edge_addr: "edge:443".into(),
        };

        let (client_io, server_io) = tokio::io::duplex(8192);
        let (mut c_read, mut c_write) = tokio::io::split(client_io);
        let origin_priv = real_origin.private;
        tokio::spawn(async move {
            let (mut s_read, mut s_write) = tokio::io::split(server_io);
            let mut hs = origin_handshake(&origin_priv).unwrap();
            let mut buf = vec![0u8; 65535];
            let mut tmp = vec![0u8; 65535];
            if let Ok(m1) = read_frame(&mut s_read).await {
                // Reading msg1 against the wrong pin fails; just stop.
                if hs.read_message(&m1, &mut tmp).is_ok() {
                    if let Ok(n) = hs.write_message(&[], &mut buf) {
                        let _ = s_write.write_all(&frame(&buf[..n])).await;
                    }
                }
            }
        });

        let result = client_noise_exchange(
            &mut c_write,
            &mut c_read,
            &client_kp.private,
            &cap,
            b"secret-payload",
        )
        .await;
        assert!(result.is_err(), "mismatched Origin Identity must fail");
    }

    // --- M8.4b: provider-blind assertion --------------------------------------
    //
    // The Edge's relay_quic is a pure bidirectional byte copy, so the bytes on
    // the Client's tunnel stream are byte-for-byte what the Edge relays. These
    // adapters record exactly those bytes; the test then asserts the plaintext
    // never appears among them.

    use std::io;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    struct RecordingWriter<W> {
        inner: W,
        log: Arc<Mutex<Vec<u8>>>,
    }

    impl<W: AsyncWrite + Unpin> AsyncWrite for RecordingWriter<W> {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            match Pin::new(&mut this.inner).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => {
                    this.log.lock().unwrap().extend_from_slice(&buf[..n]);
                    Poll::Ready(Ok(n))
                }
                other => other,
            }
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    struct RecordingReader<R> {
        inner: R,
        log: Arc<Mutex<Vec<u8>>>,
    }

    impl<R: AsyncRead + Unpin> AsyncRead for RecordingReader<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let start = buf.filled().len();
            let this = self.get_mut();
            match Pin::new(&mut this.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    let fresh = buf.filled()[start..].to_vec();
                    this.log.lock().unwrap().extend_from_slice(&fresh);
                    Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[tokio::test]
    async fn tunnel_carries_only_ciphertext_never_the_plaintext() {
        use ct_common::noise::{origin_handshake, generate_static_keypair};
        use tokio::net::TcpListener;

        const PLAINTEXT: &[u8] = b"TOP-SECRET-PLAINTEXT-MARKER";

        // Real TCP echo Origin (the only place plaintext legitimately appears).
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = origin_listener.accept().await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        let (client_io, server_io) = tokio::io::duplex(8192);
        let (c_read, c_write) = tokio::io::split(client_io);
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut rec_write = RecordingWriter { inner: c_write, log: log.clone() };
        let mut rec_read = RecordingReader { inner: c_read, log: log.clone() };

        // Agent-side responder terminates Noise and bridges plaintext to Origin.
        let origin_priv = origin_kp.private;
        let bridge = tokio::spawn(async move {
            let (mut s_read, mut s_write) = tokio::io::split(server_io);
            // Inline responder bridge (mirrors ct-agent::serve::serve_noise_bridge).
            let mut hs = origin_handshake(&origin_priv).unwrap();
            let mut buf = vec![0u8; 65535];
            let mut tmp = vec![0u8; 65535];
            let m1 = read_frame(&mut s_read).await.unwrap();
            hs.read_message(&m1, &mut tmp).unwrap();
            let n = hs.write_message(&[], &mut buf).unwrap();
            s_write.write_all(&frame(&buf[..n])).await.unwrap();
            let mut transport = hs.into_transport_mode().unwrap();
            let ct = read_frame(&mut s_read).await.unwrap();
            let n = transport.read_message(&ct, &mut tmp).unwrap();
            let request = tmp[..n].to_vec();
            let mut tcp = tokio::net::TcpStream::connect(origin_addr).await.unwrap();
            tcp.write_all(&request).await.unwrap();
            tcp.shutdown().await.unwrap();
            let mut response = Vec::new();
            tcp.read_to_end(&mut response).await.unwrap();
            let n = transport.write_message(&response, &mut buf).unwrap();
            s_write.write_all(&frame(&buf[..n])).await.unwrap();
        });

        let resp = client_noise_exchange(&mut rec_write, &mut rec_read, &client_kp.private, &cap, PLAINTEXT)
            .await
            .expect("noise exchange");
        assert_eq!(resp, PLAINTEXT, "functional: plaintext round-trips E2E");

        let seen = log.lock().unwrap().clone();
        assert!(!seen.is_empty(), "bytes did cross the tunnel");
        assert!(
            !contains(&seen, PLAINTEXT),
            "provider-blind: the relayed tunnel bytes must never contain the plaintext"
        );

        bridge.await.unwrap();
        let _ = origin.await;
    }
}
