//! Agent Fabric — agent-to-agent Noise_IK session (#72 AF4-session, ADR-0020).
//!
//! After the edge broker pairs two channel members (each learns the other's endpoint
//! via the rendezvous in `ct_edge::channel_broker` / `ct_agent::channel`), the
//! **initiator** dials the **responder** and the two run a `Noise_IK` session pinned
//! to each other's member Noise static key (AF4-keydist). This module drives that
//! handshake and frames application data over the resulting transport — the encrypted,
//! mutually-authenticated A2A data path that makes tunnel-to-tunnel communication
//! actually carry bytes.
//!
//! The drivers are generic over the byte stream, so they run over a QUIC bi-stream
//! (the live path — `quinn::SendStream`/`RecvStream`) or any `AsyncRead`/`AsyncWrite`
//! pair (an in-memory duplex, for hermetic tests). `Noise_IK` authenticates the peer:
//! the initiator encrypts to the responder's static key, so a wrong `peer_noise_pubkey`
//! fails the AEAD tag and no session forms — only the intended member can complete it.

use std::io;

use snow::TransportState;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::noise::{client_handshake, frame, origin_handshake, read_frame};

/// Noise's plaintext ceiling per message (65535 − 16-byte tag). Callers that need to
/// move more than this per message must chunk; [`a2a_send`] rejects an over-size body.
pub const A2A_MAX_MESSAGE: usize = 65519;

fn noise_io(e: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("noise: {e}"))
}

/// Initiator half of the A2A handshake: run `Noise_IK` over `(send, recv)` pinning the
/// peer's member Noise public key, returning the established transport session. Fails
/// if the peer's key doesn't match (AEAD tag failure on the response) — so a session
/// only forms with the intended member.
pub async fn a2a_initiate<W, R>(
    send: &mut W,
    recv: &mut R,
    own_noise_private: &[u8; 32],
    peer_noise_pubkey: &[u8; 32],
) -> io::Result<TransportState>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut hs = client_handshake(own_noise_private, peer_noise_pubkey).map_err(noise_io)?;
    let mut buf = [0u8; 1024];
    let mut tmp = [0u8; 1024];
    let n = hs.write_message(&[], &mut buf).map_err(noise_io)?;
    send.write_all(&frame(&buf[..n])).await?;
    let m2 = read_frame(recv).await?;
    hs.read_message(&m2, &mut tmp).map_err(noise_io)?;
    hs.into_transport_mode().map_err(noise_io)
}

/// Responder half: read the initiator's first message (learning its static key), reply
/// with the second, and return the established transport session.
pub async fn a2a_respond<W, R>(
    send: &mut W,
    recv: &mut R,
    own_noise_private: &[u8; 32],
) -> io::Result<TransportState>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut hs = origin_handshake(own_noise_private).map_err(noise_io)?;
    let mut buf = [0u8; 1024];
    let mut tmp = [0u8; 1024];
    let m1 = read_frame(recv).await?;
    hs.read_message(&m1, &mut tmp).map_err(noise_io)?;
    let n = hs.write_message(&[], &mut buf).map_err(noise_io)?;
    send.write_all(&frame(&buf[..n])).await?;
    hs.into_transport_mode().map_err(noise_io)
}

/// Encrypt and send one application message over an established A2A session.
pub async fn a2a_send<W: AsyncWrite + Unpin>(
    send: &mut W,
    session: &mut TransportState,
    plaintext: &[u8],
) -> io::Result<()> {
    if plaintext.len() > A2A_MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a2a message exceeds the Noise plaintext limit; chunk it",
        ));
    }
    let mut ct = vec![0u8; plaintext.len() + 16];
    let n = session.write_message(plaintext, &mut ct).map_err(noise_io)?;
    send.write_all(&frame(&ct[..n])).await?;
    Ok(())
}

/// Receive and decrypt one application message from an established A2A session.
pub async fn a2a_recv<R: AsyncRead + Unpin>(
    recv: &mut R,
    session: &mut TransportState,
) -> io::Result<Vec<u8>> {
    let ct = read_frame(recv).await?;
    let mut pt = vec![0u8; ct.len()];
    let n = session.read_message(&ct, &mut pt).map_err(noise_io)?;
    pt.truncate(n);
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::generate_static_keypair;

    #[tokio::test]
    async fn two_agents_establish_a_session_and_exchange_data_both_ways() {
        // #72 AF4-session: two agents, each with a member Noise keypair, establish a
        // mutually-authenticated Noise_IK session over a duplex byte stream (standing
        // in for the paired QUIC bi-stream) and exchange application data in BOTH
        // directions — the encrypted A2A data path carrying real bytes.
        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let resp_priv = responder.private;
        let init_priv = initiator.private;
        let resp_pub = responder.public;

        // A duplex pair: initiator writes to a_w (responder reads a_r); responder
        // writes to b_w (initiator reads b_r).
        let (mut a_w, mut a_r) = tokio::io::duplex(4096);
        let (mut b_w, mut b_r) = tokio::io::duplex(4096);

        let responder_task = tokio::spawn(async move {
            let mut sess = a2a_respond(&mut b_w, &mut a_r, &resp_priv).await.expect("respond");
            let got = a2a_recv(&mut a_r, &mut sess).await.expect("recv ping");
            assert_eq!(got, b"ping from initiator", "responder decrypts the initiator's message");
            a2a_send(&mut b_w, &mut sess, b"pong from responder").await.expect("send pong");
        });

        let mut sess = a2a_initiate(&mut a_w, &mut b_r, &init_priv, &resp_pub)
            .await
            .expect("initiate");
        a2a_send(&mut a_w, &mut sess, b"ping from initiator").await.expect("send ping");
        let pong = a2a_recv(&mut b_r, &mut sess).await.expect("recv pong");
        assert_eq!(pong, b"pong from responder", "initiator decrypts the responder's reply");

        responder_task.await.expect("responder task");
    }

    #[tokio::test]
    async fn a_session_only_forms_with_the_intended_peer_key() {
        // Noise_IK authenticates the responder: an initiator that pins the WRONG peer
        // key cannot complete the handshake (the responder can't decrypt msg1 under a
        // key it doesn't hold), so no A2A session is established with an impostor.
        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let wrong = generate_static_keypair();
        let resp_priv = responder.private;
        let init_priv = initiator.private;
        let wrong_pub = wrong.public;

        let (mut a_w, mut a_r) = tokio::io::duplex(4096);
        let (mut b_w, mut b_r) = tokio::io::duplex(4096);

        let responder_task =
            tokio::spawn(async move { a2a_respond(&mut b_w, &mut a_r, &resp_priv).await.is_ok() });

        // Initiator pins `wrong_pub`, not the responder's real key.
        let init = a2a_initiate(&mut a_w, &mut b_r, &init_priv, &wrong_pub).await;
        let responder_ok = responder_task.await.expect("responder task");
        assert!(
            init.is_err() || !responder_ok,
            "a mismatched peer key must not yield a session on either side"
        );
    }
}
