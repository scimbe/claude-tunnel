//! Agent Fabric — agent-side channel-join client (#72 AF4, ADR-0020).
//!
//! The counterpart to the edge broker's admission gate (`ct_edge::channel_broker`):
//! an agent that holds a `SignedChannelGrant` presents a [`ChannelJoinRequest`] to
//! the edge over QUIC and proves it holds the grant's `holder` private key, then
//! learns its paired peer's advertised endpoint. This module is the wire-protocol
//! client half; dialing the edge endpoint and custody of the channel key are the
//! caller's. (The broker is not yet mounted in the live edge — #81 SEC81c-c — so this
//! drives exactly the protocol the broker's own tests exercise.)

use ct_common::channel::ChannelJoinRequest;
use ed25519_dalek::{Signer, SigningKey};
use quinn::Connection;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Outcome of presenting a channel join to the edge broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelJoinOutcome {
    /// Admitted. `peer_endpoint` is the paired peer's advertised address when the
    /// edge ran a two-party rendezvous, or empty for a single-participant admission.
    Admitted { peer_endpoint: String },
    /// Refused: a bad/expired grant, a non-member holder, an unsafe advertised
    /// endpoint, or a failed possession proof.
    Refused,
}

/// Present `request` on `conn` and complete the edge's possession handshake, signing
/// the edge-issued challenge with `holder` — whose public key must equal the grant's
/// `holder`. Returns whether the edge admitted the join and, if paired, the peer's
/// advertised endpoint.
///
/// Wire protocol (matches `ct_edge::channel_broker`): send a `u16`-BE length prefix +
/// the encoded request, keeping the stream open; if the edge replies with a 32-byte
/// challenge, answer with a 64-byte ed25519 signature over it; then read the
/// `OK[ <endpoint>]` / `NO` ack. A refusal before the possession step finishes the
/// stream with no challenge, which surfaces as [`ChannelJoinOutcome::Refused`].
pub async fn present_channel_join(
    conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
) -> Result<ChannelJoinOutcome, BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let bytes = request.encode();
    let len = u16::try_from(bytes.len()).map_err(|_| "channel join request too large")?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&bytes).await?;

    // Answer the possession challenge if the edge issues one; a refusal before the
    // possession step finishes the stream early, so read_exact then errors.
    let mut challenge = [0u8; 32];
    if recv.read_exact(&mut challenge).await.is_ok() {
        let sig = holder.sign(&challenge).to_bytes();
        send.write_all(&sig).await?;
    }
    send.finish()?;

    let ack = recv.read_to_end(128).await.unwrap_or_default();
    match String::from_utf8_lossy(&ack).strip_prefix("OK") {
        Some(rest) => Ok(ChannelJoinOutcome::Admitted {
            peer_endpoint: rest.trim().to_string(),
        }),
        None => Ok(ChannelJoinOutcome::Refused),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ct_edge::channel_broker::{broker_channel_rendezvous, resolve_channel_join};
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};

    const OP_SEED: [u8; 32] = [7u8; 32];

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&OP_SEED)
    }

    fn signed_grant(channel: [u8; 32], holder: &SigningKey, dir: Direction) -> SignedChannelGrant {
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder.verifying_key().to_bytes(),
            direction: dir,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let signature = operator().sign(&g.signing_bytes()).to_bytes();
        SignedChannelGrant { grant: g, signature }
    }

    #[tokio::test]
    async fn present_channel_join_completes_the_possession_handshake() {
        // AF4: the agent-side client drives the full broker handshake end-to-end
        // against the real edge broker. A genuine holder is admitted; a holder that
        // signs the possession challenge with the wrong key is refused.
        let op_pub = operator().verifying_key().to_bytes();
        let channel = [0xA0u8; 32];
        let holder = SigningKey::from_bytes(&[0x11u8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.7:9000".to_string(),
        };

        // (1) genuine holder -> Admitted.
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let srv = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, _h| async move { (c.0 == channel).then_some(op_pub) })
                .await
                .map(|_| ())
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let outcome = present_channel_join(&conn, &request, &holder).await.expect("join drives");
        assert_eq!(
            outcome,
            ChannelJoinOutcome::Admitted { peer_endpoint: String::new() },
            "the genuine holder proves possession and is admitted"
        );
        conn.close(0u32.into(), b"done");
        let _ = srv.await;

        // (2) wrong possession key -> Refused (the grant is valid, possession is not).
        let thief = SigningKey::from_bytes(&[0x99u8; 32]);
        let (server2, cert2) = build_server_endpoint_with_cert().expect("server");
        let addr2 = server2.local_addr().expect("addr");
        let srv2 = tokio::spawn(async move {
            resolve_channel_join(&server2, 500, move |c, _h| async move { (c.0 == channel).then_some(op_pub) })
                .await
                .map(|_| ())
        });
        let client2 = build_client_endpoint(cert2).expect("client");
        let conn2 = client2.connect(addr2, "localhost").expect("cfg").await.expect("conn");
        let outcome2 = present_channel_join(&conn2, &request, &thief).await.expect("join drives");
        assert_eq!(outcome2, ChannelJoinOutcome::Refused, "a wrong possession key is refused");
        let _ = srv2.await;
    }

    #[tokio::test]
    async fn two_agent_clients_learn_each_others_endpoint() {
        // AF4 end-to-end: two agent clients present joins for the same channel; the
        // broker pairs them and each client parses the PEER's advertised endpoint out
        // of its Admitted outcome.
        let op_pub = operator().verifying_key().to_bytes();
        let channel = [0xB0u8; 32];
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
        let req_a = ChannelJoinRequest {
            grant: signed_grant(channel, &holder_a, Direction::Initiate),
            endpoint: "203.0.113.1:7001".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: signed_grant(channel, &holder_b, Direction::Accept),
            endpoint: "203.0.113.2:7002".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let srv = tokio::spawn(async move {
            broker_channel_rendezvous(&server, 500, move |c, _h| async move { (c.0 == channel).then_some(op_pub) })
                .await
                .map(|_| ())
        });
        let cert_b = cert.clone();
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let out = present_channel_join(&conn, &req_a, &holder_a).await.expect("a joins");
            conn.close(0u32.into(), b"done");
            out
        });
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let out = present_channel_join(&conn, &req_b, &holder_b).await.expect("b joins");
            conn.close(0u32.into(), b"done");
            out
        });

        let out_a = a.await.expect("a");
        let out_b = b.await.expect("b");
        let _ = srv.await;
        assert_eq!(
            out_a,
            ChannelJoinOutcome::Admitted { peer_endpoint: "203.0.113.2:7002".to_string() },
            "agent A learns B's endpoint"
        );
        assert_eq!(
            out_b,
            ChannelJoinOutcome::Admitted { peer_endpoint: "203.0.113.1:7001".to_string() },
            "agent B learns A's endpoint"
        );
    }

    #[tokio::test]
    async fn two_agents_carry_data_over_a_channel_session() {
        // #72 AF4-session end-to-end over a REAL QUIC connection: this is the payoff
        // of the rendezvous above. Once each agent has learned its peer's endpoint,
        // the initiator dials the responder and they run a Noise_IK A2A session keyed
        // on their member Noise static keys, then exchange application data BOTH ways
        // — the live, encrypted, mutually-authenticated tunnel-to-tunnel data path.
        use ct_common::a2a::{a2a_initiate, a2a_recv, a2a_respond, a2a_send};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};

        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let resp_priv = responder.private;

        // The responder listens on its advertised endpoint; the initiator dials it.
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let (mut s, mut r) = conn.accept_bi().await.expect("accept_bi");
            let mut sess = a2a_respond(&mut s, &mut r, &resp_priv).await.expect("responder handshake");
            let got = a2a_recv(&mut r, &mut sess).await.expect("recv");
            assert_eq!(got, b"hello from agent A", "responder decrypts A's application data");
            a2a_send(&mut s, &mut sess, b"ack from agent B").await.expect("send ack");
            // Keep the connection (and endpoint) alive until the initiator is done so
            // the ack is delivered before teardown.
            conn.closed().await;
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let (mut s, mut r) = conn.open_bi().await.expect("open_bi");
        let mut sess = a2a_initiate(&mut s, &mut r, &initiator.private, &responder.public)
            .await
            .expect("initiator handshake");
        a2a_send(&mut s, &mut sess, b"hello from agent A").await.expect("send");
        let ack = a2a_recv(&mut r, &mut sess).await.expect("recv");
        assert_eq!(ack, b"ack from agent B", "agent A decrypts agent B's encrypted reply");
        conn.close(0u32.into(), b"done");
        srv.await.expect("responder task");
    }
}
