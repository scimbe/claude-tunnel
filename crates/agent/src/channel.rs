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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Outcome of presenting a channel join to the edge broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelJoinOutcome {
    /// Admitted. `peer_endpoint` is the paired peer's advertised address when the
    /// edge ran a two-party rendezvous, or empty for a single-participant admission.
    /// `peer_noise_pubkey` is the peer's attested Noise key when the edge relayed it
    /// (#72 AF4 / #100) — so an initiator can pin it with no operator-conveyed value.
    Admitted {
        peer_endpoint: String,
        peer_noise_pubkey: Option<[u8; 32]>,
        /// The peer's grant-authenticated holder pubkey, when the edge relayed the
        /// attested-key triple (#101) — the key to verify `peer_attestation` against.
        peer_holder: Option<[u8; 32]>,
        /// The peer's holder-signed attestation over `peer_noise_pubkey` (#101), which
        /// the initiator verifies before pinning the key.
        peer_attestation: Option<[u8; 64]>,
        /// This member's own **reflexive** (post-NAT) address as the edge observed it on
        /// the authenticated join, when the ack carried it (#121 Phase B1 — the AutoNAT
        /// primitive). `None` on an older ack that omits it or on the relay leg (a
        /// relay-only member is behind symmetric NAT, so it has no punchable reflexive).
        /// This is the address the later hole-punch (B2) punches toward and the input to
        /// [`ct_common::channel::reachability_class`].
        observed_reflexive: Option<std::net::SocketAddr>,
    },
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
    let (send, recv) = conn.open_bi().await?;
    present_channel_join_on_stream(send, recv, request, holder).await
}

/// The transport-agnostic core of [`present_channel_join`]: run the channel-join wire
/// protocol over an already-open bidirectional stream (#106 client-dial). The QUIC
/// client reaches this via [`present_channel_join`] (a `quinn` bi-stream), but the
/// identical protocol — length-framed request, possession challenge/response, `OK`/`NO`
/// ack — runs over *any* duplex, so a TLS-over-TCP `:443` front-door stream (the
/// fallback when the channel UDP/TCP ports are blocked) speaks it unchanged. `send`/
/// `recv` are the write/read halves; the send half is closed after the possession step.
pub async fn present_channel_join_on_stream<W, R>(
    mut send: W,
    mut recv: R,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
) -> Result<ChannelJoinOutcome, BoxError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
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
    // Close the write half (EOF to the edge) — the QUIC `finish()` equivalent over a
    // generic stream. Lenient: on a refusal the edge may already have closed.
    let _ = send.shutdown().await;

    // The ack can carry endpoint + noise(64) + holder(64) + attestation(128) hex plus the
    // #121 `r=<reflexive>` token and separators — well over 256 bytes; cap at 512 so nothing
    // is truncated (the `take` bound is the generic-stream equivalent of quinn `read_to_end`).
    let mut ack = Vec::new();
    let _ = recv.take(512).read_to_end(&mut ack).await;
    let ack = String::from_utf8_lossy(&ack);
    match ack.strip_prefix("OK") {
        // `OK[ <endpoint>[ <noise_hex> <holder_hex> <attest_hex>]][ r=<reflexive>]` — the
        // broker appends the peer's attested Noise key, its holder, and the holder-signed
        // attestation (#101) when the registry has them (all-or-nothing), plus (#121 Phase
        // B1) the joining member's OWN edge-observed reflexive address as a tagged `r=<addr>`
        // token. The `r=` token is pulled out first (it is self-addressed, not peer material,
        // and order-independent); its absence on an older ack yields `None` — backward-additive.
        Some(rest) => {
            let mut observed_reflexive = None;
            let mut fields: Vec<&str> = Vec::new();
            for tok in rest.split_whitespace() {
                match tok.strip_prefix("r=") {
                    Some(addr) => observed_reflexive = addr.parse().ok(),
                    None => fields.push(tok),
                }
            }
            let mut parts = fields.into_iter();
            let peer_endpoint = parts.next().unwrap_or_default().to_string();
            let peer_noise_pubkey = parts.next().and_then(decode_hex_32);
            let peer_holder = parts.next().and_then(decode_hex_32);
            let peer_attestation = parts.next().and_then(decode_hex_64);
            Ok(ChannelJoinOutcome::Admitted {
                peer_endpoint,
                peer_noise_pubkey,
                peer_holder,
                peer_attestation,
                observed_reflexive,
            })
        }
        None => Ok(ChannelJoinOutcome::Refused),
    }
}

/// Present a channel join over a **relay** stream that then carries the spliced Noise
/// session on the *same* duplex (#106 relay-leg-443). This differs from
/// [`present_channel_join_on_stream`] — the QUIC / front-door **broker** leg, where the
/// join stream is throwaway (it reads the ack to EOF and closes its write half, and the
/// data path is a *separate* connection) — in two ways the `:443` relay leg requires:
/// it must **not** close the send half (the session writes over it next), and it must
/// read **exactly** the 2-byte `OK`/`NO` ack, leaving every subsequent byte for
/// [`crate::channel_run::run_channel_session_on_stream`]. The edge relay acks a bare
/// `OK` (no peer endpoint/keys — the caller already holds the peer's attested Noise key)
/// and then splices the two members' streams, so the relay ack carries no peer material.
/// `send`/`recv` are borrowed, not consumed, so the caller reuses them for the session.
pub async fn present_channel_relay_join_on_stream<W, R>(
    send: &mut W,
    recv: &mut R,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
) -> Result<ChannelJoinOutcome, BoxError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let bytes = request.encode();
    let len = u16::try_from(bytes.len()).map_err(|_| "channel join request too large")?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    send.flush().await?;

    // Answer the edge's possession challenge, same as the broker leg — but leave the send
    // half OPEN afterward (the spliced session writes over it), so no `shutdown()` here.
    let mut challenge = [0u8; 32];
    recv.read_exact(&mut challenge).await?;
    let sig = holder.sign(&challenge).to_bytes();
    send.write_all(&sig).await?;
    send.flush().await?;

    // Read EXACTLY the 2-byte `OK`/`NO` ack. Unlike the broker leg's `read_to_end`, we
    // must not read past it: the Noise session ciphertext follows immediately on this same
    // relay-spliced stream, and over-reading would swallow the session's first frame.
    let mut ack = [0u8; 2];
    recv.read_exact(&mut ack).await?;
    match &ack {
        b"OK" => Ok(ChannelJoinOutcome::Admitted {
            peer_endpoint: String::new(),
            peer_noise_pubkey: None,
            peer_holder: None,
            peer_attestation: None,
            // The relay leg acks a bare 2-byte `OK` and the Noise session follows immediately
            // on this same stream — there is no room for a reflexive token, and a relay-only
            // member has no punchable reflexive anyway (#121 Phase B1).
            observed_reflexive: None,
        }),
        _ => Ok(ChannelJoinOutcome::Refused),
    }
}

/// Decode 64 lowercase-hex chars into 32 bytes (the peer Noise key / holder the
/// broker relays), or `None` if malformed.
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Decode 128 lowercase-hex chars into the 64-byte attestation, or `None`.
fn decode_hex_64(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
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
    async fn present_channel_join_on_stream_speaks_the_protocol_over_a_plain_duplex() {
        // #106 client-dial (frozen): the channel-join wire protocol is transport-agnostic
        // — it runs over a plain in-memory duplex (the stand-in for a TLS-over-TCP :443
        // front-door stream) identically to the QUIC path. A minimal test "edge" reads
        // the framed request, issues a possession challenge, verifies the client's
        // signature under the grant holder, then acks OK + a peer endpoint; the client
        // returns Admitted with it.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        let channel = [0x3Cu8; 32];
        let holder = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_pub = holder.verifying_key().to_bytes();
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            // send = write half, recv = read half — no quinn anywhere.
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder).await
        });

        // Minimal "edge": read the framed request, challenge, verify possession, ack OK.
        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        er.read_exact(&mut body).await.expect("request");
        let challenge = [0x9u8; 32];
        ew.write_all(&challenge).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("sig");
        VerifyingKey::from_bytes(&holder_pub)
            .unwrap()
            .verify(&challenge, &Signature::from_bytes(&sig))
            .expect("the client proved possession of the holder key over the duplex");
        ew.write_all(b"OK 198.51.100.9:8008").await.expect("ack");
        let _ = ew.shutdown().await;

        match client.await.expect("client task").expect("join") {
            ChannelJoinOutcome::Admitted { peer_endpoint, .. } => assert_eq!(
                peer_endpoint, "198.51.100.9:8008",
                "the client learns the peer endpoint over a non-QUIC stream",
            ),
            ChannelJoinOutcome::Refused => panic!("a valid join over the duplex must be Admitted, not Refused"),
        }
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
            resolve_channel_join(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((op_pub, None, None)) })
                .await
                .map(|_| ())
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let outcome = present_channel_join(&conn, &request, &holder).await.expect("join drives");
        assert_eq!(
            outcome,
            ChannelJoinOutcome::Admitted { peer_endpoint: String::new(), peer_noise_pubkey: None, peer_holder: None, peer_attestation: None, observed_reflexive: None },
            "the genuine holder proves possession and is admitted"
        );
        conn.close(0u32.into(), b"done");
        let _ = srv.await;

        // (2) wrong possession key -> Refused (the grant is valid, possession is not).
        let thief = SigningKey::from_bytes(&[0x99u8; 32]);
        let (server2, cert2) = build_server_endpoint_with_cert().expect("server");
        let addr2 = server2.local_addr().expect("addr");
        let srv2 = tokio::spawn(async move {
            resolve_channel_join(&server2, 500, move |c, _h| async move { (c.0 == channel).then_some((op_pub, None, None)) })
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
            broker_channel_rendezvous(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((op_pub, None, None)) })
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
            ChannelJoinOutcome::Admitted { peer_endpoint: "203.0.113.2:7002".to_string(), peer_noise_pubkey: None, peer_holder: None, peer_attestation: None, observed_reflexive: None },
            "agent A learns B's endpoint"
        );
        assert_eq!(
            out_b,
            ChannelJoinOutcome::Admitted { peer_endpoint: "203.0.113.1:7001".to_string(), peer_noise_pubkey: None, peer_holder: None, peer_attestation: None, observed_reflexive: None },
            "agent B learns A's endpoint"
        );
    }

    #[tokio::test]
    async fn rendezvous_relays_each_peers_attested_noise_key() {
        // #72 AF4 / #100 (hands-off): when the registry has each member's Noise key,
        // the broker relays the PEER's key in the ack, so each agent learns the peer's
        // Noise pubkey to pin — no operator-conveyed value. The authorize closure
        // returns (operator, this-holder's-noise), keyed on the holder.
        let op_pub = operator().verifying_key().to_bytes();
        let channel = [0xC0u8; 32];
        let holder_a = SigningKey::from_bytes(&[0x31u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x32u8; 32]);
        let hkey_a = holder_a.verifying_key().to_bytes();
        let hkey_b = holder_b.verifying_key().to_bytes();
        let noise_a = [0xAAu8; 32];
        let noise_b = [0xBBu8; 32];
        // Each member attests its own Noise key with its holder key (#101).
        let attest_a = holder_a
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &hkey_a, &noise_a))
            .to_bytes();
        let attest_b = holder_b
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &hkey_b, &noise_b))
            .to_bytes();
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
            broker_channel_rendezvous(&server, 500, move |c, h| async move {
                // Each member resolves to (operator, its Noise key, its attestation).
                let (noise, attest) = if h == hkey_a { (noise_a, attest_a) } else { (noise_b, attest_b) };
                (c.0 == channel).then_some((op_pub, Some(noise), Some(attest)))
            })
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
            ChannelJoinOutcome::Admitted {
                peer_endpoint: "203.0.113.2:7002".to_string(),
                peer_noise_pubkey: Some(noise_b),
                peer_holder: Some(hkey_b),
                peer_attestation: Some(attest_b),
                observed_reflexive: None,
            },
            "agent A learns B's endpoint, Noise key, holder, AND attestation"
        );
        assert_eq!(
            out_b,
            ChannelJoinOutcome::Admitted {
                peer_endpoint: "203.0.113.1:7001".to_string(),
                peer_noise_pubkey: Some(noise_a),
                peer_holder: Some(hkey_a),
                peer_attestation: Some(attest_a),
                observed_reflexive: None,
            },
            "agent B learns A's endpoint, Noise key, holder, AND attestation"
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

    #[tokio::test]
    async fn member_learns_its_edge_observed_reflexive_over_quic() {
        // #121 Phase B1 (frozen): the AutoNAT round-trip over REAL QUIC. A member joins over the
        // authenticated channel connection; the edge observes its reflexive (post-NAT) source
        // via `read_join_on_connection` (`conn.remote_address()`) and reports it back in the OK
        // ack as the `r=<addr>` token; the joining member parses it into
        // `Admitted { observed_reflexive: Some(..) }`. The learned address MUST equal both what
        // the edge observed AND the loopback source the client actually connected from.
        use ct_edge::channel_broker::read_join_on_connection;

        let pk = operator().verifying_key().to_bytes();
        let channel = [0x5Bu8; 32];
        let holder = SigningKey::from_bytes(&[0x0au8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.9:6011".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        // The edge task: admit the join, then ack `OK r=<observed reflexive>` — the exact
        // primitive the B2 hole-punch and Phase C superpeer election consume.
        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let (mut send, _req, _op, _noise, _attest, observed) =
                read_join_on_connection(&conn, 500, std::time::Duration::from_secs(5), &move |c, _h| async move {
                    (c.0 == channel).then_some((pk, None, None))
                })
                .await
                .expect("admitted");
            send.write_all(format!("OK r={observed}").as_bytes()).await.expect("ack");
            send.finish().expect("finish");
            conn.closed().await; // hold the connection so the member reads the ack to EOF
            observed
        });

        let client = build_client_endpoint(cert).expect("client");
        let client_source = client.local_addr().expect("client local addr");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let outcome = present_channel_join(&conn, &request, &holder).await.expect("join drives");
        conn.close(0u32.into(), b"done");
        let observed = srv.await.expect("edge task");

        match outcome {
            ChannelJoinOutcome::Admitted { observed_reflexive, .. } => {
                assert_eq!(
                    observed_reflexive,
                    Some(observed),
                    "the member learns exactly the reflexive address the edge observed",
                );
                assert_eq!(
                    observed_reflexive,
                    Some(client_source),
                    "the observed reflexive equals the loopback source the client connected from",
                );
                assert!(observed.ip().is_loopback(), "the test's source is loopback");
            }
            ChannelJoinOutcome::Refused => panic!("a valid join must be Admitted, not Refused"),
        }
    }

    #[tokio::test]
    async fn member_learns_its_edge_observed_reflexive_over_tls_tcp_443() {
        // #121 Phase B1 (frozen): the same AutoNAT round-trip over a REAL TLS-over-TCP `:443`
        // front-door stream — the fallback path for a member whose network blocks the channel
        // ports. The edge takes the reflexive from the accepted `TcpStream`'s `peer_addr()`,
        // threads it through `admit_channel_join_on_duplex`, and reports it in the `r=<addr>`
        // token; the member parses it into `Admitted { observed_reflexive: Some(..) }` via the
        // transport-agnostic `present_channel_join_on_stream`. Proves BOTH transports carry it.
        use ct_edge::channel_broker::admit_channel_join_on_duplex;
        use ct_edge::transport::{build_tcp_tls_listener_at, tcp_tls_connect};
        use std::net::{Ipv4Addr, SocketAddr};
        use tokio::io::split;

        let pk = operator().verifying_key().to_bytes();
        let channel = [0xF4u8; 32];
        let holder = SigningKey::from_bytes(&[0x0au8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.9:6041".to_string(),
        };

        let (listener, acceptor, cert) = build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into())
            .await
            .expect("tls-tcp listener");
        let listen_addr: SocketAddr = listener.local_addr().expect("addr");

        let srv = tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.expect("tcp accept");
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            let (mut stream, _req, _op, _noise, _attest, observed) = admit_channel_join_on_duplex(
                tls,
                peer,
                500,
                std::time::Duration::from_secs(5),
                &move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) },
            )
            .await
            .expect("admitted over a real TLS-TCP stream");
            stream.write_all(format!("OK r={observed}").as_bytes()).await.expect("ack");
            stream.shutdown().await.expect("shutdown");
            observed
        });

        let client_tls = tcp_tls_connect(listen_addr, cert).await.expect("tls-tcp connect");
        let (cli_r, cli_w) = split(client_tls);
        let outcome = present_channel_join_on_stream(cli_w, cli_r, &request, &holder)
            .await
            .expect("join drives over the :443 duplex");
        let observed = srv.await.expect("edge task");

        match outcome {
            ChannelJoinOutcome::Admitted { observed_reflexive, .. } => {
                assert_eq!(
                    observed_reflexive,
                    Some(observed),
                    "the :443 member learns exactly the reflexive the edge observed on the TCP peer",
                );
                assert!(observed.ip().is_loopback(), "the test's TCP source is loopback");
            }
            ChannelJoinOutcome::Refused => panic!("a valid :443 join must be Admitted, not Refused"),
        }
    }
}
