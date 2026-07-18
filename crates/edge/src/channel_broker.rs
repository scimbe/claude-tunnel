//! Agent Fabric — edge channel-pairing authorization (ADR-0020, #72 AF2b).
//!
//! The edge is the rendezvous gate for agent-to-agent channels: two agents that
//! want a direct channel each present a [`SignedChannelGrant`] for the same
//! [`ChannelId`], and the edge decides whether to broker them together. This module
//! is the **pure authorization + pairing core** (no sockets): it verifies both
//! grants against the channel operator's key, checks they are for the same channel
//! with compatible directions, and returns which side initiates and which accepts.
//! The socket-level QUIC brokering (generalising `rendezvous.rs` to relay between
//! two agents) and where the operator key comes from are later sub-packets.

use ct_common::channel::{
    verify, verify_holder_possession, ChannelId, ChannelJoinRequest, Direction, GrantError,
    SignedChannelGrant, UnixSeconds,
};
use quinn::Endpoint;
use rand::RngCore;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The decided pairing for a channel: who dials (initiator) and who accepts, bound
/// to each side's holder identity (the pubkey its grant is bound to).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelPairing {
    pub channel: ChannelId,
    pub initiator_holder: [u8; 32],
    pub acceptor_holder: [u8; 32],
}

/// Why two presented grants could not be brokered into a channel pairing.
#[derive(Debug, PartialEq, Eq)]
pub enum BrokerError {
    /// One side's grant failed verification (bad signature / expired / bad key).
    GrantInvalid(GrantError),
    /// The two grants are for different channels.
    ChannelMismatch,
    /// Neither side can initiate while the other accepts (e.g. both initiate-only).
    IncompatibleDirections,
    /// Both grants bind the same holder — an agent cannot channel to itself.
    SameHolder,
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerError::GrantInvalid(e) => write!(f, "channel grant invalid: {e}"),
            BrokerError::ChannelMismatch => write!(f, "grants are for different channels"),
            BrokerError::IncompatibleDirections => {
                write!(f, "no initiator/acceptor pairing between the two grants")
            }
            BrokerError::SameHolder => write!(f, "both grants bind the same holder"),
        }
    }
}

impl std::error::Error for BrokerError {}

/// Decide whether two presented grants may be brokered into a direct channel, and
/// which side initiates. Both grants must verify against the channel operator's
/// public key at `now`, be for the same channel, bind distinct holders, and offer a
/// compatible direction split (one may Initiate, the other may Accept). When both
/// sides permit either direction, `a` is chosen as the initiator (a stable, caller-
/// independent convention).
pub fn authorize_channel_pair(
    operator_pubkey: &[u8; 32],
    a: &SignedChannelGrant,
    b: &SignedChannelGrant,
    now: UnixSeconds,
) -> Result<ChannelPairing, BrokerError> {
    verify(operator_pubkey, a, now).map_err(BrokerError::GrantInvalid)?;
    verify(operator_pubkey, b, now).map_err(BrokerError::GrantInvalid)?;

    if a.grant.channel != b.grant.channel {
        return Err(BrokerError::ChannelMismatch);
    }
    if a.grant.holder == b.grant.holder {
        return Err(BrokerError::SameHolder);
    }

    let channel = a.grant.channel;
    // Prefer a-initiates when a may initiate and b may accept; else b-initiates.
    if a.grant.direction.permits(Direction::Initiate)
        && b.grant.direction.permits(Direction::Accept)
    {
        Ok(ChannelPairing {
            channel,
            initiator_holder: a.grant.holder,
            acceptor_holder: b.grant.holder,
        })
    } else if b.grant.direction.permits(Direction::Initiate)
        && a.grant.direction.permits(Direction::Accept)
    {
        Ok(ChannelPairing {
            channel,
            initiator_holder: b.grant.holder,
            acceptor_holder: a.grant.holder,
        })
    } else {
        Err(BrokerError::IncompatibleDirections)
    }
}

/// Endpoint policy (#81 gap 3, tightened for #94): a peer agent will *dial* this
/// advertised address, so it must be a real, **publicly-routable** socket address and
/// not an SSRF / internal-pivot target. A malicious holder must not be able to make the
/// peer dial into the operator's LAN (`10.0.0.5:22`, a metadata service, an internal
/// admin API). Reject anything that isn't a parseable `SocketAddr`, and reject
/// loopback / unspecified / multicast **plus** every private / internal range: RFC1918,
/// link-local (`169.254/16`, `fe80::/10`), CGNAT (`100.64/10`) and IPv6 unique-local
/// (`fc00::/7`). Only global unicast passes. Returns the parsed address when acceptable.
fn safe_endpoint(ep: &str) -> Option<std::net::SocketAddr> {
    use std::net::IpAddr;
    let addr: std::net::SocketAddr = ep.parse().ok()?;
    let ip = addr.ip();
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return None;
    }
    match ip {
        IpAddr::V4(v4) => {
            // RFC1918 private + link-local (169.254/16) + shared/CGNAT (100.64/10).
            if v4.is_private() || v4.is_link_local() {
                return None;
            }
            let o = v4.octets();
            if o[0] == 100 && (64..=127).contains(&o[1]) {
                return None; // 100.64.0.0/10
            }
        }
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            if (s0 & 0xfe00) == 0xfc00 {
                return None; // unique-local fc00::/7
            }
            if (s0 & 0xffc0) == 0xfe80 {
                return None; // link-local fe80::/10
            }
        }
    }
    Some(addr)
}

/// Accept one QUIC connection and read + verify a presented [`ChannelJoinRequest`],
/// but do NOT ack yet — the caller owns the reply, because a single admission acks
/// `OK` immediately while the two-party broker must defer until it knows the pairing.
///
/// `authorize(channel, holder)` returns the channel's operator public key **iff the
/// holder is a current member** of the channel — a single lookup that folds the
/// #81 gap-2 membership/revocation check into the operator-key source (removing a
/// member from the registry now denies admission at the gate, no key rotation or
/// expiry-shortening needed). Rejects (with a `NO`) a malformed request, an
/// #81 gap-3 unsafe advertised endpoint, an unknown-channel/non-member holder, a
/// bad/expired grant, and (#81 gap 1) a presenter that cannot prove it holds the
/// grant's `holder` private key. Returns the request and the resolved operator key.
///
/// Wire framing: the presenter sends a `u16`-BE length prefix + the encoded request,
/// then keeps its stream open. The edge replies with a fresh 32-byte challenge; the
/// presenter must answer with a 64-byte ed25519 signature over it under `holder`
/// before the edge acks. (A plain `read_to_end` would force the presenter to finish
/// its send stream, leaving no room for the possession round-trip.)
async fn accept_and_read_join<F>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: &F,
) -> Result<(quinn::Connection, quinn::SendStream, ChannelJoinRequest, [u8; 32]), BoxError>
where
    F: Fn(&ChannelId, &[u8; 32]) -> Option<[u8; 32]>,
{
    let incoming = endpoint
        .accept()
        .await
        .ok_or("endpoint closed with no incoming")?;
    let conn = incoming.await?;
    let (mut send, mut recv) = conn.accept_bi().await?;

    // Length-framed request so the presenter's send stream stays open for the
    // possession challenge-response below.
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 1024 {
        let _ = send.write_all(b"NO").await;
        let _ = send.finish();
        return Err("channel join request length out of range".into());
    }
    let mut bytes = vec![0u8; len];
    recv.read_exact(&mut bytes).await?;

    let req = match ChannelJoinRequest::decode(&bytes) {
        Ok(r) => r,
        Err(_) => {
            let _ = send.write_all(b"NO").await;
            let _ = send.finish();
            return Err("malformed channel join request".into());
        }
    };
    // #81 gap 3: the advertised endpoint must be a safe, dialable socket address.
    if safe_endpoint(&req.endpoint).is_none() {
        let _ = send.write_all(b"NO").await;
        let _ = send.finish();
        return Err("unsafe advertised endpoint".into());
    }
    // #81 gap 2: the holder must be a current member; `authorize` yields the
    // operator key only then, so a revoked member is refused here.
    let operator = match authorize(&req.grant.grant.channel, &req.grant.grant.holder) {
        Some(op) => op,
        None => {
            let _ = send.write_all(b"NO").await;
            let _ = send.finish();
            return Err("unknown channel or holder not a member".into());
        }
    };
    if let Err(e) = verify(&operator, &req.grant, now) {
        let _ = send.write_all(b"NO").await;
        let _ = send.finish();
        return Err(format!("channel grant rejected: {e}").into());
    }
    // #81 gap 1: a signed grant is bearer bytes until the presenter proves it holds
    // the `holder` private key. The edge picks a fresh single-use challenge; the
    // presenter must return an ed25519 signature over it under `holder`. A stolen
    // grant (exfiltrated wire bytes) cannot answer, and a captured old signature
    // can't be replayed against a new challenge.
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    send.write_all(&challenge).await?;
    let mut sig = [0u8; 64];
    if recv.read_exact(&mut sig).await.is_err()
        || !verify_holder_possession(&req.grant.grant.holder, &challenge, &sig)
    {
        let _ = send.write_all(b"NO").await;
        let _ = send.finish();
        return Err("holder possession proof failed".into());
    }
    Ok((conn, send, req, operator))
}

/// Accept one channel-join over QUIC (AF2d-transport-a): read the presented
/// [`ChannelJoinRequest`], authorize the holder + verify its grant (via `authorize`,
/// wired to the control-plane channel registry — see [`accept_and_read_join`]),
/// reply `OK`/`NO`, and return the request on success. This is the edge admission
/// gate for a *single* participant; [`broker_channel_rendezvous`] pairs two.
pub async fn resolve_channel_join<F>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: F,
) -> Result<ChannelJoinRequest, BoxError>
where
    F: Fn(&ChannelId, &[u8; 32]) -> Option<[u8; 32]>,
{
    let (conn, mut send, req, _op) = accept_and_read_join(endpoint, now, &authorize).await?;
    send.write_all(b"OK").await?;
    send.finish()?;
    conn.closed().await; // hold the connection so the peer reads the ack
    Ok(req)
}

/// Broker a direct channel between two agents (AF2d-transport-b): accept two
/// channel-joins for the same channel, pair them via [`authorize_channel_pair`],
/// and reply to each side with the *peer's* advertised endpoint (`OK <endpoint>`)
/// so the two can connect directly — the edge is only the rendezvous broker and
/// never sees their payload. An unpairable pair (channel mismatch / incompatible
/// directions / same holder) gets `NO` on both sides. Returns the decided pairing.
pub async fn broker_channel_rendezvous<F>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: F,
) -> Result<ChannelPairing, BoxError>
where
    F: Fn(&ChannelId, &[u8; 32]) -> Option<[u8; 32]>,
{
    let (conn_a, mut send_a, req_a, operator) =
        accept_and_read_join(endpoint, now, &authorize).await?;
    let (conn_b, mut send_b, req_b, _op_b) =
        accept_and_read_join(endpoint, now, &authorize).await?;

    // Both holders are authorized members with verified grants; pair using channel
    // A's operator key (authorize_channel_pair rejects a cross-channel pair).
    match authorize_channel_pair(&operator, &req_a.grant, &req_b.grant, now) {
        Ok(pairing) => {
            // Each agent learns the OTHER's advertised endpoint to dial directly.
            send_a
                .write_all(format!("OK {}", req_b.endpoint).as_bytes())
                .await?;
            send_b
                .write_all(format!("OK {}", req_a.endpoint).as_bytes())
                .await?;
            send_a.finish()?;
            send_b.finish()?;
            conn_a.closed().await;
            conn_b.closed().await;
            Ok(pairing)
        }
        Err(e) => {
            let _ = send_a.write_all(b"NO").await;
            let _ = send_b.write_all(b"NO").await;
            let _ = send_a.finish();
            let _ = send_b.finish();
            Err(format!("channel pair refused: {e}").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use ct_common::channel::{ChannelGrant, Rights};
    use ed25519_dalek::{Signer, SigningKey};

    const OP_SEED: [u8; 32] = [5u8; 32];

    fn operator_pubkey() -> [u8; 32] {
        SigningKey::from_bytes(&OP_SEED).verifying_key().to_bytes()
    }

    /// A grant for `channel`, bound to `holder`, signed by the channel operator.
    fn grant(
        channel: [u8; 32],
        holder: u8,
        direction: Direction,
        expires_at: UnixSeconds,
    ) -> SignedChannelGrant {
        let sk = SigningKey::from_bytes(&OP_SEED);
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: [holder; 32],
            direction,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at,
        };
        let signature = sk.sign(&g.signing_bytes()).to_bytes();
        SignedChannelGrant { grant: g, signature }
    }

    #[test]
    fn pairs_initiator_and_acceptor() {
        let pk = operator_pubkey();
        let a = grant([1u8; 32], 0xa1, Direction::Initiate, 1_000);
        let b = grant([1u8; 32], 0xb2, Direction::Accept, 1_000);
        let pairing = authorize_channel_pair(&pk, &a, &b, 500).expect("pairs");
        assert_eq!(pairing.channel, ChannelId([1u8; 32]));
        assert_eq!(pairing.initiator_holder, [0xa1; 32]);
        assert_eq!(pairing.acceptor_holder, [0xb2; 32]);
    }

    #[test]
    fn both_directions_makes_a_the_initiator() {
        let pk = operator_pubkey();
        let a = grant([2u8; 32], 0x11, Direction::Both, 1_000);
        let b = grant([2u8; 32], 0x22, Direction::Both, 1_000);
        let pairing = authorize_channel_pair(&pk, &a, &b, 500).expect("pairs");
        assert_eq!(pairing.initiator_holder, [0x11; 32], "a leads when both are flexible");
        assert_eq!(pairing.acceptor_holder, [0x22; 32]);
    }

    #[test]
    fn reverses_roles_when_only_b_can_initiate() {
        let pk = operator_pubkey();
        let a = grant([3u8; 32], 0xaa, Direction::Accept, 1_000);
        let b = grant([3u8; 32], 0xbb, Direction::Initiate, 1_000);
        let pairing = authorize_channel_pair(&pk, &a, &b, 500).expect("pairs");
        assert_eq!(pairing.initiator_holder, [0xbb; 32]);
        assert_eq!(pairing.acceptor_holder, [0xaa; 32]);
    }

    #[test]
    fn rejects_two_initiators_and_two_acceptors() {
        let pk = operator_pubkey();
        let ii_a = grant([4u8; 32], 0x01, Direction::Initiate, 1_000);
        let ii_b = grant([4u8; 32], 0x02, Direction::Initiate, 1_000);
        assert_eq!(
            authorize_channel_pair(&pk, &ii_a, &ii_b, 500),
            Err(BrokerError::IncompatibleDirections)
        );
        let aa_a = grant([4u8; 32], 0x01, Direction::Accept, 1_000);
        let aa_b = grant([4u8; 32], 0x02, Direction::Accept, 1_000);
        assert_eq!(
            authorize_channel_pair(&pk, &aa_a, &aa_b, 500),
            Err(BrokerError::IncompatibleDirections)
        );
    }

    #[test]
    fn rejects_different_channels() {
        let pk = operator_pubkey();
        let a = grant([5u8; 32], 0x01, Direction::Initiate, 1_000);
        let b = grant([6u8; 32], 0x02, Direction::Accept, 1_000);
        assert_eq!(
            authorize_channel_pair(&pk, &a, &b, 500),
            Err(BrokerError::ChannelMismatch)
        );
    }

    #[test]
    fn rejects_same_holder() {
        let pk = operator_pubkey();
        let a = grant([7u8; 32], 0x09, Direction::Both, 1_000);
        let b = grant([7u8; 32], 0x09, Direction::Both, 1_000);
        assert_eq!(authorize_channel_pair(&pk, &a, &b, 500), Err(BrokerError::SameHolder));
    }

    #[test]
    fn rejects_expired_and_wrong_operator_key() {
        let pk = operator_pubkey();
        let a = grant([8u8; 32], 0x01, Direction::Initiate, 1_000);
        let b = grant([8u8; 32], 0x02, Direction::Accept, 1_000);
        // Expired at now == expires_at.
        assert_eq!(
            authorize_channel_pair(&pk, &a, &b, 1_000),
            Err(BrokerError::GrantInvalid(GrantError::Expired))
        );
        // A different operator key must not validate these grants.
        let other = SigningKey::from_bytes(&[6u8; 32]).verifying_key().to_bytes();
        assert_eq!(
            authorize_channel_pair(&other, &a, &b, 500),
            Err(BrokerError::GrantInvalid(GrantError::BadSignature))
        );
    }

    #[test]
    fn safe_endpoint_rejects_private_and_internal_ranges() {
        // #94: a peer dials the advertised endpoint, so only publicly-routable
        // addresses may pass — a holder must not be able to make the peer dial the
        // operator's LAN, the cloud metadata service, or a link-local host.
        for bad in [
            "127.0.0.1:22",        // loopback
            "0.0.0.0:80",          // unspecified
            "224.0.0.1:80",        // multicast
            "10.0.0.5:22",         // RFC1918
            "172.16.0.1:22",       // RFC1918
            "192.168.1.1:22",      // RFC1918
            "169.254.169.254:80",  // link-local (cloud metadata!)
            "100.64.0.1:22",       // CGNAT 100.64/10
            "[::1]:22",            // v6 loopback
            "[fe80::1]:22",        // v6 link-local
            "[fc00::1]:22",        // v6 unique-local
            "[fd12:3456::1]:22",   // v6 unique-local
            "not-an-address",
        ] {
            assert!(safe_endpoint(bad).is_none(), "{bad} must be rejected");
        }
        for ok in [
            "203.0.113.10:7001",             // public unicast (TEST-NET stand-in)
            "8.8.8.8:443",                   // public unicast
            "[2001:4860:4860::8888]:443",    // public v6 unicast
        ] {
            assert!(safe_endpoint(ok).is_some(), "{ok} must be allowed");
        }
    }

    // --- AF2d-transport: the QUIC channel-join admission gate ---

    /// A holder keypair with a real ed25519 public key (unlike the `[byte; 32]`
    /// fake pubkeys used in the pure-authz tests) so the possession round-trip works.
    fn holder_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A grant bound to a real holder pubkey, signed by the channel operator.
    fn grant_h(
        channel: [u8; 32],
        holder: &SigningKey,
        direction: Direction,
        expires_at: UnixSeconds,
    ) -> SignedChannelGrant {
        let sk = SigningKey::from_bytes(&OP_SEED);
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder.verifying_key().to_bytes(),
            direction,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at,
        };
        let signature = sk.sign(&g.signing_bytes()).to_bytes();
        SignedChannelGrant { grant: g, signature }
    }

    /// Drive the client side of the admission handshake: send the length-framed
    /// request, then (if the edge challenges) sign it under `holder` to prove
    /// possession. Returns the edge's final ack (empty if refused pre-possession).
    async fn present_join(
        conn: &quinn::Connection,
        req_bytes: &[u8],
        holder: &SigningKey,
    ) -> Vec<u8> {
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(&(req_bytes.len() as u16).to_be_bytes())
            .await
            .expect("write length");
        send.write_all(req_bytes).await.expect("write request");
        // Answer the edge's possession challenge; if the join was refused before
        // that point the stream finishes early and read_exact fails — return the ack.
        let mut challenge = [0u8; 32];
        if recv.read_exact(&mut challenge).await.is_ok() {
            let sig = holder.sign(&challenge).to_bytes();
            let _ = send.write_all(&sig).await;
        }
        let _ = send.finish();
        recv.read_to_end(128).await.unwrap_or_default()
    }

    fn join_request(channel: [u8; 32], holder: u8, endpoint: &str) -> ChannelJoinRequest {
        ChannelJoinRequest {
            grant: grant(channel, holder, Direction::Initiate, 1_000),
            endpoint: endpoint.to_string(),
        }
    }

    #[tokio::test]
    async fn edge_admits_a_valid_channel_join() {
        let pk = operator_pubkey();
        let channel = [0xC1u8; 32];
        let holder = holder_sk(0x0a);
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6001".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, _h| (c.0 == channel).then_some(pk))
                .await
                .map(|r| r.endpoint)
                .map_err(|e| e.to_string())
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &holder).await;
        assert_eq!(ack, b"OK");
        conn.close(0u32.into(), b"done");

        let endpoint = server_task.await.expect("join").expect("admitted");
        assert_eq!(endpoint, "203.0.113.9:6001", "handler returns the advertised endpoint");
    }

    #[tokio::test]
    async fn edge_refuses_unknown_channel_and_expired_grant() {
        // Unknown channel: the operator lookup returns None -> NO.
        let unknown = join_request([0xC2u8; 32], 0x0b, "203.0.113.9:6002");
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task =
            tokio::spawn(
                async move { resolve_channel_join(&server, 500, |_c, _h| None).await.map(|_| ()) },
            );
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &unknown.encode(), &holder_sk(0x0b)).await;
        assert_ne!(ack, b"OK", "an unknown channel must be refused");
        let _ = server_task.await;

        // Known channel but the grant is expired at `now` -> NO.
        let pk = operator_pubkey();
        let channel = [0xC3u8; 32];
        let expired = join_request(channel, 0x0c, "203.0.113.9:6003"); // expires_at = 1_000
        let (server2, cert2) = build_server_endpoint_with_cert().expect("server");
        let addr2 = server2.local_addr().expect("addr");
        let server2_task = tokio::spawn(async move {
            resolve_channel_join(&server2, 2_000, move |c, _h| (c.0 == channel).then_some(pk))
                .await
                .map(|_| ())
        });
        let client2 = build_client_endpoint(cert2).expect("client");
        let conn2 = client2.connect(addr2, "localhost").expect("cfg").await.expect("conn");
        let ack2 = present_join(&conn2, &expired.encode(), &holder_sk(0x0c)).await;
        assert_ne!(ack2, b"OK", "an expired grant must be refused");
        let _ = server2_task.await;
    }

    #[tokio::test]
    async fn broker_pairs_two_agents_and_swaps_endpoints() {
        // The end-to-end AF2d milestone: two agents present valid joins for the
        // SAME channel (one Initiate, one Accept); the edge pairs them and hands
        // each the OTHER's advertised endpoint so they can connect directly.
        let pk = operator_pubkey();
        let channel = [0xD1u8; 32];
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            broker_channel_rendezvous(&server, 500, move |c, _h| (c.0 == channel).then_some(pk))
                .await
                .map(|p| (p.initiator_holder[0], p.acceptor_holder[0]))
                .map_err(|e| e.to_string())
        });

        let holder_a = holder_sk(0xa1);
        let holder_b = holder_sk(0xb2);
        // First pubkey byte identifies each holder in the returned pairing.
        let ia = holder_a.verifying_key().to_bytes()[0];
        let ib = holder_b.verifying_key().to_bytes()[0];
        let req_a = ChannelJoinRequest {
            grant: grant_h(channel, &holder_a, Direction::Initiate, 1_000),
            endpoint: "203.0.113.1:7001".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: grant_h(channel, &holder_b, Direction::Accept, 1_000),
            endpoint: "203.0.113.2:7002".to_string(),
        };
        let cert_b = cert.clone();
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let ack = present_join(&conn, &req_a.encode(), &holder_a).await;
            conn.close(0u32.into(), b"done");
            String::from_utf8(ack).unwrap_or_default()
        });
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let ack = present_join(&conn, &req_b.encode(), &holder_b).await;
            conn.close(0u32.into(), b"done");
            String::from_utf8(ack).unwrap_or_default()
        });

        let ack_a = a.await.expect("a");
        let ack_b = b.await.expect("b");
        let paired = server_task.await.expect("join").expect("paired");

        // Each agent learned the PEER's endpoint (independent of edge accept order).
        assert!(ack_a.contains("203.0.113.2:7002"), "agent A learns B's endpoint, got {ack_a:?}");
        assert!(ack_b.contains("203.0.113.1:7001"), "agent B learns A's endpoint, got {ack_b:?}");
        // The initiator is the Initiate-holder, the acceptor the Accept-holder.
        assert_eq!(paired, (ia, ib), "roles follow the grants' directions");
    }

    #[tokio::test]
    async fn edge_refuses_a_non_member_holder() {
        // #81 gap 2: a holder that is NOT a current member is refused even with a
        // valid, signed, unexpired grant — this is what makes revocation work
        // (removing a member from the registry denies admission at the gate).
        let pk = operator_pubkey();
        let channel = [0xE1u8; 32];
        let member = [0x0au8; 32];
        let req = join_request(channel, 0x0b, "203.0.113.9:6100"); // holder 0x0b, not a member
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, h| {
                (c.0 == channel && h == &member).then_some(pk)
            })
            .await
            .map(|_| ())
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &holder_sk(0x0b)).await;
        assert_ne!(ack, b"OK", "a non-member holder must be refused");
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn edge_refuses_an_unsafe_endpoint() {
        // #81 gap 3: a loopback advertised endpoint (a dial-to-self SSRF target) is
        // refused before pairing, even for an authorized member with a valid grant.
        let pk = operator_pubkey();
        let channel = [0xE2u8; 32];
        let req = join_request(channel, 0x0c, "127.0.0.1:22"); // loopback -> unsafe
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, _h| (c.0 == channel).then_some(pk))
                .await
                .map(|_| ())
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &holder_sk(0x0c)).await;
        assert_ne!(ack, b"OK", "a loopback advertised endpoint must be refused");
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn edge_requires_holder_possession_of_the_grant() {
        // #81 gap 1: a valid, signed, unexpired grant for a current member is still
        // bearer bytes until the presenter proves it holds the holder private key.
        // The genuine holder signs the edge challenge and is admitted; a thief who
        // replays the SAME ~139-byte grant but signs with a different key is refused.
        let pk = operator_pubkey();
        let channel = [0xF1u8; 32];
        let holder = holder_sk(0x33);
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6200".to_string(),
        };

        // (1) genuine holder proves possession -> admitted.
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let task = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, _h| (c.0 == channel).then_some(pk))
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &holder).await;
        assert_eq!(ack, b"OK", "the genuine holder proves possession and is admitted");
        conn.close(0u32.into(), b"done");
        task.await.expect("join").expect("admitted");

        // (2) a thief replays the identical grant bytes but signs with another key.
        let thief = holder_sk(0x99);
        let (server2, cert2) = build_server_endpoint_with_cert().expect("server");
        let addr2 = server2.local_addr().expect("addr");
        let task2 = tokio::spawn(async move {
            resolve_channel_join(&server2, 500, move |c, _h| (c.0 == channel).then_some(pk))
                .await
                .map(|_| ())
        });
        let client2 = build_client_endpoint(cert2).expect("client");
        let conn2 = client2.connect(addr2, "localhost").expect("cfg").await.expect("conn");
        let ack2 = present_join(&conn2, &req.encode(), &thief).await;
        assert_ne!(ack2, b"OK", "a stolen grant without holder possession is refused");
        let _ = task2.await;
    }
}
