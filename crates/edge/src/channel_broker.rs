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
    verify, ChannelId, ChannelJoinRequest, Direction, GrantError, SignedChannelGrant, UnixSeconds,
};
use quinn::Endpoint;

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

/// Accept one channel-join over QUIC (AF2d-transport): read the presented
/// [`ChannelJoinRequest`], look up the channel's operator public key via
/// `operator_for` (wired to the control-plane channel registry), verify the grant
/// at `now`, reply `OK`/`NO`, and return the request on success. This is the edge
/// admission gate for a *single* participant; pairing two admitted participants
/// (via [`authorize_channel_pair`]) and swapping their advertised endpoints is the
/// next step. Rejects a malformed request, an unknown channel, and a bad/expired
/// grant — always replying `NO` before erroring so the peer learns it was refused.
pub async fn resolve_channel_join<F>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    operator_for: F,
) -> Result<ChannelJoinRequest, BoxError>
where
    F: Fn(&ChannelId) -> Option<[u8; 32]>,
{
    let incoming = endpoint
        .accept()
        .await
        .ok_or("endpoint closed with no incoming")?;
    let conn = incoming.await?;
    let (mut send, mut recv) = conn.accept_bi().await?;
    let bytes = recv.read_to_end(1024).await?;

    let req = match ChannelJoinRequest::decode(&bytes) {
        Ok(r) => r,
        Err(_) => {
            let _ = send.write_all(b"NO").await;
            let _ = send.finish();
            return Err("malformed channel join request".into());
        }
    };
    let operator = match operator_for(&req.grant.grant.channel) {
        Some(op) => op,
        None => {
            let _ = send.write_all(b"NO").await;
            let _ = send.finish();
            return Err("unknown channel".into());
        }
    };
    match verify(&operator, &req.grant, now) {
        Ok(()) => {
            send.write_all(b"OK").await?;
            send.finish()?;
            conn.closed().await; // hold the connection so the peer reads the ack
            Ok(req)
        }
        Err(e) => {
            let _ = send.write_all(b"NO").await;
            let _ = send.finish();
            Err(format!("channel grant rejected: {e}").into())
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

    // --- AF2d-transport: the QUIC channel-join admission gate ---

    async fn present_join(conn: &quinn::Connection, req_bytes: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(req_bytes).await.expect("write request");
        send.finish().expect("finish");
        recv.read_to_end(8).await.unwrap_or_default()
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
        let req = join_request(channel, 0x0a, "203.0.113.9:6001");

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c| (c.0 == channel).then_some(pk))
                .await
                .map(|r| r.endpoint)
                .map_err(|e| e.to_string())
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode()).await;
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
                async move { resolve_channel_join(&server, 500, |_c| None).await.map(|_| ()) },
            );
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &unknown.encode()).await;
        assert_ne!(ack, b"OK", "an unknown channel must be refused");
        let _ = server_task.await;

        // Known channel but the grant is expired at `now` -> NO.
        let pk = operator_pubkey();
        let channel = [0xC3u8; 32];
        let expired = join_request(channel, 0x0c, "203.0.113.9:6003"); // expires_at = 1_000
        let (server2, cert2) = build_server_endpoint_with_cert().expect("server");
        let addr2 = server2.local_addr().expect("addr");
        let server2_task = tokio::spawn(async move {
            resolve_channel_join(&server2, 2_000, move |c| (c.0 == channel).then_some(pk))
                .await
                .map(|_| ())
        });
        let client2 = build_client_endpoint(cert2).expect("client");
        let conn2 = client2.connect(addr2, "localhost").expect("cfg").await.expect("conn");
        let ack2 = present_join(&conn2, &expired.encode()).await;
        assert_ne!(ack2, b"OK", "an expired grant must be refused");
        let _ = server2_task.await;
    }
}
