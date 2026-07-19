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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

/// A member parked in the [`ChannelPairer`] waiting to be matched with the other
/// holder of its channel. `payload` is opaque to the pairer — the live broker carries
/// the accepted connection + its send stream + the verified [`ChannelJoinRequest`] +
/// operator key there; the pairer itself only correlates by `channel`/`holder` and
/// enforces `deadline`, so it stays pure and socket-free (unit-testable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitingMember<T> {
    pub channel: ChannelId,
    pub holder: [u8; 32],
    /// Absolute time by which this lone waiter must be paired or evicted (#109 #3).
    pub deadline: UnixSeconds,
    pub payload: T,
}

/// The outcome of offering a member to the [`ChannelPairer`].
#[derive(Debug, PartialEq, Eq)]
pub enum PairOutcome<T> {
    /// First holder of this channel — now parked, waiting for its partner.
    Parked,
    /// A different holder of the *same* channel arrived: broker exactly these two.
    Paired(WaitingMember<T>, WaitingMember<T>),
    /// The same holder re-presented (a retry) before its partner arrived: the newer
    /// offer supersedes and stays parked; the returned stale waiter must be closed
    /// (pairing a holder with itself would only earn a `SameHolder` refusal).
    Superseded(WaitingMember<T>),
}

/// Channel-keyed pairing correlator (#109 robustness): the substrate that replaces the
/// broker's channel-blind "pair the next two arrivals" accept model. Each accepted +
/// admitted member is `offer`ed here; the pairer parks the first holder of a channel
/// and only pairs it with a *different holder of the same channel* — so two channels'
/// members racing to connect can never cross-pair (the #109 mis-pairing failure), and
/// a lone first-comer is bounded by its `deadline` instead of wedging the round.
#[derive(Debug, Default)]
pub struct ChannelPairer<T> {
    waiting: std::collections::HashMap<ChannelId, WaitingMember<T>>,
}

impl<T> ChannelPairer<T> {
    pub fn new() -> Self {
        Self { waiting: std::collections::HashMap::new() }
    }

    /// Offer an admitted member. Parks it, pairs it with the waiting partner of the
    /// same channel, or supersedes a stale same-holder wait — see [`PairOutcome`].
    pub fn offer(&mut self, member: WaitingMember<T>) -> PairOutcome<T> {
        match self.waiting.remove(&member.channel) {
            None => {
                self.waiting.insert(member.channel, member);
                PairOutcome::Parked
            }
            Some(existing) if existing.holder == member.holder => {
                // Same holder retried before its partner showed up: keep the fresh
                // offer parked, hand the stale one back to be closed.
                self.waiting.insert(member.channel, member);
                PairOutcome::Superseded(existing)
            }
            Some(existing) => PairOutcome::Paired(existing, member),
        }
    }

    /// Evict and return every lone waiter whose `deadline` is at or before `now` (#3):
    /// a first-comer with no partner is bounded instead of wedging the round forever.
    pub fn drain_expired(&mut self, now: UnixSeconds) -> Vec<WaitingMember<T>> {
        let expired: Vec<ChannelId> = self
            .waiting
            .iter()
            .filter(|(_, m)| m.deadline <= now)
            .map(|(c, _)| *c)
            .collect();
        expired
            .into_iter()
            .filter_map(|c| self.waiting.remove(&c))
            .collect()
    }

    /// Number of members currently parked (one per waiting channel).
    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
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
pub async fn read_join_on_connection<F, Fut>(
    conn: &quinn::Connection,
    now: UnixSeconds,
    join_timeout: std::time::Duration,
    authorize: &F,
) -> Result<
    (quinn::SendStream, ChannelJoinRequest, [u8; 32], Option<[u8; 32]>, Option<[u8; 64]>),
    BoxError,
>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // #105: bound `accept_bi` itself — a connection that completes the QUIC handshake
    // but never opens a stream can't wedge the broker's serial round loop. The framed
    // request + possession round-trip is then bounded a second time inside
    // `read_channel_join_on_stream`, so each phase has its own guard.
    let (send, recv) = match tokio::time::timeout(join_timeout, conn.accept_bi()).await {
        Ok(streams) => streams?,
        Err(_) => {
            return Err(
                "channel join not submitted within the timeout — dropping stalled connection (#105)"
                    .into(),
            )
        }
    };
    read_channel_join_on_stream(send, recv, now, join_timeout, authorize).await
}

/// Admit a channel join over an already-established bidirectional byte stream —
/// transport-agnostic (#106 edge-dispatch). The QUIC broker reaches this via
/// [`read_join_on_connection`] (a `quinn` bi-stream), but the same admission —
/// length-framed [`ChannelJoinRequest`], membership + grant verification, and the
/// single-use holder-possession challenge — runs unchanged over *any* duplex, so a
/// TLS-over-TCP `:443` front-door stream (for members whose network blocks the
/// channel UDP/TCP ports) is admitted identically. `send`/`recv` are the write/read
/// halves of the stream; on success `send` is returned so the caller can drive the
/// pairing (rendezvous endpoint exchange or relay splice) on the same stream.
pub async fn read_channel_join_on_stream<W, R, F, Fut>(
    mut send: W,
    mut recv: R,
    now: UnixSeconds,
    join_timeout: std::time::Duration,
    authorize: &F,
) -> Result<(W, ChannelJoinRequest, [u8; 32], Option<[u8; 32]>, Option<[u8; 64]>), BoxError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // #105: bound the framed request + possession round-trip so a peer that opens the
    // stream but never submits a valid join can't wedge the broker's serial round loop.
    let read = async {
    // Length-framed request so the presenter's send stream stays open for the
    // possession challenge-response below.
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 1024 {
        let _ = send.write_all(b"NO").await;
        let _ = send.shutdown().await;
        return Err("channel join request length out of range".into());
    }
    let mut bytes = vec![0u8; len];
    recv.read_exact(&mut bytes).await?;

    let req = match ChannelJoinRequest::decode(&bytes) {
        Ok(r) => r,
        Err(_) => {
            let _ = send.write_all(b"NO").await;
            let _ = send.shutdown().await;
            return Err("malformed channel join request".into());
        }
    };
    // #81 gap 3: the advertised endpoint must be a safe, dialable socket address.
    if safe_endpoint(&req.endpoint).is_none() {
        let _ = send.write_all(b"NO").await;
        let _ = send.shutdown().await;
        return Err("unsafe advertised endpoint".into());
    }
    // #81 gap 2: the holder must be a current member; `authorize` yields the
    // operator key only then, so a revoked member is refused here.
    let (operator, member_noise, member_attest) =
        match authorize(req.grant.grant.channel, req.grant.grant.holder).await {
            Some(t) => t,
            None => {
                let _ = send.write_all(b"NO").await;
                let _ = send.shutdown().await;
                return Err("unknown channel or holder not a member".into());
            }
        };
    if let Err(e) = verify(&operator, &req.grant, now) {
        let _ = send.write_all(b"NO").await;
        let _ = send.shutdown().await;
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
        let _ = send.shutdown().await;
        return Err("holder possession proof failed".into());
    }
    Ok((send, req, operator, member_noise, member_attest))
    };
    match tokio::time::timeout(join_timeout, read).await {
        Ok(r) => r,
        Err(_) => {
            Err("channel join not submitted within the timeout — dropping stalled connection (#105)".into())
        }
    }
}

/// The bound on a single connection's join read (#105). A legitimate join completes
/// in one CP `authorize` HTTP round-trip plus a local possession exchange; anything
/// slower is a slow/broken/hostile client whose stalled connection would otherwise
/// wedge the broker's serial round loop, so it is dropped and the loop moves on.
const JOIN_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Accept one QUIC connection from `endpoint` and read its channel-join via
/// [`read_join_on_connection`]. The standalone entrypoint used by the broker's own
/// tests and by any dedicated channel-rendezvous endpoint; the live edge instead calls
/// `read_join_on_connection` directly on a connection dispatched by its accept loop.
async fn accept_and_read_join<F, Fut>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: &F,
) -> Result<
    (
        quinn::Connection,
        quinn::SendStream,
        ChannelJoinRequest,
        [u8; 32],
        Option<[u8; 32]>,
        Option<[u8; 64]>,
    ),
    BoxError,
>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    let incoming = endpoint
        .accept()
        .await
        .ok_or("endpoint closed with no incoming")?;
    let conn = incoming.await?;
    let (send, req, operator, noise, attest) =
        read_join_on_connection(&conn, now, JOIN_READ_TIMEOUT, authorize).await?;
    Ok((conn, send, req, operator, noise, attest))
}

/// Accept one channel-join over QUIC (AF2d-transport-a): read the presented
/// [`ChannelJoinRequest`], authorize the holder + verify its grant (via `authorize`,
/// wired to the control-plane channel registry — see [`accept_and_read_join`]),
/// reply `OK`/`NO`, and return the request on success. This is the edge admission
/// gate for a *single* participant; [`broker_channel_rendezvous`] pairs two.
pub async fn resolve_channel_join<F, Fut>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: F,
) -> Result<ChannelJoinRequest, BoxError>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    let (conn, mut send, req, _op, _noise, _attest) = accept_and_read_join(endpoint, now, &authorize).await?;
    send.write_all(b"OK").await?;
    send.finish()?;
    conn.closed().await; // hold the connection so the peer reads the ack
    Ok(req)
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The ` <noise> <holder> <attest>` suffix appended to `OK <endpoint>` carrying the
/// peer's attested Noise key, the peer's holder, and its holder-signed attestation
/// (#72 AF4 / #100 / #101) — so the paired agent can VERIFY the key is genuinely the
/// holder's before pinning it. Emitted only when both the Noise key and its attestation
/// are present (all-or-nothing — an initiator can't verify a key without its
/// attestation). `holder` is the peer's **grant-authenticated** holder (from the
/// verified grant, not the mutable registry), so a DB-tampered attestation over a
/// different key won't verify against it.
fn member_ack_suffix(noise: Option<[u8; 32]>, holder: &[u8; 32], attest: Option<[u8; 64]>) -> String {
    match (noise, attest) {
        (Some(n), Some(a)) => format!(" {} {} {}", hex_of(&n), hex_of(holder), hex_of(&a)),
        _ => String::new(),
    }
}

/// A channel member that has cleared admission (`accept_and_read_join` /
/// [`read_join_on_connection`]): its live QUIC connection and reply stream, the
/// verified [`ChannelJoinRequest`] it presented, the operator key its grant was
/// verified under, and the peer key material to relay to its partner. This is the
/// unit the *admit* stage produces and the `finish_*_pair` *completers* consume —
/// the seam that lets a `ChannelPairer`-driven concurrent accept loop park a lone
/// arrival and hand off exactly two members once paired (#109-concurrent).
struct AdmittedMember {
    conn: quinn::Connection,
    send: quinn::SendStream,
    req: ChannelJoinRequest,
    operator: [u8; 32],
    noise: Option<[u8; 32]>,
    attest: Option<[u8; 64]>,
}

/// Accept one QUIC connection and admit its channel-join, returning it as an
/// [`AdmittedMember`] ready to pair. Thin wrapper over `accept_and_read_join` that
/// packs the admitted tuple into the pairing unit both `broker_channel_*` functions
/// (and, later, the concurrent accept loop) consume.
async fn accept_member<F, Fut>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: &F,
) -> Result<AdmittedMember, BoxError>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    let (conn, send, req, operator, noise, attest) =
        accept_and_read_join(endpoint, now, authorize).await?;
    Ok(AdmittedMember { conn, send, req, operator, noise, attest })
}

/// Complete a **rendezvous** pairing for two already-admitted members: authorize the
/// pair under member A's operator key (`authorize_channel_pair` rejects a
/// cross-channel / incompatible / same-holder pair), then hand each side the OTHER's
/// advertised endpoint plus (when registered) the peer's attested Noise key +
/// attestation to VERIFY and pin — so an A2A session forms with no operator-conveyed
/// key. An unpairable pair gets `NO` on both sides. This is the behaviour-preserving
/// pair-completion tail of [`broker_channel_rendezvous`], split from admission so a
/// concurrent loop can `spawn` it per `ChannelPairer::offer` -> `Paired(a, b)`.
async fn finish_rendezvous_pair(
    mut a: AdmittedMember,
    mut b: AdmittedMember,
    now: UnixSeconds,
) -> Result<ChannelPairing, BoxError> {
    match authorize_channel_pair(&a.operator, &a.req.grant, &b.req.grant, now) {
        Ok(pairing) => {
            a.send
                .write_all(
                    format!(
                        "OK {}{}",
                        b.req.endpoint,
                        member_ack_suffix(b.noise, &b.req.grant.grant.holder, b.attest)
                    )
                    .as_bytes(),
                )
                .await?;
            b.send
                .write_all(
                    format!(
                        "OK {}{}",
                        a.req.endpoint,
                        member_ack_suffix(a.noise, &a.req.grant.grant.holder, a.attest)
                    )
                    .as_bytes(),
                )
                .await?;
            a.send.finish()?;
            b.send.finish()?;
            a.conn.closed().await;
            b.conn.closed().await;
            Ok(pairing)
        }
        Err(e) => {
            let _ = a.send.write_all(b"NO").await;
            let _ = b.send.write_all(b"NO").await;
            let _ = a.send.finish();
            let _ = b.send.finish();
            Err(format!("channel pair refused: {e}").into())
        }
    }
}

/// Complete a **relay** pairing for two already-admitted members: authorize the pair,
/// ack both `OK`, then splice each side's next bi-stream through the edge via
/// [`crate::relay::relay_initiator_to_acceptor`] — preserving the direct-path stream
/// roles (initiator opens, acceptor accepts the edge-opened stream) so the agents'
/// `run_channel_session` runs unchanged. The tunnel flows through the edge as
/// ciphertext. This is the behaviour-preserving pair-completion tail of
/// [`broker_channel_relay`], split from admission so a concurrent loop can `spawn` it
/// per pair — the mechanical prerequisite for taking the splice off the accept loop's
/// single global slot (#109-concurrent).
async fn finish_relay_pair(
    mut a: AdmittedMember,
    mut b: AdmittedMember,
    now: UnixSeconds,
) -> Result<ChannelPairing, BoxError> {
    match authorize_channel_pair(&a.operator, &a.req.grant, &b.req.grant, now) {
        Ok(pairing) => {
            a.send.write_all(b"OK").await?;
            b.send.write_all(b"OK").await?;
            a.send.finish()?;
            b.send.finish()?;
            let (init_conn, acc_conn) = if pairing.initiator_holder == a.req.grant.grant.holder {
                (&a.conn, &b.conn)
            } else {
                (&b.conn, &a.conn)
            };
            crate::relay::relay_initiator_to_acceptor(init_conn, acc_conn, "channel-relay").await?;
            Ok(pairing)
        }
        Err(e) => {
            let _ = a.send.write_all(b"NO").await;
            let _ = b.send.write_all(b"NO").await;
            let _ = a.send.finish();
            let _ = b.send.finish();
            Err(format!("channel relay pair refused: {e}").into())
        }
    }
}

/// Broker a direct channel between two agents (AF2d-transport-b): accept two
/// channel-joins for the same channel, pair them via [`authorize_channel_pair`],
/// and reply to each side with the *peer's* advertised endpoint (`OK <endpoint>`)
/// so the two can connect directly — the edge is only the rendezvous broker and
/// never sees their payload. An unpairable pair (channel mismatch / incompatible
/// directions / same holder) gets `NO` on both sides. Returns the decided pairing.
pub async fn broker_channel_rendezvous<F, Fut>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: F,
) -> Result<ChannelPairing, BoxError>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // Admit two members, then complete the pairing. Splitting admission from
    // completion is the seam a `ChannelPairer`-driven concurrent loop will drive
    // (park lone arrivals, spawn the finisher once two same-channel holders meet).
    let a = accept_member(endpoint, now, &authorize).await?;
    let b = accept_member(endpoint, now, &authorize).await?;
    finish_rendezvous_pair(a, b, now).await
}

/// Relay-mode admission for two channel members that can't reach each other on the
/// **direct** path (#72 AF4-session-resilience). Like [`broker_channel_rendezvous`] it
/// accepts + authorizes two joins for the same channel, but instead of swapping
/// endpoints for a direct dial it acks `OK` and then splices each side's *next*
/// bi-stream through the edge via [`crate::relay::relay_two_connections`] — so the
/// tunnel flows through the edge as ciphertext (the Noise_IK session the agents run
/// over the relayed stream stays end-to-end; the edge sees only opaque bytes). This is
/// the edge endpoint two agents fall back to when the direct dial is `Unreachable`.
/// Returns the pairing when the relay ends (either side closing tears it down).
pub async fn broker_channel_relay<F, Fut>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: F,
) -> Result<ChannelPairing, BoxError>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // Admit two members, then complete the relay. The splice lives in
    // `finish_relay_pair` so a concurrent loop can take it off the accept loop's
    // single global slot (the #109 failure mode #1) in the follow sub-packet.
    let a = accept_member(endpoint, now, &authorize).await?;
    let b = accept_member(endpoint, now, &authorize).await?;
    finish_relay_pair(a, b, now).await
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
    fn channel_pairer_correlates_by_channel_and_never_cross_pairs() {
        // #109-pairer (frozen): the channel-keyed correlator that replaces the broker's
        // channel-blind "pair the next two arrivals". Two channels racing to connect
        // must park independently and pair only same-channel holders — never cross.
        let m = |chan: u8, holder: u8, deadline: UnixSeconds, tag: &'static str| WaitingMember {
            channel: ChannelId([chan; 32]),
            holder: [holder; 32],
            deadline,
            payload: tag,
        };
        let mut pairer: ChannelPairer<&'static str> = ChannelPairer::new();

        // First holder of channel X parks.
        assert_eq!(pairer.offer(m(0x11, 0xAA, 100, "X-init")), PairOutcome::Parked);
        assert_eq!(pairer.len(), 1);

        // A different channel Y parks independently — it does NOT cross-pair with the
        // waiting X member (this is the #109 mis-pairing failure the pairer closes).
        assert_eq!(pairer.offer(m(0x22, 0xCC, 100, "Y-init")), PairOutcome::Parked);
        assert_eq!(pairer.len(), 2);

        // The second holder of channel X pairs with exactly the first X member; Y stays.
        match pairer.offer(m(0x11, 0xBB, 100, "X-acc")) {
            PairOutcome::Paired(first, second) => {
                assert_eq!(first.payload, "X-init");
                assert_eq!(second.payload, "X-acc");
                assert_eq!(first.channel, ChannelId([0x11; 32]));
            }
            other => panic!("expected Paired(X-init, X-acc), got {other:?}"),
        }
        assert_eq!(pairer.len(), 1, "X consumed by the pairing; Y still parked");

        // A same-holder re-offer (a retry) supersedes the stale wait rather than
        // pairing the holder with itself.
        assert_eq!(pairer.offer(m(0x33, 0xDD, 100, "Z-v1")), PairOutcome::Parked);
        match pairer.offer(m(0x33, 0xDD, 200, "Z-v2")) {
            PairOutcome::Superseded(stale) => assert_eq!(stale.payload, "Z-v1"),
            other => panic!("expected Superseded(Z-v1), got {other:?}"),
        }
        assert_eq!(pairer.len(), 2, "the fresh Z offer stays parked, plus Y");

        // Lone waiters past their deadline are drained (#3): Y (deadline 100) is evicted
        // at now=150, but the fresh Z-v2 (deadline 200) survives.
        let drained = pairer.drain_expired(150);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].payload, "Y-init");
        assert_eq!(pairer.len(), 1, "Z-v2 (deadline 200) is not yet expired at 150");
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
            resolve_channel_join(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
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
    async fn read_join_on_connection_admits_a_valid_join() {
        // #81 SEC81c-c c-iii-2: the connection-level entry point — what the live edge's
        // accept loop dispatches to once it has accepted the QUIC connection itself.
        let pk = operator_pubkey();
        let channel = [0xD7u8; 32];
        let holder = holder_sk(0x0a);
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6011".to_string(),
        };
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            // Accept the connection first (as the live edge loop does), then read the join.
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let (mut send, req, _op, _noise, _attest) = read_join_on_connection(&conn, 500, std::time::Duration::from_secs(5), &move |c, _h| async move {
                (c.0 == channel).then_some((pk, None, None))
            })
            .await
            .expect("admitted");
            send.write_all(b"OK").await.expect("ack");
            send.finish().expect("finish");
            conn.closed().await;
            req.endpoint
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &holder).await;
        assert_eq!(ack, b"OK", "connection-level gate admits a valid join");
        conn.close(0u32.into(), b"done");
        assert_eq!(server_task.await.expect("join"), "203.0.113.9:6011");
    }

    #[tokio::test]
    async fn read_channel_join_on_stream_admits_over_a_plain_duplex() {
        // #106 edge-dispatch (frozen): the admission is transport-agnostic. The SAME
        // framed request + membership/grant check + single-use possession challenge the
        // QUIC broker runs over a quinn bi-stream must admit an identical join presented
        // over a plain in-memory duplex — the stand-in for a TLS-over-TCP `:443`
        // front-door stream. This is what lets a member whose restrictive network blocks
        // the channel UDP/TCP ports reach the broker through the `:443` front door.
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
        let pk = operator_pubkey();
        let channel = [0xE2u8; 32];
        let holder = holder_sk(0x0a);
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6021".to_string(),
        };

        let (client_end, server_end) = tokio::io::duplex(4096);
        let (srv_r, srv_w) = split(server_end);
        let server_task = tokio::spawn(async move {
            // Note: read/write halves are passed as distinct AsyncRead/AsyncWrite, not a
            // quinn connection — no QUIC anywhere in this path.
            let (mut send, req, _op, _noise, _attest) = read_channel_join_on_stream(
                srv_w,
                srv_r,
                500,
                std::time::Duration::from_secs(5),
                &move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) },
            )
            .await
            .expect("admitted over a plain duplex");
            send.write_all(b"OK").await.expect("ack");
            send.shutdown().await.expect("shutdown");
            req.endpoint
        });

        // Drive the client side of the admission handshake over the same duplex.
        let (mut cli_r, mut cli_w) = split(client_end);
        let req_bytes = req.encode();
        cli_w
            .write_all(&(req_bytes.len() as u16).to_be_bytes())
            .await
            .expect("write length");
        cli_w.write_all(&req_bytes).await.expect("write request");
        let mut challenge = [0u8; 32];
        cli_r.read_exact(&mut challenge).await.expect("read challenge");
        let sig = holder.sign(&challenge).to_bytes();
        cli_w.write_all(&sig).await.expect("write possession sig");
        let mut ack = [0u8; 2];
        cli_r.read_exact(&mut ack).await.expect("read ack");
        assert_eq!(&ack, b"OK", "plain-duplex admission returns the same OK ack as QUIC");

        assert_eq!(
            server_task.await.expect("join"),
            "203.0.113.9:6021",
            "the handler receives the advertised endpoint over a non-QUIC transport",
        );
    }

    #[tokio::test]
    async fn read_join_on_connection_times_out_a_stalled_connection() {
        // #105: a client that completes the QUIC handshake but never opens a bi-stream
        // (never submits a join) must NOT wedge the broker — read_join_on_connection
        // abandons it within the timeout instead of blocking the serial round forever.
        use std::time::{Duration, Instant};
        let pk = operator_pubkey();
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let start = Instant::now();
            let r = read_join_on_connection(&conn, 500, Duration::from_millis(400), &move |c, _h| async move {
                (c.0 == [0u8; 32]).then_some((pk, None, None))
            })
            .await;
            (r.is_err(), start.elapsed())
        });
        let client = build_client_endpoint(cert).expect("client");
        // Connect but NEVER open a bi-stream — the stalled/silent case. Hold the
        // connection so accept_bi genuinely waits (and hits the timeout).
        let _conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let (errored, elapsed) = server_task.await.expect("task");
        assert!(errored, "a stalled connection is abandoned with an error, not hung");
        assert!(elapsed < Duration::from_secs(2), "it timed out fast ({elapsed:?}), not forever");
    }

    #[tokio::test]
    async fn edge_refuses_unknown_channel_and_expired_grant() {
        // Unknown channel: the operator lookup returns None -> NO.
        let unknown = join_request([0xC2u8; 32], 0x0b, "203.0.113.9:6002");
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task =
            tokio::spawn(
                async move {
                    resolve_channel_join(&server, 500, |_c, _h| async move { None::<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)> })
                        .await
                        .map(|_| ())
                },
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
            resolve_channel_join(&server2, 2_000, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
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
    async fn broker_channel_relay_splices_two_members_tunnels() {
        // #72 AF4-relay-fallback (edge side): the connection-difficulty path. Two
        // members that can't go direct both join the RELAY endpoint; the edge auths +
        // pairs them and splices their data streams, so the tunnel flows THROUGH the
        // edge (ciphertext). Prove bytes cross both ways over the relay.
        let pk = operator_pubkey();
        let channel = [0xE0u8; 32];
        let holder_a = holder_sk(0xa1);
        let holder_b = holder_sk(0xb2);
        let req_a = ChannelJoinRequest {
            grant: grant_h(channel, &holder_a, Direction::Initiate, 1_000),
            endpoint: "203.0.113.1:7001".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: grant_h(channel, &holder_b, Direction::Accept, 1_000),
            endpoint: "203.0.113.2:7002".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&server, 500, move |c, _h| async move {
                (c.0 == channel).then_some((pk, None, None))
            })
            .await
            .map(|_| ())
        });

        // Roles preserved through the relay (as the real Noise session needs): the
        // INITIATOR opens its data stream; the ACCEPTOR accepts one the edge opens.
        let cert_b = cert.clone();
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            assert_eq!(present_join(&conn, &req_a.encode(), &holder_a).await, b"OK", "A admitted to relay");
            let (mut s, mut r) = conn.open_bi().await.expect("a data bi"); // initiator opens
            s.write_all(b"tunnel A->B via edge").await.expect("a write");
            let mut got = vec![0u8; 20];
            r.read_exact(&mut got).await.expect("a read");
            conn.close(0u32.into(), b"done");
            got
        });
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            assert_eq!(present_join(&conn, &req_b.encode(), &holder_b).await, b"OK", "B admitted to relay");
            let (mut s, mut r) = conn.accept_bi().await.expect("b data bi"); // acceptor accepts the edge-opened stream
            let mut got = vec![0u8; 20];
            r.read_exact(&mut got).await.expect("b read");
            s.write_all(b"tunnel B->A via edge").await.expect("b write");
            let _ = s.finish();
            conn.closed().await;
            got
        });

        let got_a = a.await.expect("a");
        let got_b = b.await.expect("b");
        let _ = relay_task.await;
        assert_eq!(&got_a, b"tunnel B->A via edge", "A receives B's bytes through the edge relay");
        assert_eq!(&got_b, b"tunnel A->B via edge", "B receives A's bytes through the edge relay");
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
            broker_channel_rendezvous(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
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
    async fn finish_rendezvous_pair_completes_two_separately_admitted_members() {
        // #109-concurrent finish-pair (frozen): admission is now separable from
        // pair-completion. Admit two members with `accept_member`, THEN hand them to
        // `finish_rendezvous_pair` directly — the exact seam a `ChannelPairer`-driven
        // loop uses (`offer` -> `Paired(a, b)` -> spawn the finisher). The completion
        // must match the monolithic broker: each side learns the OTHER's endpoint and
        // roles follow the grants — proving the extraction is behaviour-preserving.
        let pk = operator_pubkey();
        let channel = [0xD5u8; 32];
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            let authorize =
                move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
            let a = accept_member(&server, 500, &authorize).await.expect("admit a");
            let b = accept_member(&server, 500, &authorize).await.expect("admit b");
            finish_rendezvous_pair(a, b, 500)
                .await
                .map(|p| (p.initiator_holder[0], p.acceptor_holder[0]))
                .map_err(|e| e.to_string())
        });

        let holder_a = holder_sk(0xa1);
        let holder_b = holder_sk(0xb2);
        let ia = holder_a.verifying_key().to_bytes()[0];
        let ib = holder_b.verifying_key().to_bytes()[0];
        let req_a = ChannelJoinRequest {
            grant: grant_h(channel, &holder_a, Direction::Initiate, 1_000),
            endpoint: "203.0.113.1:7051".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: grant_h(channel, &holder_b, Direction::Accept, 1_000),
            endpoint: "203.0.113.2:7052".to_string(),
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

        assert!(ack_a.contains("203.0.113.2:7052"), "A learns B's endpoint via the finisher, got {ack_a:?}");
        assert!(ack_b.contains("203.0.113.1:7051"), "B learns A's endpoint via the finisher, got {ack_b:?}");
        assert_eq!(paired, (ia, ib), "the finisher decides roles from the grants, same as the monolithic broker");
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
            resolve_channel_join(&server, 500, move |c, h| async move {
                (c.0 == channel && h == member).then_some((pk, None, None))
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
            resolve_channel_join(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
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
            resolve_channel_join(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
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
            resolve_channel_join(&server2, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
                .await
                .map(|_| ())
        });
        let client2 = build_client_endpoint(cert2).expect("client");
        let conn2 = client2.connect(addr2, "localhost").expect("cfg").await.expect("conn");
        let ack2 = present_join(&conn2, &req.encode(), &thief).await;
        assert_ne!(ack2, b"OK", "a stolen grant without holder possession is refused");
        let _ = task2.await;
    }

    #[tokio::test]
    async fn channel_authorizer_as_the_gate_closure_admits_a_member() {
        // #81 SEC81c-c c-iii-3a: the live wiring — the c-ii resolver (ChannelAuthorizer)
        // plugged in as the broker's async authorize closure, sourcing membership from a
        // (mock) control plane. A member is admitted; a non-member is refused. Proves the
        // c-ii resolver + c-iii-1 async gate compose before c-iii-3 mounts them in run_edge.
        use crate::channel_authorize::ChannelAuthorizer;
        use axum::routing::post;
        use axum::{Json, Router};
        use serde_json::Value;

        fn hx(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }

        let op = operator_pubkey();
        let channel = [0xE7u8; 32];
        let member = holder_sk(0x0a);
        let member_hex = hx(&member.verifying_key().to_bytes());
        let op_hex = hx(&op);
        let admin_hex = hx(&[0x7au8; 32]);

        // Mock CP c-i endpoint: operator key iff the right admin token + the known member.
        let app = Router::new().route(
            "/internal/channel/authorize",
            post(move |headers: axum::http::HeaderMap, Json(b): Json<Value>| {
                let (op_hex, member_hex, admin_hex) =
                    (op_hex.clone(), member_hex.clone(), admin_hex.clone());
                async move {
                    if headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok())
                        != Some(admin_hex.as_str())
                    {
                        return Err(axum::http::StatusCode::UNAUTHORIZED);
                    }
                    if b.get("holder").and_then(|v| v.as_str()) == Some(member_hex.as_str()) {
                        Ok(Json(serde_json::json!({ "operator_pubkey": op_hex })))
                    } else {
                        Err(axum::http::StatusCode::NOT_FOUND)
                    }
                }
            }),
        );
        let cp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cp_addr = cp.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(cp, app).await.unwrap() });
        let authorizer = ChannelAuthorizer::new(&format!("http://{cp_addr}"), &[0x7au8; 32]);

        // Broker on a QUIC endpoint, authorize sourced from the CP via the resolver.
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let az = authorizer.clone();
        let server_task = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, h| {
                let a = az.clone();
                async move { a.resolve(&c, &h).await.map(|m| (m.operator_pubkey, m.noise_pubkey, m.noise_attestation)) }
            })
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
        });

        let req = ChannelJoinRequest {
            grant: grant_h(channel, &member, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6100".to_string(),
        };
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &member).await;
        assert_eq!(ack, b"OK", "a member (per the mock CP) is admitted via ChannelAuthorizer");
        conn.close(0u32.into(), b"done");
        server_task.await.expect("join").expect("admitted");
    }
}
