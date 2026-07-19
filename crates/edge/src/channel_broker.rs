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
    // Behaviour-preserving (#121 Phase B1): the private/internal-range test is factored into
    // the shared `ct_common::channel::is_global_unicast`, so the edge's SSRF filter and the
    // reflexive-reachability classifier agree by construction on what counts as reachable.
    ep.parse::<std::net::SocketAddr>()
        .ok()
        .filter(|addr| ct_common::channel::is_global_unicast(*addr))
}

/// Admission predicate for a join's advertised endpoint (#121): admit the explicit
/// `relay-only` sentinel (`CHANNEL_ENDPOINT_RELAY_ONLY`; a NAT-only member that participates via the
/// relay only) **or** a safe, globally-routable address ([`safe_endpoint`]). A private /
/// loopback / internal address is STILL refused exactly as #94 requires — the sentinel is a
/// reserved non-address, so a member cannot smuggle a LAN SSRF target through it, and
/// [`safe_endpoint`] itself is left untouched. So a member either advertises a global-unicast
/// address it can be dialed at, or the sentinel (not an address at all): there is no third
/// case a hostile holder can exploit.
fn admissible_endpoint(req: &ChannelJoinRequest) -> bool {
    req.is_relay_only() || safe_endpoint(&req.endpoint).is_some()
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
    (
        quinn::SendStream,
        ChannelJoinRequest,
        [u8; 32],
        Option<[u8; 32]>,
        Option<[u8; 64]>,
        std::net::SocketAddr,
    ),
    BoxError,
>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // #121 Phase B1: the reflexive (post-NAT) address the QUIC transport observed as this
    // authenticated connection's source — the AutoNAT primitive, the same `remote_address()`
    // the classic tunnel uses (see `serve.rs`). Captured here where the whole connection
    // exists and passed into the stream-generic admission so it can travel back in the ack.
    let observed = conn.remote_address();
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
    // The quinn broker pairs over the `quinn::Connection` (rendezvous endpoint swap /
    // relay bi-stream), not over this join stream, so the returned read half is dropped.
    let (send, _recv, req, operator, member_noise, member_attest, observed) =
        read_channel_join_on_stream(send, recv, observed, now, join_timeout, authorize).await?;
    Ok((send, req, operator, member_noise, member_attest, observed))
}

/// Admit a channel join over an already-established bidirectional byte stream —
/// transport-agnostic (#106 edge-dispatch). The QUIC broker reaches this via
/// [`read_join_on_connection`] (a `quinn` bi-stream), but the same admission —
/// length-framed [`ChannelJoinRequest`], membership + grant verification, and the
/// single-use holder-possession challenge — runs unchanged over *any* duplex, so a
/// TLS-over-TCP `:443` front-door stream (for members whose network blocks the
/// channel UDP/TCP ports) is admitted identically. `send`/`recv` are the write/read
/// halves of the stream; on success **both** are returned (the write half first, then
/// the read half) so the caller can reunite them into the full duplex and drive the
/// pairing (rendezvous endpoint exchange or relay splice) on the same stream — the
/// read half is not consumed by admission (#106 complete-wire443).
///
/// `observed` is the member's **reflexive** (post-NAT) source address as seen on this
/// already-authenticated connection (#121 Phase B1 — the AutoNAT primitive): the
/// transport-aware caller supplies it (`conn.remote_address()` for QUIC, the accepted
/// `TcpStream`'s `peer_addr()` for the `:443` front door), keeping this stream-generic
/// core transport-agnostic, and it is echoed back as the last returned element so the
/// caller can report it to the member and classify reachability
/// ([`ct_common::channel::reachability_class`]).
pub async fn read_channel_join_on_stream<W, R, F, Fut>(
    mut send: W,
    mut recv: R,
    observed: std::net::SocketAddr,
    now: UnixSeconds,
    join_timeout: std::time::Duration,
    authorize: &F,
) -> Result<
    (W, R, ChannelJoinRequest, [u8; 32], Option<[u8; 32]>, Option<[u8; 64]>, std::net::SocketAddr),
    BoxError,
>
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
    // #81 gap 3 / #121: the advertised endpoint must be a safe, dialable socket address —
    // OR the explicit relay-only sentinel for a NAT-only member that joins via relay only.
    // A private/loopback address is still refused (the sentinel is not an address, so it
    // can't smuggle a LAN SSRF target; `safe_endpoint` is untouched).
    if !admissible_endpoint(&req) {
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
    Ok((send, recv, req, operator, member_noise, member_attest, observed))
    };
    match tokio::time::timeout(join_timeout, read).await {
        Ok(r) => r,
        Err(_) => {
            Err("channel join not submitted within the timeout — dropping stalled connection (#105)".into())
        }
    }
}

/// Admit a channel join over an already-TLS-accepted `:443` front-door stream —
/// the broker's **TLS-TCP accept leg** (#106 dispatch-transport). The broker speaks
/// QUIC, but `:443` is TLS-over-TCP; a member whose restrictive network blocks the
/// channel UDP/TCP ports reaches the same admission through the front door, which
/// terminates TLS over TCP. `stream` is the already-TLS-accepted duplex (a
/// `tokio_rustls` server stream — any `AsyncRead + AsyncWrite + Unpin`); this splits
/// it into read/write halves with [`tokio::io::split`] and runs the identical
/// [`read_channel_join_on_stream`] admission (length-framed [`ChannelJoinRequest`],
/// membership + grant verification, single-use holder-possession challenge) over
/// them — so a real TLS-over-TCP stream is admitted exactly as a QUIC bi-stream is.
/// On success the **reunited full-duplex stream** is returned (the read half is not
/// consumed by admission), alongside the admitted request/keys, so the caller can hand
/// it straight to [`finish_relay_pair_over_streams`] to relay-splice two `:443` members
/// end-to-end (#106 complete-wire443).
pub async fn admit_channel_join_on_duplex<S, F, Fut>(
    stream: S,
    observed: std::net::SocketAddr,
    now: UnixSeconds,
    join_timeout: std::time::Duration,
    authorize: &F,
) -> Result<
    (S, ChannelJoinRequest, [u8; 32], Option<[u8; 32]>, Option<[u8; 64]>, std::net::SocketAddr),
    BoxError,
>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // #121 Phase B1: the `:443` front door terminates TLS over TCP, so its accept loop knows
    // the member's reflexive source from the accepted `TcpStream`'s `peer_addr()` and passes
    // it as `observed` — this stream-generic core never calls `remote_address()` itself.
    let (recv, send) = tokio::io::split(stream);
    let (send, recv, req, operator, member_noise, member_attest, observed) =
        read_channel_join_on_stream(send, recv, observed, now, join_timeout, authorize).await?;
    // Reunite the split halves back into the original stream (`ReadHalf::unsplit`), so
    // the post-admission data path is the whole duplex — the read half is no longer
    // trapped inside admission and the caller can relay-splice it.
    Ok((recv.unsplit(send), req, operator, member_noise, member_attest, observed))
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
        std::net::SocketAddr,
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
    let (send, req, operator, noise, attest, observed) =
        read_join_on_connection(&conn, now, JOIN_READ_TIMEOUT, authorize).await?;
    Ok((conn, send, req, operator, noise, attest, observed))
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
    let (conn, mut send, req, _op, _noise, _attest, _observed) =
        accept_and_read_join(endpoint, now, &authorize).await?;
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
pub(crate) struct AdmittedMember {
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
    // #121 Phase B1: the observed reflexive address is captured at admission and returned by
    // `accept_and_read_join`; wiring it into the pair-completion ack (so a member learns its
    // reflexive during live rendezvous/relay) is the deferred B1 follow slice, so it is not
    // carried on `AdmittedMember` yet — the primitive's edge-observe→report→client-parse round
    // trip is proven end-to-end at the admission seam by the reflexive round-trip tests.
    let (conn, send, req, operator, noise, attest, _observed) =
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
pub(crate) async fn finish_rendezvous_pair(
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
pub(crate) async fn finish_relay_pair(
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

/// A channel member admitted over a **generic byte stream** (not a `quinn::Connection`)
/// — e.g. a `:443` TLS-over-TCP front-door member whose network blocks the channel
/// UDP/TCP ports (#106). Unlike [`AdmittedMember`] it carries no `quinn::Connection`:
/// its data path is the **same** duplex the join was admitted over (there is no separate
/// bi-stream to open), so the relay splice reads/writes the Noise ciphertext directly on
/// `stream`. Only the relay path needs this (a member that can't be dialed can't use
/// rendezvous), so it carries just what the relay completer uses — `stream` + the
/// verified request + the operator key its grant verified under. `pub` like the rest of
/// the transport-generic seam ([`admit_channel_join_on_duplex`]); the `:443` front-door
/// wiring (#106-complete-wire443) constructs it from an admitted stream + its keys.
pub struct AdmittedStreamMember<S> {
    stream: S,
    req: ChannelJoinRequest,
    operator: [u8; 32],
}

/// Complete a **relay** pairing for two members admitted over generic byte streams
/// (#106 relay-splice-generic) — the transport-agnostic sibling of [`finish_relay_pair`].
/// Authorize the pair under member A's operator key, ack `OK` on each stream, then splice
/// the two duplexes through the edge via [`crate::relay::relay_streams`] so the Noise_IK
/// tunnel flows end-to-end as ciphertext (the edge sees only opaque bytes). Because each
/// member's data path is the **same** stream it joined on (no separate bi-stream to
/// open/accept, unlike the quinn path), the splice is a plain symmetric bidirectional
/// pump — no initiator/acceptor stream-role dance. This is what lets two `:443`/TLS-TCP
/// members (which cannot be dialed, so rendezvous is useless to them) be relay-paired.
/// Returns the decided pairing when either side closes; an unpairable pair gets `NO`.
pub async fn finish_relay_pair_over_streams<A, B>(
    mut a: AdmittedStreamMember<A>,
    mut b: AdmittedStreamMember<B>,
    now: UnixSeconds,
) -> Result<ChannelPairing, BoxError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    match authorize_channel_pair(&a.operator, &a.req.grant, &b.req.grant, now) {
        Ok(pairing) => {
            a.stream.write_all(b"OK").await?;
            a.stream.flush().await?;
            b.stream.write_all(b"OK").await?;
            b.stream.flush().await?;
            crate::relay::relay_streams(a.stream, b.stream, "channel-relay-443").await?;
            Ok(pairing)
        }
        Err(e) => {
            let _ = a.stream.write_all(b"NO").await;
            let _ = b.stream.write_all(b"NO").await;
            let _ = a.stream.shutdown().await;
            let _ = b.stream.shutdown().await;
            Err(format!("channel relay pair refused: {e}").into())
        }
    }
}

/// Admit one channel member arriving over a `:443` front-door stream and offer it to a
/// shared [`ChannelPairer`] (#106 dispatch-frontdoor). Because a `:443` member cannot
/// be dialed, front-door connections arrive **independently** (the two holders of a
/// channel connect separately), so the front door can't pair "the next two arrivals" —
/// it must correlate by `ChannelId`. This admits the stream
/// ([`admit_channel_join_on_duplex`]), parks it in `pairer` keyed by channel, and:
/// - returns `Ok(None)` when it is the first holder of its channel (now parked), or
/// - returns `Ok(Some((a, b)))` when its partner was already waiting — the caller then
///   relay-splices exactly those two with [`finish_relay_pair_over_streams`] (typically
///   on its own task, so the accept loop stays free).
///
/// A same-holder retry supersedes the stale wait (its stream is closed) and the fresh
/// offer stays parked (`Ok(None)`). The lock is held only for the synchronous `offer`,
/// never across `.await`. This is the transport-generic core the front-door accept loop
/// drives; wiring it into `serve_front_door` is the follow slice.
pub async fn admit_and_pair_on_stream<S, F, Fut>(
    stream: S,
    observed: std::net::SocketAddr,
    now: UnixSeconds,
    join_timeout: std::time::Duration,
    authorize: &F,
    deadline: UnixSeconds,
    pairer: &std::sync::Mutex<ChannelPairer<AdmittedStreamMember<S>>>,
) -> Result<Option<(AdmittedStreamMember<S>, AdmittedStreamMember<S>)>, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // #121 Phase B1: `observed` is this member's reflexive source (the front door fills it from
    // the accepted `TcpStream`'s `peer_addr()`). It is captured through admission; carrying it
    // into the relay-pair ack for a `:443` member is the deferred B1 follow slice (a `:443`-only
    // member is behind symmetric/CGNAT NAT — `RelayOnly` — so it needs no reflexive to punch).
    let (stream, req, operator, _noise, _attest, _observed) =
        admit_channel_join_on_duplex(stream, observed, now, join_timeout, authorize).await?;
    let channel = req.grant.grant.channel;
    let holder = req.grant.grant.holder;
    let member = AdmittedStreamMember { stream, req, operator };
    let outcome = pairer
        .lock()
        .unwrap()
        .offer(WaitingMember { channel, holder, deadline, payload: member });
    match outcome {
        PairOutcome::Parked => Ok(None),
        PairOutcome::Paired(a, b) => Ok(Some((a.payload, b.payload))),
        PairOutcome::Superseded(stale) => {
            // A retry from the same holder arrived before its partner; the fresh offer is
            // now parked, so close the stale stream and report "parked" (nothing to pair).
            let mut stale = stale.payload;
            let _ = stale.stream.shutdown().await;
            Ok(None)
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

/// Drive a QUIC channel endpoint (RELAY *or* RENDEZVOUS) as a concurrent, channel-keyed
/// broker (#109-concurrent-b, #120) — the QUIC analog of the front-door
/// [`admit_and_pair_on_stream`] loop, generic over the pairing **completer**. This replaces
/// the serial `loop { broker_channel_relay(..).await }` / `loop { broker_channel_rendezvous
/// (..).await }` the edge used to run, which admitted exactly two connections and then ran
/// the pair-completion **inline**: a single member that held its connection open (a #103
/// persistent relay sink, or — #120 — a rendezvous member that never closes) held that one
/// global slot forever, so every other member of every channel was blocked (#109/#120
/// failure #1), and two channels racing were paired blind by arrival order (#109 failure #2).
///
/// Each accepted + admitted member is `offer`ed to a channel-keyed [`ChannelPairer`]: the
/// first holder of a channel parks; when a *different holder of the same channel* arrives
/// the two are paired and `complete(a, b, now)` (e.g. [`finish_relay_pair`] for the relay,
/// [`finish_rendezvous_pair`] for rendezvous) is `spawn`ed on its own task, so the accept
/// loop immediately returns to admit the next member — a held-open member can no longer wedge
/// the endpoint (#1), and channel-keying means two channels can never cross-pair (#2). A
/// same-holder retry supersedes the stale wait (its connection is closed). On each accept the
/// pairer is swept for lone waiters past their `park_ttl` deadline, which are closed instead
/// of parked forever (#109 failure #3). `now_fn` is sampled per accept (a real clock in the
/// daemon, a fixed stub in tests). The `Mutex` is held only for the synchronous
/// `offer`/`drain_expired`, never across an `.await`; the spawned `complete` future must be
/// `Send + 'static` ([`AdmittedMember`] is).
///
/// Never returns: it *is* the endpoint's accept loop, spawned by `run_edge`.
pub(crate) async fn run_channel_broker_loop<F, Fut, N, C, CFut>(
    endpoint: &Endpoint,
    now_fn: N,
    authorize: F,
    park_ttl: UnixSeconds,
    complete: C,
) where
    N: Fn() -> UnixSeconds,
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
    C: Fn(AdmittedMember, AdmittedMember, UnixSeconds) -> CFut,
    CFut: std::future::Future<Output = Result<ChannelPairing, BoxError>> + Send + 'static,
{
    let pairer: std::sync::Mutex<ChannelPairer<AdmittedMember>> =
        std::sync::Mutex::new(ChannelPairer::new());
    loop {
        let now = now_fn();

        // Sweep lone waiters past their park deadline (#3) before admitting the next member,
        // so a first-comer with no partner is bounded instead of wedging the endpoint. The
        // guard is dropped before the following `.await`.
        let expired = pairer.lock().unwrap().drain_expired(now);
        for m in expired {
            m.payload.conn.close(0u32.into(), b"channel park timeout");
        }

        // Admit ONE member (its join read is bounded by #105); on error, log and keep
        // serving — a single bad connection must not tear down the endpoint loop.
        let member = match accept_member(endpoint, now, &authorize).await {
            Ok(m) => m,
            Err(e) => {
                eprintln!("ct-edge: channel admit failed: {e}");
                continue;
            }
        };
        let channel = member.req.grant.grant.channel;
        let holder = member.req.grant.grant.holder;

        // Offer to the channel-keyed pairer; the lock is held only for the sync `offer`.
        let outcome = pairer.lock().unwrap().offer(WaitingMember {
            channel,
            holder,
            deadline: now.saturating_add(park_ttl),
            payload: member,
        });
        match outcome {
            // First holder of this channel — parked, waiting for its partner.
            PairOutcome::Parked => {}
            // Its partner met it: complete the pair on its OWN task so the accept loop stays
            // free to admit the next member. This is the fix for the single-slot wedge (#1).
            PairOutcome::Paired(a, b) => {
                let fut = complete(a.payload, b.payload, now);
                tokio::spawn(async move {
                    if let Err(e) = fut.await {
                        eprintln!("ct-edge: channel pair ended: {e}");
                    }
                });
            }
            // Same holder re-presented before its partner arrived: the fresh offer stays
            // parked; close the stale connection (pairing a holder with itself is refused).
            PairOutcome::Superseded(stale) => {
                stale.payload.conn.close(0u32.into(), b"superseded by newer join");
            }
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
    fn admission_accepts_the_relay_only_sentinel_but_still_refuses_private_addresses() {
        // #121 (frozen): a NAT-only member advertises the relay-only sentinel and is admitted
        // WITHOUT weakening `safe_endpoint` — a private / loopback / internal address is still
        // refused exactly as #94 requires. The sentinel is a reserved non-address, so a hostile
        // holder can't smuggle a LAN SSRF target through it: it's the sentinel or a real
        // global-unicast address, nothing in between.
        use ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY;
        let mk = |ep: &str| ChannelJoinRequest {
            grant: grant([1u8; 32], 0xaa, Direction::Initiate, 1_000),
            endpoint: ep.to_string(),
        };
        // The explicit sentinel is admitted...
        assert!(admissible_endpoint(&mk(CHANNEL_ENDPOINT_RELAY_ONLY)), "the relay-only sentinel is admitted");
        // ...and is not itself a parseable address, so it can't collide with a real endpoint
        // and `safe_endpoint` (unchanged) never treats it as one.
        assert!(safe_endpoint(CHANNEL_ENDPOINT_RELAY_ONLY).is_none(), "the sentinel is not a safe_endpoint address");
        // Every private / loopback / internal address is STILL refused (safe_endpoint intact).
        for bad in ["10.0.0.5:22", "127.0.0.1:22", "192.168.1.1:22", "169.254.169.254:80", "[fc00::1]:22"] {
            assert!(!admissible_endpoint(&mk(bad)), "{bad} is still refused — the sentinel didn't weaken #94");
        }
        // A real global-unicast address still passes on its own merits.
        assert!(admissible_endpoint(&mk("203.0.113.10:7001")), "a public address is still admitted");
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
            let (mut send, req, _op, _noise, _attest, _observed) = read_join_on_connection(&conn, 500, std::time::Duration::from_secs(5), &move |c, _h| async move {
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
            let observed: std::net::SocketAddr = "203.0.113.50:40001".parse().unwrap();
            let (mut send, _recv, req, _op, _noise, _attest, _observed) = read_channel_join_on_stream(
                srv_w,
                srv_r,
                observed,
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
    async fn admit_channel_join_over_tls_tcp_matches_the_quic_path() {
        // #106 dispatch-transport (accept leg, frozen): the `:443` front-door channel
        // admission runs over a REAL TLS-over-TCP stream, not just an in-memory duplex.
        // Stand up a genuine rustls TLS-over-TCP server+client over loopback (the
        // `transport.rs` fallback helpers the classic edge uses for its `:443` leg) and
        // drive the full admission handshake — length-framed request → possession
        // challenge → OK — through `admit_channel_join_on_duplex`. The admitted member
        // must match the QUIC path exactly (same OK ack, same advertised endpoint), so a
        // member whose network blocks the channel ports is admitted identically via `:443`.
        use crate::transport::{build_tcp_tls_listener_at, tcp_tls_connect};
        use std::net::{Ipv4Addr, SocketAddr};

        let pk = operator_pubkey();
        let channel = [0xF4u8; 32];
        let holder = holder_sk(0x0a);
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6041".to_string(),
        };

        let (listener, acceptor, cert) = build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into())
            .await
            .expect("tls-tcp listener");
        let addr: SocketAddr = listener.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.expect("tcp accept");
            // A real TLS handshake terminates here — `tls` is a tokio_rustls server
            // stream, the exact transport the `:443` front door yields.
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            let (mut stream, req, _op, _noise, _attest, _observed) = admit_channel_join_on_duplex(
                tls,
                peer,
                500,
                std::time::Duration::from_secs(5),
                &move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) },
            )
            .await
            .expect("admitted over a real TLS-TCP stream");
            // #106 complete-wire443: `admit_channel_join_on_duplex` returns the REUNITED
            // full duplex, not just the write half. Prove it: ack on the write side, then
            // read a post-admission app byte off the SAME stream — the read half survived
            // admission, so this stream is ready to hand to `finish_relay_pair_over_streams`.
            stream.write_all(b"OK").await.expect("ack");
            let mut app = [0u8; 1];
            stream.read_exact(&mut app).await.expect("read app byte over the reunited stream");
            stream.shutdown().await.expect("shutdown");
            (req.endpoint, app[0])
        });

        // Client: connect over TLS-TCP and drive the same handshake `present_join` drives
        // over QUIC (framed request, then answer the edge's possession challenge).
        let mut client = tcp_tls_connect(addr, cert).await.expect("tls-tcp connect");
        let req_bytes = req.encode();
        client
            .write_all(&(req_bytes.len() as u16).to_be_bytes())
            .await
            .expect("write length");
        client.write_all(&req_bytes).await.expect("write request");
        let mut challenge = [0u8; 32];
        client.read_exact(&mut challenge).await.expect("read challenge");
        let sig = holder.sign(&challenge).to_bytes();
        client.write_all(&sig).await.expect("write possession sig");
        let mut ack = [0u8; 2];
        client.read_exact(&mut ack).await.expect("read ack");
        assert_eq!(&ack, b"OK", "TLS-TCP admission returns the same OK ack as QUIC");
        // Post-admission app byte on the same TLS-TCP stream — the server reads it off
        // the reunited duplex, proving the full stream survives admission (wire443).
        client.write_all(&[0x5a]).await.expect("write app byte after OK");

        let (endpoint, app) = server_task.await.expect("join");
        assert_eq!(
            endpoint, "203.0.113.9:6041",
            "the admitted member's advertised endpoint matches the QUIC path",
        );
        assert_eq!(
            app, 0x5a,
            "the reunited TLS-TCP stream carries post-admission app data (read half survived)",
        );
    }

    #[tokio::test]
    async fn relay_pairs_two_admitted_tls_tcp_members_end_to_end() {
        // #106 complete-wire443-e2e (frozen): the capstone `:443` relay path. Admit TWO
        // real TLS-over-TCP members (a source + a `:443`-only sink, neither dialable) via
        // `admit_channel_join_on_duplex`, then `finish_relay_pair_over_streams` them —
        // proving a full source<->sink A2A relay forms end-to-end over `:443`, edge-
        // brokered, with no quinn anywhere. The Noise_IK session would run over this
        // spliced path; here each side pushes one app byte to prove the edge splices the
        // two admitted duplexes together (and that roles come from the grants).
        use crate::transport::{build_tcp_tls_listener_at, tcp_tls_connect};
        use std::net::{Ipv4Addr, SocketAddr};

        let pk = operator_pubkey();
        let channel = [0x7Eu8; 32];
        let src = holder_sk(0xa1); // Initiate grant → initiator
        let snk = holder_sk(0xb2); // Accept grant → acceptor
        let src_pk = src.verifying_key().to_bytes();
        let snk_pk = snk.verifying_key().to_bytes();
        let req_src = ChannelJoinRequest {
            grant: grant_h(channel, &src, Direction::Initiate, 1_000),
            endpoint: "203.0.113.1:7001".to_string(),
        };
        let req_snk = ChannelJoinRequest {
            grant: grant_h(channel, &snk, Direction::Accept, 1_000),
            endpoint: "203.0.113.2:7002".to_string(),
        };

        let (listener, acceptor, cert) = build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into())
            .await
            .expect("tls-tcp listener");
        let addr: SocketAddr = listener.local_addr().expect("addr");

        // Edge: accept two TLS-TCP connections, admit both over the front-door transport,
        // then relay-splice the two admitted `:443` duplexes.
        let server = tokio::spawn(async move {
            let authorize =
                move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
            let (t1, peer1) = listener.accept().await.expect("accept 1");
            let tls1 = acceptor.accept(t1).await.expect("tls 1");
            let (s1, r1, op1, _n1, _a1, _o1) =
                admit_channel_join_on_duplex(tls1, peer1, 500, std::time::Duration::from_secs(5), &authorize)
                    .await
                    .expect("admit 1");
            let (t2, peer2) = listener.accept().await.expect("accept 2");
            let tls2 = acceptor.accept(t2).await.expect("tls 2");
            let (s2, r2, op2, _n2, _a2, _o2) =
                admit_channel_join_on_duplex(tls2, peer2, 500, std::time::Duration::from_secs(5), &authorize)
                    .await
                    .expect("admit 2");
            finish_relay_pair_over_streams(
                AdmittedStreamMember { stream: s1, req: r1, operator: op1 },
                AdmittedStreamMember { stream: s2, req: r2, operator: op2 },
                500,
            )
            .await
            .map(|p| (p.initiator_holder, p.acceptor_holder))
            .map_err(|e| e.to_string())
        });

        // Each member: connect over TLS-TCP, run the admission handshake, wait for the
        // relay's OK (written once both are paired), then push one app byte and read the
        // peer's — the bytes cross only if the edge spliced the two duplexes.
        let cert2 = cert.clone();
        let src_task = tokio::spawn(async move {
            let mut c = tcp_tls_connect(addr, cert).await.expect("connect src");
            let rb = req_src.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&src.sign(&ch).to_bytes()).await.expect("sig");
            let mut ok = [0u8; 2];
            c.read_exact(&mut ok).await.expect("ok");
            assert_eq!(&ok, b"OK", "relay acks OK once both :443 members are paired");
            c.write_all(&[0x11]).await.expect("app send");
            let mut got = [0u8; 1];
            c.read_exact(&mut got).await.expect("app recv");
            // Close gracefully (TLS close_notify) so the relay sees a clean EOF, not an
            // abrupt drop — a real client shuts down; the test must too.
            let _ = c.shutdown().await;
            got[0]
        });
        let snk_task = tokio::spawn(async move {
            let mut c = tcp_tls_connect(addr, cert2).await.expect("connect snk");
            let rb = req_snk.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&snk.sign(&ch).to_bytes()).await.expect("sig");
            let mut ok = [0u8; 2];
            c.read_exact(&mut ok).await.expect("ok");
            assert_eq!(&ok, b"OK", "relay acks OK once both :443 members are paired");
            c.write_all(&[0x22]).await.expect("app send");
            let mut got = [0u8; 1];
            c.read_exact(&mut got).await.expect("app recv");
            let _ = c.shutdown().await;
            got[0]
        });

        let got_src = src_task.await.expect("src task");
        let got_snk = snk_task.await.expect("snk task");
        let (init_h, acc_h) = server.await.expect("server task").expect("relay paired");

        assert_eq!(got_src, 0x22, "source received the sink's byte through the :443 relay");
        assert_eq!(got_snk, 0x11, "sink received the source's byte through the :443 relay");
        assert_eq!(init_h, src_pk, "the Initiate-grant holder is the initiator");
        assert_eq!(acc_h, snk_pk, "the Accept-grant holder is the acceptor");
    }

    #[tokio::test]
    async fn admit_and_pair_on_stream_parks_then_pairs_by_channel() {
        // #106 dispatch-frontdoor (handler, frozen): the front door's `:443` members arrive
        // independently, so admission must correlate by `ChannelId` via a shared
        // `ChannelPairer`. The FIRST holder of a channel parks (Ok(None)); the SECOND
        // returns Ok(Some((a, b))) — exactly the two same-channel members — which the
        // caller relay-splices. Prove it end-to-end over two in-memory duplexes: park,
        // pair, splice, bytes cross, pairer drained.
        use std::sync::Mutex;
        let pk = operator_pubkey();
        let channel = [0x9Au8; 32];
        let src = holder_sk(0xa1); // Initiate
        let snk = holder_sk(0xb2); // Accept
        let req_src = ChannelJoinRequest {
            grant: grant_h(channel, &src, Direction::Initiate, 1_000),
            endpoint: "203.0.113.1:8001".to_string(),
        };
        let req_snk = ChannelJoinRequest {
            grant: grant_h(channel, &snk, Direction::Accept, 1_000),
            endpoint: "203.0.113.2:8002".to_string(),
        };

        let (c1, s1) = tokio::io::duplex(4096);
        let (c2, s2) = tokio::io::duplex(4096);

        // Two members drive the admission handshake independently, then exchange a byte
        // once the relay's OK arrives.
        let src_task = tokio::spawn(async move {
            let mut c = c1;
            let rb = req_src.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&src.sign(&ch).to_bytes()).await.expect("sig");
            let mut ok = [0u8; 2];
            c.read_exact(&mut ok).await.expect("ok");
            assert_eq!(&ok, b"OK");
            c.write_all(&[0x11]).await.expect("send");
            let mut g = [0u8; 1];
            c.read_exact(&mut g).await.expect("recv");
            let _ = c.shutdown().await;
            g[0]
        });
        let snk_task = tokio::spawn(async move {
            let mut c = c2;
            let rb = req_snk.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&snk.sign(&ch).to_bytes()).await.expect("sig");
            let mut ok = [0u8; 2];
            c.read_exact(&mut ok).await.expect("ok");
            assert_eq!(&ok, b"OK");
            c.write_all(&[0x22]).await.expect("send");
            let mut g = [0u8; 1];
            c.read_exact(&mut g).await.expect("recv");
            let _ = c.shutdown().await;
            g[0]
        });

        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<tokio::io::DuplexStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize =
            move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };

        // In-memory duplexes have no socket peer; a dummy reflexive addr stands in (the observed
        // address isn't asserted here — the front-door wiring test covers real `peer_addr()`).
        let obs1: std::net::SocketAddr = "203.0.113.1:8001".parse().unwrap();
        let obs2: std::net::SocketAddr = "203.0.113.2:8002".parse().unwrap();

        // First holder → parked (no partner yet).
        let r1 = admit_and_pair_on_stream(s1, obs1, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer)
            .await
            .expect("admit 1");
        assert!(r1.is_none(), "first holder of the channel parks in the pairer");
        assert_eq!(pairer.lock().unwrap().len(), 1, "one member waiting");

        // Second holder → paired with exactly the parked first.
        let r2 = admit_and_pair_on_stream(s2, obs2, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer)
            .await
            .expect("admit 2");
        let (a, b) = r2.expect("second holder pairs with the parked first");
        assert!(pairer.lock().unwrap().is_empty(), "the pair was removed from the pairer");

        // The caller relay-splices exactly those two.
        finish_relay_pair_over_streams(a, b, 500).await.expect("relay spliced the paired members");

        assert_eq!(src_task.await.expect("src"), 0x22, "source got the sink's byte via the paired relay");
        assert_eq!(snk_task.await.expect("snk"), 0x11, "sink got the source's byte via the paired relay");
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

    /// One relay member for the concurrency test: connect over QUIC, run the admission
    /// handshake, await the relay's `OK` (written only once the member is PAIRED), then run
    /// the data-stream dance for its role and exchange one byte through the edge. The
    /// Initiate side opens its data stream; the Accept side accepts the edge-opened one
    /// (roles come from the grant direction), exactly as the live Noise session does. After
    /// the byte crosses, it signals `on_ready` (proving it paired + is relaying) and, when
    /// `hold` is set, keeps its connection open until notified — so one channel's relay can
    /// be held LIVE while another channel races to pair. Returns the peer's byte.
    async fn run_relay_member(
        cert: rustls::pki_types::CertificateDer<'static>,
        addr: std::net::SocketAddr,
        channel: [u8; 32],
        holder: SigningKey,
        direction: Direction,
        send_byte: u8,
        on_ready: Option<tokio::sync::mpsc::Sender<()>>,
        hold: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> u8 {
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, direction, 1_000),
            endpoint: "203.0.113.9:7000".to_string(),
        };
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        assert_eq!(present_join(&conn, &req.encode(), &holder).await, b"OK", "member admitted + paired");
        let mut got = [0u8; 1];
        if direction == Direction::Initiate {
            let (mut s, mut r) = conn.open_bi().await.expect("init data bi"); // initiator opens
            s.write_all(&[send_byte]).await.expect("init write");
            r.read_exact(&mut got).await.expect("init read");
        } else {
            let (mut s, mut r) = conn.accept_bi().await.expect("acc data bi"); // acceptor accepts edge-opened
            r.read_exact(&mut got).await.expect("acc read");
            s.write_all(&[send_byte]).await.expect("acc write");
            let _ = s.finish(); // finish (not abort) so the relay forwards the byte + EOF
        }
        if let Some(tx) = on_ready {
            let _ = tx.send(()).await; // paired + a byte has crossed → relay is live
        }
        if let Some(rx) = hold {
            let _ = rx.await; // keep the relay (and connection) open until released
        }
        // Teardown order matches the passing `broker_channel_relay_splices` test: the
        // initiator closes the connection (tearing the relay down), and the acceptor
        // WAITS for that teardown so its finished byte is fully forwarded first — an
        // abrupt `conn.close()` on the writer races the relay and drops the last byte.
        if direction == Direction::Initiate {
            conn.close(0u32.into(), b"done");
        } else {
            conn.closed().await;
        }
        got[0]
    }

    #[tokio::test]
    async fn relay_broker_loop_pairs_two_channels_concurrently_without_wedging() {
        // #109-concurrent-b (frozen): the anti-wedge + correct-correlation property over real
        // QUIC, driving the RELAY endpoint with `run_relay_broker_loop`. Channel X and channel
        // Y each present an Initiate+Accept member (4 connections). We deterministically pair X
        // FIRST and HOLD its relay open, then race Y in: with the pairer-driven loop that spawns
        // each splice on its own task, Y still pairs and its bytes cross (anti-wedge, #1) while
        // being channel-keyed so X and Y never cross-pair (#2). Under the old serial
        // `loop { broker_channel_relay }`, X's held-open inline splice would block the accept
        // loop forever and Y would never be admitted — this test would hang.
        let pk = operator_pubkey();
        let chan_x = [0x11u8; 32];
        let chan_y = [0x22u8; 32];

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        // Drive the relay endpoint with the concurrent, channel-keyed broker loop. Fixed clock
        // + generous park TTL so no lone waiter is evicted mid-test.
        let driver = tokio::spawn(async move {
            run_channel_broker_loop(
                &server,
                || 500u64,
                move |c: ChannelId, _h: [u8; 32]| async move {
                    (c.0 == chan_x || c.0 == chan_y).then_some((pk, None, None))
                },
                10_000,
                |a, b, now| finish_relay_pair(a, b, now),
            )
            .await;
        });

        // Phase 1: pair channel X and hold its relay OPEN. A per-member oneshot keeps X's two
        // members (hence X's spawned splice task) alive until we release them after Y is done
        // — a oneshot is race-free (the release is delivered even if sent before the member
        // awaits it, unlike `Notify::notify_waiters`).
        let (x1_tx, x1_rx) = tokio::sync::oneshot::channel::<()>();
        let (x2_tx, x2_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::channel::<()>(2);
        let x_init = tokio::spawn(run_relay_member(
            cert.clone(), addr, chan_x, holder_sk(0xa1), Direction::Initiate, 0x01,
            Some(ready_tx.clone()), Some(x1_rx),
        ));
        let x_acc = tokio::spawn(run_relay_member(
            cert.clone(), addr, chan_x, holder_sk(0xb2), Direction::Accept, 0x02,
            Some(ready_tx.clone()), Some(x2_rx),
        ));
        drop(ready_tx);
        // Both X members report a byte has crossed: X is paired and its relay is actively
        // splicing (and held open) BEFORE any Y connection exists.
        ready_rx.recv().await.expect("x member 1 relaying");
        ready_rx.recv().await.expect("x member 2 relaying");

        // Phase 2: now race channel Y in. If the accept loop were wedged by X's held-open relay,
        // these would hang; with the pairer-driven loop they pair on a fresh spawned splice.
        let y_init = tokio::spawn(run_relay_member(
            cert.clone(), addr, chan_y, holder_sk(0xc3), Direction::Initiate, 0x91,
            None, None,
        ));
        let y_acc = tokio::spawn(run_relay_member(
            cert.clone(), addr, chan_y, holder_sk(0xd4), Direction::Accept, 0x92,
            None, None,
        ));
        let got_y_init = y_init.await.expect("y init task");
        let got_y_acc = y_acc.await.expect("y acc task");
        assert_eq!(got_y_init, 0x92, "Y initiator received Y acceptor's byte (Y paired while X held)");
        assert_eq!(got_y_acc, 0x91, "Y acceptor received Y initiator's byte (no cross-channel mis-pair)");

        // Release X and verify its own bytes crossed correctly (X paired with X, not Y).
        let _ = x1_tx.send(());
        let _ = x2_tx.send(());
        let got_x_init = x_init.await.expect("x init task");
        let got_x_acc = x_acc.await.expect("x acc task");
        assert_eq!(got_x_init, 0x02, "X initiator received X acceptor's byte");
        assert_eq!(got_x_acc, 0x01, "X acceptor received X initiator's byte");

        driver.abort();
    }

    /// One rendezvous member for the concurrency test: connect over QUIC, run the admission
    /// handshake, and receive the rendezvous `OK <peer_endpoint>` ack (written only once the
    /// member is PAIRED and its finisher runs). Rendezvous is an endpoint swap, not a data
    /// splice — the member only READS its ack (no stream exchange, so no writer-finish race).
    /// It reports readiness via `on_ready` (proving it paired) and, when `hold` is set, keeps
    /// its connection OPEN until notified — so one channel's rendezvous finisher (blocked in
    /// `conn.closed()`) stays live while another channel races to pair. Returns the ack text.
    async fn run_rendezvous_member(
        cert: rustls::pki_types::CertificateDer<'static>,
        addr: std::net::SocketAddr,
        channel: [u8; 32],
        holder: SigningKey,
        direction: Direction,
        advertised: &'static str,
        on_ready: Option<tokio::sync::mpsc::Sender<()>>,
        hold: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> String {
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, direction, 1_000),
            endpoint: advertised.to_string(),
        };
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = String::from_utf8(present_join(&conn, &req.encode(), &holder).await)
            .unwrap_or_default();
        if let Some(tx) = on_ready {
            let _ = tx.send(()).await; // paired: the OK ack arrived
        }
        if let Some(rx) = hold {
            let _ = rx.await; // keep the rendezvous connection OPEN until released
        }
        // Release: close the connection so the spawned finisher's `conn.closed()` returns.
        conn.close(0u32.into(), b"done");
        ack
    }

    #[tokio::test]
    async fn rendezvous_broker_loop_pairs_two_channels_concurrently_without_wedging() {
        // #120 (frozen): the anti-wedge + correct-correlation property over real QUIC, driving
        // the RENDEZVOUS endpoint with `run_channel_broker_loop` + `finish_rendezvous_pair`.
        // Channel X and channel Y each present an Initiate+Accept member (4 connections). We
        // deterministically pair X FIRST and HOLD its rendezvous connections open — so X's
        // spawned `finish_rendezvous_pair` blocks forever in `conn.closed()` — then race Y in:
        // with the pairer-driven loop that spawns each finisher on its own task, Y still pairs
        // and both Y members get their `OK <peer_endpoint>` ack (anti-wedge, #1) while channel-
        // keying means X and Y never cross-pair (#2). Under the old serial
        // `loop { broker_channel_rendezvous }`, X's held-open `conn.closed()` await would block
        // the accept loop forever and Y would never be admitted — this test would hang. (This is
        // the exact single-slot wedge #109 fixed for the relay, left serial for rendezvous.)
        let pk = operator_pubkey();
        let chan_x = [0x11u8; 32];
        let chan_y = [0x22u8; 32];

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        // Drive the rendezvous endpoint with the concurrent, channel-keyed broker loop, passing
        // the rendezvous completer. Fixed clock + generous park TTL so no waiter is evicted.
        let driver = tokio::spawn(async move {
            run_channel_broker_loop(
                &server,
                || 500u64,
                move |c: ChannelId, _h: [u8; 32]| async move {
                    (c.0 == chan_x || c.0 == chan_y).then_some((pk, None, None))
                },
                10_000,
                |a, b, now| finish_rendezvous_pair(a, b, now),
            )
            .await;
        });

        // Phase 1: pair channel X and HOLD its two rendezvous connections open. A per-member
        // oneshot keeps X's members (and hence X's spawned finisher, blocked in `conn.closed()`)
        // alive until released after Y is done.
        let (x1_tx, x1_rx) = tokio::sync::oneshot::channel::<()>();
        let (x2_tx, x2_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::channel::<()>(2);
        let x_init = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan_x, holder_sk(0xa1), Direction::Initiate, "203.0.113.1:7001",
            Some(ready_tx.clone()), Some(x1_rx),
        ));
        let x_acc = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan_x, holder_sk(0xb2), Direction::Accept, "203.0.113.2:7002",
            Some(ready_tx.clone()), Some(x2_rx),
        ));
        drop(ready_tx);
        // Both X members received their OK ack: X is paired and its finisher is now blocked in
        // `conn.closed()` (held open) BEFORE any Y connection exists.
        ready_rx.recv().await.expect("x member 1 paired");
        ready_rx.recv().await.expect("x member 2 paired");

        // Phase 2: now race channel Y in. If the accept loop were wedged by X's held-open
        // finisher, these would hang; with the pairer-driven loop they pair on a fresh finisher.
        let y_init = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan_y, holder_sk(0xc3), Direction::Initiate, "203.0.113.3:7003",
            None, None,
        ));
        let y_acc = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan_y, holder_sk(0xd4), Direction::Accept, "203.0.113.4:7004",
            None, None,
        ));
        let ack_y_init = y_init.await.expect("y init task");
        let ack_y_acc = y_acc.await.expect("y acc task");
        // Each Y member is admitted+paired and learns the OTHER Y member's endpoint (paired
        // while X was held) — and NEVER an X endpoint (channel-keyed: no cross-pair).
        assert!(ack_y_init.starts_with("OK "), "Y initiator was admitted+paired, got {ack_y_init:?}");
        assert!(ack_y_acc.starts_with("OK "), "Y acceptor was admitted+paired, got {ack_y_acc:?}");
        assert!(ack_y_init.contains("203.0.113.4:7004"), "Y initiator learns Y acceptor's endpoint, got {ack_y_init:?}");
        assert!(ack_y_acc.contains("203.0.113.3:7003"), "Y acceptor learns Y initiator's endpoint, got {ack_y_acc:?}");
        assert!(
            !ack_y_init.contains("7001") && !ack_y_init.contains("7002")
                && !ack_y_acc.contains("7001") && !ack_y_acc.contains("7002"),
            "channel-keyed: no X<->Y cross-pair (Y never learns an X endpoint)",
        );

        // Release X and verify its own acks swapped the X endpoints (X paired with X, not Y).
        let _ = x1_tx.send(());
        let _ = x2_tx.send(());
        let ack_x_init = x_init.await.expect("x init task");
        let ack_x_acc = x_acc.await.expect("x acc task");
        assert!(ack_x_init.contains("203.0.113.2:7002"), "X initiator learns X acceptor's endpoint, got {ack_x_init:?}");
        assert!(ack_x_acc.contains("203.0.113.1:7001"), "X acceptor learns X initiator's endpoint, got {ack_x_acc:?}");

        driver.abort();
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
    async fn finish_relay_pair_over_streams_splices_two_non_quinn_members() {
        // #106 relay-splice-generic (frozen): a `:443`/TLS-TCP member can't be dialed, so
        // rendezvous (direct endpoint exchange) is useless to it — it needs the RELAY.
        // Prove the transport-generic relay finisher works over NON-quinn streams: two
        // members admitted over plain in-memory duplexes are acked `OK` and their data
        // streams spliced end-to-end (the Noise_IK ciphertext would flow exactly this
        // way), with roles decided from the grants — the same completion the quinn
        // `finish_relay_pair` gives, but with no `quinn::Connection` anywhere.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let pk = operator_pubkey();
        let channel = [0x77u8; 32];
        let holder_a = holder_sk(0xa1);
        let holder_b = holder_sk(0xb2);
        let ia = holder_a.verifying_key().to_bytes()[0];
        let ib = holder_b.verifying_key().to_bytes()[0];

        let (mut member_a, broker_a) = tokio::io::duplex(1024);
        let (mut member_b, broker_b) = tokio::io::duplex(1024);
        let a = AdmittedStreamMember {
            stream: broker_a,
            req: ChannelJoinRequest {
                grant: grant_h(channel, &holder_a, Direction::Initiate, 1_000),
                endpoint: "203.0.113.1:7051".to_string(),
            },
            operator: pk,
        };
        let b = AdmittedStreamMember {
            stream: broker_b,
            req: ChannelJoinRequest {
                grant: grant_h(channel, &holder_b, Direction::Accept, 1_000),
                endpoint: "203.0.113.2:7052".to_string(),
            },
            operator: pk,
        };

        let splice = tokio::spawn(async move {
            finish_relay_pair_over_streams(a, b, 500)
                .await
                .map(|p| (p.initiator_holder[0], p.acceptor_holder[0]))
                .map_err(|e| e.to_string())
        });

        // Each member reads its `OK` ack, then the relay carries bytes both ways.
        let mut ok = [0u8; 2];
        member_a.read_exact(&mut ok).await.expect("a ok");
        assert_eq!(&ok, b"OK", "member A is acked OK over its plain stream");
        member_b.read_exact(&mut ok).await.expect("b ok");
        assert_eq!(&ok, b"OK", "member B is acked OK over its plain stream");

        // A -> B through the edge splice (A keeps its stream open, like a Noise msg1).
        member_a.write_all(b"noise-msg1-from-a").await.expect("a writes");
        let mut on_b = [0u8; 17];
        member_b.read_exact(&mut on_b).await.expect("b reads a");
        assert_eq!(&on_b, b"noise-msg1-from-a", "A's ciphertext reaches B via the generic relay");

        // B -> A with the forward leg still open — the reply must not be starved.
        member_b.write_all(b"noise-msg2-from-b").await.expect("b writes");
        let mut on_a = [0u8; 17];
        member_a.read_exact(&mut on_a).await.expect("a reads b");
        assert_eq!(&on_a, b"noise-msg2-from-b", "B's reply reaches A via the generic relay");

        // Both close -> the splice tears down and returns the decided pairing (no hang).
        member_a.shutdown().await.expect("a shutdown");
        member_b.shutdown().await.expect("b shutdown");
        let paired = splice.await.expect("join").expect("paired");
        assert_eq!(paired, (ia, ib), "roles follow the grants, same as the quinn relay finisher");
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
