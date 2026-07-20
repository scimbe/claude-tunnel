//! Agent Fabric — channel addressing and trust-chain grants (ADR-0020, #72).
//!
//! A **Channel** is an opaque agent-to-agent rendezvous point one agent operates
//! and others join; it is addressed by a [`ChannelId`] (no hostname, operator-blind
//! — the same shape as a `RoutingToken`). A **[`ChannelGrant`]** is the trust-chain
//! primitive: a *scoped, directional, expiring* authorization minted by a channel
//! operator for a member — deliberately unlike a flat bearer token where possession
//! equals full access. This module holds the claims, the wire form, and stateless
//! verification; the operator's signing key lives with the operator, mirroring the
//! issuer model of [`crate::credential`]. Time is caller-supplied so it stays
//! deterministic and wall-clock-free.
//!
//! AF2a lands only these primitives (types + sign/verify + wire). The rendezvous
//! transport, the control-plane channel/invitation registry, and connect-time
//! enforcement of the `holder` binding come in later sub-packets (AF2b/AF3/AF4).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Unix timestamp in whole seconds, supplied by the caller.
pub type UnixSeconds = u64;

/// Opaque channel address in the Agent Fabric — like a `RoutingToken`, it reveals
/// no hostname to the operator and decouples "who I want to reach" from any network
/// address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId(pub [u8; 32]);

/// The domain separating a derived per-link channel id from every other hashed object.
const LINK_CHANNEL_DOMAIN: &[u8] = b"ct-link-channel-v1";

/// Derive the deterministic [`ChannelId`] for the A2A link between two members
/// (`holder_a`, `holder_b`) under channel operator `operator_pubkey` (#107-nway). A
/// topology's overlay links (from `min_latency_overlay`/`plan_network_overlay`) each map
/// to a channel the controller mints per-link grants for — and because the id is
/// **derived**, both endpoints compute the *same* `ChannelId` locally from their holder
/// keys with no coordination round-trip.
///
/// It is a domain-separated SHA-256 over `domain || operator_pubkey || min(a,b) ||
/// max(a,b)`, so it is:
/// - **canonical / order-independent** — the two members derive the same id regardless of
///   which they call `a` (the pair is sorted before hashing);
/// - **operator-bound** — binding `operator_pubkey` means two different operators can't
///   collide onto the same channel id for the same holder pair (cross-operator isolation);
/// - **collision-resistant** — distinct holder pairs (or operators) yield distinct ids.
///
/// This is a channel *address* only (like a `RoutingToken`); it authorizes nothing on its
/// own — membership still flows from the operator-signed [`SignedChannelGrant`] the
/// controller issues for this channel to each holder.
pub fn channel_id_for_link(
    operator_pubkey: &[u8; 32],
    holder_a: &[u8; 32],
    holder_b: &[u8; 32],
) -> ChannelId {
    use sha2::{Digest, Sha256};
    // Canonical order so both endpoints hash the same (lo, hi) regardless of their roles.
    let (lo, hi) = if holder_a <= holder_b {
        (holder_a, holder_b)
    } else {
        (holder_b, holder_a)
    };
    let mut h = Sha256::new();
    h.update(LINK_CHANNEL_DOMAIN);
    h.update(operator_pubkey);
    h.update(lo);
    h.update(hi);
    ChannelId(h.finalize().into())
}

/// The direction a grant authorizes on its channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// May open connections to the channel (dial out).
    Initiate,
    /// May accept connections on the channel (the operator/host side).
    Accept,
    /// Both directions.
    Both,
}

impl Direction {
    fn as_byte(self) -> u8 {
        match self {
            Direction::Initiate => 1,
            Direction::Accept => 2,
            Direction::Both => 3,
        }
    }
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Direction::Initiate),
            2 => Some(Direction::Accept),
            3 => Some(Direction::Both),
            _ => None,
        }
    }
    /// Stable label used in the canonical signing bytes.
    fn label(self) -> &'static str {
        match self {
            Direction::Initiate => "initiate",
            Direction::Accept => "accept",
            Direction::Both => "both",
        }
    }
    /// Whether this direction permits `want` (Both permits either).
    pub fn permits(self, want: Direction) -> bool {
        self == Direction::Both || self == want
    }
}

/// The data-exchange rights a grant confers on its channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rights {
    /// Read-only.
    Read,
    /// Write-only.
    Write,
    /// Read and write.
    ReadWrite,
}

impl Rights {
    fn as_byte(self) -> u8 {
        match self {
            Rights::Read => 1,
            Rights::Write => 2,
            Rights::ReadWrite => 3,
        }
    }
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Rights::Read),
            2 => Some(Rights::Write),
            3 => Some(Rights::ReadWrite),
            _ => None,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Rights::Read => "r",
            Rights::Write => "w",
            Rights::ReadWrite => "rw",
        }
    }
    /// Whether these rights include reading.
    pub fn can_read(self) -> bool {
        matches!(self, Rights::Read | Rights::ReadWrite)
    }
    /// Whether these rights include writing.
    pub fn can_write(self) -> bool {
        matches!(self, Rights::Write | Rights::ReadWrite)
    }
}

/// The claims of a channel grant: which channel, bound to which holder, in which
/// direction, with which rights, whether re-delegable, until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelGrant {
    /// The channel this grant is for.
    pub channel: ChannelId,
    /// The member's identity (their static public key) the grant is bound to — a
    /// stolen grant is useless without the matching private key (connect-time
    /// possession proof lands in a later sub-packet).
    pub holder: [u8; 32],
    /// Which direction(s) the holder may use on the channel.
    pub direction: Direction,
    /// The data-exchange rights conferred.
    pub rights: Rights,
    /// Whether the holder may re-delegate (extend the trust chain). A flat bearer
    /// token has no such control; here re-delegation is explicit.
    pub delegable: bool,
    /// Expiry (unix seconds); the grant is invalid at and after this instant.
    pub expires_at: UnixSeconds,
}

impl ChannelGrant {
    /// Canonical bytes covered by the operator signature. Human-auditable and
    /// stable: any change to a field changes these bytes, so a tampered grant
    /// fails verification.
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "ct-grant:v1|{}|{}|{}|{}|{}|{}",
            hex32(&self.channel.0),
            hex32(&self.holder),
            self.direction.label(),
            self.rights.label(),
            self.delegable as u8,
            self.expires_at,
        )
        .into_bytes()
    }
}

/// A channel grant together with the operator's signature over its claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedChannelGrant {
    pub grant: ChannelGrant,
    pub signature: [u8; 64],
}

/// Why grant verification or decoding failed.
#[derive(Debug, PartialEq, Eq)]
pub enum GrantError {
    BadSignature,
    Expired,
    BadKey,
    /// The wire bytes were not a well-formed grant.
    Malformed,
    /// A previously-accepted grant was presented again before its expiry
    /// (#88 SEC88b) — rejected by the replay cache in [`verify_fresh`].
    Replayed,
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantError::BadSignature => write!(f, "channel grant signature invalid"),
            GrantError::Expired => write!(f, "channel grant expired"),
            GrantError::BadKey => write!(f, "operator public key invalid"),
            GrantError::Malformed => write!(f, "channel grant bytes malformed"),
            GrantError::Replayed => write!(f, "channel grant replayed"),
        }
    }
}

impl std::error::Error for GrantError {}

impl SignedChannelGrant {
    /// The exact byte length of [`SignedChannelGrant::encode`]'s output — all
    /// fields are fixed-size, so a grant occupies a fixed prefix on the wire.
    pub const WIRE_LEN: usize = 64 + 32 + 32 + 1 + 1 + 1 + 8; // 139

    /// Encode to a fixed-layout binary wire form (all fields are fixed size):
    /// `signature(64) | channel(32) | holder(32) | direction(1) | rights(1) | delegable(1) | expires_at(u64 LE)`.
    pub fn encode(&self) -> Vec<u8> {
        let g = &self.grant;
        let mut out = Vec::with_capacity(64 + 32 + 32 + 1 + 1 + 1 + 8);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&g.channel.0);
        out.extend_from_slice(&g.holder);
        out.push(g.direction.as_byte());
        out.push(g.rights.as_byte());
        out.push(g.delegable as u8);
        out.extend_from_slice(&g.expires_at.to_le_bytes());
        out
    }

    /// Decode from [`SignedChannelGrant::encode`]'s wire form.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], GrantError> {
            if cur.len() < n {
                return Err(GrantError::Malformed);
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }
        let mut cur = bytes;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(take(&mut cur, 64)?);
        let mut channel = [0u8; 32];
        channel.copy_from_slice(take(&mut cur, 32)?);
        let mut holder = [0u8; 32];
        holder.copy_from_slice(take(&mut cur, 32)?);
        let direction = Direction::from_byte(take(&mut cur, 1)?[0]).ok_or(GrantError::Malformed)?;
        let rights = Rights::from_byte(take(&mut cur, 1)?[0]).ok_or(GrantError::Malformed)?;
        let delegable = match take(&mut cur, 1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(GrantError::Malformed),
        };
        let expires_at = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap());
        if !cur.is_empty() {
            return Err(GrantError::Malformed);
        }
        Ok(SignedChannelGrant {
            grant: ChannelGrant {
                channel: ChannelId(channel),
                holder,
                direction,
                rights,
                delegable,
                expires_at,
            },
            signature,
        })
    }
}

/// The reserved advertised endpoint of a **relay-only** member (#121): a NAT-only host
/// with no globally-routable address that participates purely via the edge relay (plus the
/// #106 `:443` fallback) instead of a direct dial. A member sets `endpoint` to this literal
/// instead of a `host:port` to declare it is not dialable. It is deliberately **not** a
/// parseable [`std::net::SocketAddr`], so [`ChannelJoinRequest::is_relay_only`] is
/// unambiguous and it can never collide with a real endpoint: the edge admits it as an
/// explicit non-dialable marker *without* weakening its private/loopback endpoint filter
/// (#94), and a peer that is paired with such a member skips the wasted direct dial and
/// goes straight to the relay.
pub const CHANNEL_ENDPOINT_RELAY_ONLY: &str = "relay-only";

/// What an agent presents to the edge to join/operate a channel: its signed
/// [`ChannelGrant`] plus the direct endpoint it advertises for the peer to reach it
/// (host:port — the edge brokers the two advertised endpoints, ADR-0015), or the
/// [`CHANNEL_ENDPOINT_RELAY_ONLY`] sentinel for a member that can only be reached via
/// the relay (#121). The channel and holder are inside the grant, so they are not
/// repeated here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelJoinRequest {
    pub grant: SignedChannelGrant,
    pub endpoint: String,
}

impl ChannelJoinRequest {
    /// Whether this join advertises the [`CHANNEL_ENDPOINT_RELAY_ONLY`] sentinel (#121)
    /// rather than a dialable address — a NAT-only member that participates via relay only.
    pub fn is_relay_only(&self) -> bool {
        self.endpoint == CHANNEL_ENDPOINT_RELAY_ONLY
    }

    /// Wire form: the fixed-length grant, then the advertised endpoint as the tail
    /// (`grant(WIRE_LEN) | endpoint(utf8, rest)`). No length prefix is needed — the
    /// grant is fixed-size, so the endpoint is unambiguously the remainder.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.grant.encode();
        out.extend_from_slice(self.endpoint.as_bytes());
        out
    }

    /// Decode from [`ChannelJoinRequest::encode`]. Requires a full grant prefix and
    /// a non-empty, valid-UTF-8 endpoint.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        if bytes.len() <= SignedChannelGrant::WIRE_LEN {
            return Err(GrantError::Malformed);
        }
        let (grant_bytes, endpoint_bytes) = bytes.split_at(SignedChannelGrant::WIRE_LEN);
        let grant = SignedChannelGrant::decode(grant_bytes)?;
        let endpoint = std::str::from_utf8(endpoint_bytes)
            .map_err(|_| GrantError::Malformed)?
            .to_string();
        if endpoint.is_empty() {
            return Err(GrantError::Malformed);
        }
        Ok(ChannelJoinRequest { grant, endpoint })
    }
}

/// Whether `addr` is a **global-unicast** socket address — a real, publicly-routable
/// host a peer can dial (#121). The single source of truth for "is this reachable from
/// the outside": it rejects loopback, unspecified, and multicast, plus every private /
/// internal range a NAT hides behind — RFC1918, link-local (`169.254/16`, `fe80::/10`),
/// shared/CGNAT (`100.64/10`), and IPv6 unique-local (`fc00::/7`). Only a global-unicast
/// address returns `true`. `ct_edge`'s `safe_endpoint` admission filter is defined in
/// terms of this helper, so the reachability classifier and the edge's SSRF filter agree
/// by construction on exactly which addresses count as externally reachable.
pub fn is_global_unicast(addr: std::net::SocketAddr) -> bool {
    use std::net::IpAddr;
    let ip = addr.ip();
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            // RFC1918 private + link-local (169.254/16) + shared/CGNAT (100.64/10).
            if v4.is_private() || v4.is_link_local() {
                return false;
            }
            let o = v4.octets();
            if o[0] == 100 && (64..=127).contains(&o[1]) {
                return false; // 100.64.0.0/10
            }
            true
        }
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            if (s0 & 0xfe00) == 0xfc00 {
                return false; // unique-local fc00::/7
            }
            if (s0 & 0xffc0) == 0xfe80 {
                return false; // link-local fe80::/10
            }
            true
        }
    }
}

/// How a channel member can be reached, classified from what it **advertised** and the
/// **reflexive** (post-NAT) source address the edge observed on its already-authenticated
/// join connection (#121 Phase B1 — the AutoNAT analog). This is the input the later
/// hole-punch (B2) punches toward and the superpeer election (Phase C) classifies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    /// The advertised address is global-unicast **and** equals the reflexive address:
    /// the member is directly reachable with no NAT rewrite (a public host).
    Public,
    /// The member is behind a NAT (it advertised a private/loopback address or the
    /// relay-only sentinel), but its reflexive address is global-unicast — so it is
    /// punchable at that reflexive address.
    Nat { reflexive: std::net::SocketAddr },
    /// No usable reflexive: the edge-observed source is itself private/loopback, so the
    /// member is behind symmetric / CGNAT double-NAT and is reachable only via the relay.
    RelayOnly,
}

/// Classify a member's reachability from its `advertised` endpoint string and the
/// `reflexive` address the edge observed on its authenticated join (#121 Phase B1).
/// Pure — no I/O. See [`Reachability`]:
/// - a non-global-unicast reflexive → [`Reachability::RelayOnly`] (symmetric/CGNAT);
/// - a global-unicast reflexive that the member also advertised verbatim →
///   [`Reachability::Public`] (no NAT rewrite);
/// - otherwise (private/loopback or relay-only advertised, but a global-unicast
///   reflexive) → [`Reachability::Nat`], punchable at the reflexive address.
pub fn reachability_class(advertised: &str, reflexive: std::net::SocketAddr) -> Reachability {
    // The edge saw a private/loopback source: symmetric/CGNAT double-NAT — relay only,
    // there is no reflexive address a peer could punch toward.
    if !is_global_unicast(reflexive) {
        return Reachability::RelayOnly;
    }
    // The reflexive is globally routable. If the member advertised that exact global
    // address it is a directly-reachable public host; otherwise it is NAT'd but punchable
    // at the reflexive (a private/loopback or relay-only advertised address never parses
    // to a global-unicast match, so it always falls through to `Nat`).
    if advertised
        .parse::<std::net::SocketAddr>()
        .ok()
        .filter(|a| is_global_unicast(*a))
        == Some(reflexive)
    {
        return Reachability::Public;
    }
    Reachability::Nat { reflexive }
}

/// Verify a signed grant against the channel `operator_pubkey` at time `now`.
/// Confirms the operator signature over the claims and that the grant has not
/// expired. Does NOT check holder possession — that is a connect-time proof in a
/// later sub-packet; this establishes the grant is authentic and current.
pub fn verify(
    operator_pubkey: &[u8; 32],
    signed: &SignedChannelGrant,
    now: UnixSeconds,
) -> Result<(), GrantError> {
    let vk = VerifyingKey::from_bytes(operator_pubkey).map_err(|_| GrantError::BadKey)?;
    let sig = Signature::from_bytes(&signed.signature);
    vk.verify(&signed.grant.signing_bytes(), &sig)
        .map_err(|_| GrantError::BadSignature)?;
    if now >= signed.grant.expires_at {
        return Err(GrantError::Expired);
    }
    Ok(())
}

/// Like [`verify`], but additionally rejects a **replay** (#88 SEC88b). A captured
/// grant is otherwise valid until `expires_at` *any number of times*; `cache` records
/// the grant's 64-byte signature (unique per grant — a replay carries the identical
/// bytes) until that expiry, so the first presentation of an authentic, unexpired
/// grant succeeds and any later presentation of the same signature fails with
/// [`GrantError::Replayed`]. Call this at the single admission point (the broker) that
/// owns `cache`; the cache evicts on expiry so it stays bounded. Signature/expiry are
/// checked first, so an invalid or expired grant never populates the cache. This is
/// orthogonal to holder-possession (#81) and membership/revocation — all three gate
/// admission together.
pub fn verify_fresh(
    operator_pubkey: &[u8; 32],
    signed: &SignedChannelGrant,
    now: UnixSeconds,
    cache: &mut crate::replay::ReplayCache,
) -> Result<(), GrantError> {
    verify(operator_pubkey, signed, now)?;
    if !cache.check_and_record(&signed.signature, signed.grant.expires_at, now) {
        return Err(GrantError::Replayed);
    }
    Ok(())
}

/// Verify a holder's **proof of possession** (#81 gap 1): `signature` must be the
/// holder's ed25519 signature over the edge-issued `challenge`. This closes "stolen
/// grant = bearer token" — presenting a valid [`SignedChannelGrant`] is not enough;
/// the presenter must also prove it holds the private key matching the grant's
/// `holder` public key by signing a fresh, single-use challenge the edge picks. The
/// caller pairs this with the grant/membership checks at the admission gate. Returns
/// `false` on a non-key `holder`, a bad signature, or a challenge mismatch.
pub fn verify_holder_possession(holder: &[u8; 32], challenge: &[u8], signature: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(holder) {
        Ok(vk) => vk.verify(challenge, &Signature::from_bytes(signature)).is_ok(),
        Err(_) => false,
    }
}

/// The domain-separated message a member signs with its **holder** key to attest that
/// it authorized `noise_pubkey` as its Noise static key on `channel` (#72 AF4-keydist /
/// #101). Binding the Noise key to `(channel, holder)` means a DB-controlling operator
/// can't substitute a key to MITM the A2A direct path — a substituted key carries no
/// valid holder signature. The agent signs this with its holder `SigningKey`; peers
/// verify with [`verify_member_noise_attestation`] before pinning the key.
pub fn member_noise_attest_bytes(
    channel: &ChannelId,
    holder: &[u8; 32],
    noise_pubkey: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(22 + 32 + 32 + 32);
    m.extend_from_slice(b"ct-a2a-noise-attest-v1");
    m.extend_from_slice(&channel.0);
    m.extend_from_slice(holder);
    m.extend_from_slice(noise_pubkey);
    m
}

/// Verify a member Noise-key attestation (#101): `signature` must be `holder`'s
/// ed25519 signature over [`member_noise_attest_bytes`]. Returns `false` on a bad key,
/// a wrong `(channel, holder, noise_pubkey)` binding, or a bad signature — so an
/// un-attested or operator-substituted Noise key is rejected before an initiator pins
/// it for the direct-path `Noise_IK` handshake.
pub fn verify_member_noise_attestation(
    channel: &ChannelId,
    holder: &[u8; 32],
    noise_pubkey: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    match VerifyingKey::from_bytes(holder) {
        Ok(vk) => vk
            .verify(
                &member_noise_attest_bytes(channel, holder, noise_pubkey),
                &Signature::from_bytes(signature),
            )
            .is_ok(),
        Err(_) => false,
    }
}

/// The domain separating a membership-staple preimage from every other signed object.
const MEMBERSHIP_STAPLE_DOMAIN: &[u8] = b"ct-membership-staple-v1";

/// A soft-state **membership staple** (E-fail-static, invariant #7): the operator's
/// short-lived, signed assertion that `holder` is *currently* a member of `channel`,
/// valid only until `expires_at`. Unlike a [`SignedChannelGrant`] — a long-lived
/// capability — a staple is refreshed continuously (gossiped) while central is reachable
/// and **cached locally**, so if central goes away existing channels keep admitting their
/// known members until the cached staple's TTL lapses: **fail-static, never fail-closed.**
/// Because it expires, revocation needs no central round-trip either — stop refreshing a
/// revoked member and its cached staple dies within one TTL (invariant #7: revocation
/// latency = staple TTL; proposed default 1h staple / 15m gossip refresh).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipStaple {
    pub channel: ChannelId,
    pub holder: [u8; 32],
    /// When the operator minted this staple.
    pub stapled_at: UnixSeconds,
    /// When it lapses (`stapled_at + staple_ttl`). After this the staple is dead; a reader
    /// must fall back to a fresher staple or refuse — this bounds the fail-static window.
    pub expires_at: UnixSeconds,
    /// The operator's ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    pub signature: [u8; 64],
}

impl MembershipStaple {
    /// The domain-separated preimage the operator signs: `domain || channel || holder ||
    /// stapled_at || expires_at`. Binding **every** field means a staple can't be replayed
    /// onto another `(channel, holder)` and its TTL can't be extended without re-signing.
    pub fn signing_bytes(
        channel: &ChannelId,
        holder: &[u8; 32],
        stapled_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Vec<u8> {
        let mut m = Vec::with_capacity(MEMBERSHIP_STAPLE_DOMAIN.len() + 32 + 32 + 8 + 8);
        m.extend_from_slice(MEMBERSHIP_STAPLE_DOMAIN);
        m.extend_from_slice(&channel.0);
        m.extend_from_slice(holder);
        m.extend_from_slice(&stapled_at.to_le_bytes());
        m.extend_from_slice(&expires_at.to_le_bytes());
        m
    }

    /// Whether this staple is authentic **and** still fresh at `now`: the operator
    /// signature verifies for its exact `(channel, holder, stapled_at, expires_at)` binding
    /// and `now < expires_at`. A forged staple (wrong operator key), any tampered field, or
    /// a lapsed staple all return `false` — the single gate fail-static admission consults.
    pub fn is_valid(&self, operator_pubkey: &[u8; 32], now: UnixSeconds) -> bool {
        if now >= self.expires_at {
            return false;
        }
        match VerifyingKey::from_bytes(operator_pubkey) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(
                        &self.channel,
                        &self.holder,
                        self.stapled_at,
                        self.expires_at,
                    ),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    /// The exact byte length of [`encode`](Self::encode)'s output — every field is
    /// fixed-size, so a staple occupies a fixed 144-byte record on the wire (the unit the
    /// gossip transport ships/refreshes).
    pub const WIRE_LEN: usize = 64 + 32 + 32 + 8 + 8; // 144

    /// Encode to a fixed-layout binary wire form (all fields fixed size):
    /// `signature(64) | channel(32) | holder(32) | stapled_at(u64 LE) | expires_at(u64 LE)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.channel.0);
        out.extend_from_slice(&self.holder);
        out.extend_from_slice(&self.stapled_at.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out
    }

    /// Decode from [`encode`](Self::encode)'s wire form. Rejects a truncated or
    /// over-long buffer as [`GrantError::Malformed`] (a partial staple is never
    /// half-trusted). Decoding does NOT authenticate — the caller still gates on
    /// [`is_valid`](Self::is_valid); a well-formed record can still be forged or lapsed.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], GrantError> {
            if cur.len() < n {
                return Err(GrantError::Malformed);
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }
        let mut cur = bytes;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(take(&mut cur, 64)?);
        let mut channel = [0u8; 32];
        channel.copy_from_slice(take(&mut cur, 32)?);
        let mut holder = [0u8; 32];
        holder.copy_from_slice(take(&mut cur, 32)?);
        let stapled_at = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap());
        let expires_at = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap());
        if !cur.is_empty() {
            return Err(GrantError::Malformed);
        }
        Ok(MembershipStaple {
            channel: ChannelId(channel),
            holder,
            stapled_at,
            expires_at,
            signature,
        })
    }
}

/// A channel's **staple admission policy** (#121 E-fail-static, option A — *staple-optional*,
/// maintainer decision 2026-07-20). A channel opts into TTL-bounded revocation; those that
/// don't are unaffected. Consumed by [`StapleCache::admits_under_policy`], always *after* the
/// operator-grant check — enabling staples can only *add* a freshness requirement, never
/// weaken the existing grant-based admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChannelAdmissionPolicy {
    /// Grant-only admission — today's behaviour and the default: a valid operator-signed
    /// grant is sufficient. Channels that don't opt into staples use this.
    #[default]
    Open,
    /// The member must also present a fresh cached [`MembershipStaple`], so revocation
    /// propagates within the staple TTL (invariant #7).
    RequireStaple,
}

/// A soft-state cache of the freshest [`MembershipStaple`] per `(channel, holder)` — the
/// local memory that lets a node keep admitting known members while central is unreachable
/// (E-fail-static). Gossip/refresh feeds [`refresh`](Self::refresh); admission consults
/// [`is_member`](Self::is_member). Keeping only the **latest-expiring** staple means a
/// stale/out-of-order gossip can never SHORTEN a member's validity, and a revoked member
/// simply stops being refreshed so its entry lapses within one TTL (invariant #7).
#[derive(Debug, Default)]
pub struct StapleCache {
    fresh: std::collections::HashMap<([u8; 32], [u8; 32]), MembershipStaple>,
}

impl StapleCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a staple (from gossip or a direct refresh). It is verified against
    /// `operator_pubkey` at `now` **first** — an invalid or already-lapsed staple is
    /// ignored, never cached. The entry with the later `expires_at` wins, so out-of-order
    /// gossip can't regress validity. Returns whether the cache now holds this (or an
    /// already-fresher) staple for the pair.
    pub fn refresh(
        &mut self,
        operator_pubkey: &[u8; 32],
        staple: MembershipStaple,
        now: UnixSeconds,
    ) -> bool {
        if !staple.is_valid(operator_pubkey, now) {
            return false;
        }
        let key = (staple.channel.0, staple.holder);
        match self.fresh.get(&key) {
            // An existing staple that lasts at least as long already dominates — keep it.
            Some(existing) if existing.expires_at >= staple.expires_at => true,
            _ => {
                self.fresh.insert(key, staple);
                true
            }
        }
    }

    /// Fail-static admission input: is `holder` a currently-stapled member of `channel` at
    /// `now`? True iff a cached staple for the pair still verifies against `operator_pubkey`
    /// and has not lapsed — with **no central round-trip**, which is the whole point:
    /// existing channels survive a central outage until the TTL. A lapsed entry returns
    /// `false` and is evicted, so a revoked (no-longer-refreshed) member is gone within one
    /// TTL (invariant #7).
    pub fn is_member(
        &mut self,
        operator_pubkey: &[u8; 32],
        channel: &ChannelId,
        holder: &[u8; 32],
        now: UnixSeconds,
    ) -> bool {
        let key = (channel.0, *holder);
        match self.fresh.get(&key) {
            Some(s) if s.is_valid(operator_pubkey, now) => true,
            Some(_) => {
                self.fresh.remove(&key); // lapsed — drop it so the map stays bounded
                false
            }
            None => false,
        }
    }

    /// Compose the channel's **staple admission policy** on top of an already grant-verified
    /// member (#121 E-fail-static, option A — *staple-optional*, maintainer decision
    /// 2026-07-20). The caller has already verified the operator-signed grant (and possession)
    /// exactly as today; this adds the staple requirement **only when the channel opted in**:
    /// - [`ChannelAdmissionPolicy::Open`] → always `true`: grant-only admission, byte-for-byte
    ///   today's behaviour and the default, so nothing changes for channels that don't opt in;
    /// - [`ChannelAdmissionPolicy::RequireStaple`] → `true` iff a fresh, unexpired,
    ///   operator-signed staple is cached for `(channel, holder)` (delegates to
    ///   [`is_member`](Self::is_member)), so revocation propagates within the staple TTL
    ///   (invariant #7).
    ///
    /// This is the single tested chokepoint the edge broker consults *after* its grant check,
    /// so enabling staples on a channel can never *weaken* admission (a valid grant is still
    /// required) — it can only add the freshness requirement.
    pub fn admits_under_policy(
        &mut self,
        policy: ChannelAdmissionPolicy,
        operator_pubkey: &[u8; 32],
        channel: &ChannelId,
        holder: &[u8; 32],
        now: UnixSeconds,
    ) -> bool {
        match policy {
            ChannelAdmissionPolicy::Open => true,
            ChannelAdmissionPolicy::RequireStaple => {
                self.is_member(operator_pubkey, channel, holder, now)
            }
        }
    }
}

/// The domain separating a billing-commitment preimage from every other signed object.
const BILLING_COMMITMENT_DOMAIN: &[u8] = b"ct-billing-commitment-v1";

/// An **optional, agent-verifiable A2A billing coupling** for a channel (#132). It does **not**
/// move funds — settlement stays external (the classic tunnel-token billing lives in
/// `ct-control-plane::billing`; multi-hop path-transit *receipts* are a #121 follow) — it is
/// the cryptographic commitment a member can **require and verify at channel setup**: the
/// committing (paying) `holder` commits, for `channel`, to the off-band billing `terms_hash`,
/// payable to `payee`, up to `max_amount` (opaque units), until `expires_at`, signed with its
/// ed25519 **holder** key (the same key family as grants/attestations). The peer verifies it
/// against that holder pubkey before proceeding. **Opt-in**: a channel that doesn't require
/// billing never uses it — exactly like [`ChannelAdmissionPolicy`], so the core tunnel stays
/// payment-free and this can never *weaken* admission (it only adds a requirement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingCommitment {
    pub channel: ChannelId,
    /// The committing (paying) member — the signature is checked against this holder pubkey.
    pub holder: [u8; 32],
    /// The settlement payee identity (opaque; a settlement pubkey/handle the external layer resolves).
    pub payee: [u8; 32],
    /// Hash of the off-band billing terms (price/unit, currency, metering rule …) — the terms
    /// themselves stay out-of-band; only their hash is committed on the wire.
    pub terms_hash: [u8; 32],
    /// The upper bound (opaque units) the payer commits to for this channel/session.
    pub max_amount: u64,
    pub expires_at: UnixSeconds,
    /// The holder's ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    pub signature: [u8; 64],
}

impl BillingCommitment {
    /// Domain-separated preimage: `domain ‖ channel ‖ holder ‖ payee ‖ terms_hash ‖
    /// max_amount(LE) ‖ expires_at(LE)`. Binding every field means the commitment can't be
    /// replayed onto another channel/payee nor have its amount/terms/TTL altered without
    /// re-signing.
    pub fn signing_bytes(
        channel: &ChannelId,
        holder: &[u8; 32],
        payee: &[u8; 32],
        terms_hash: &[u8; 32],
        max_amount: u64,
        expires_at: UnixSeconds,
    ) -> Vec<u8> {
        let mut m = Vec::with_capacity(BILLING_COMMITMENT_DOMAIN.len() + 32 * 4 + 8 + 8);
        m.extend_from_slice(BILLING_COMMITMENT_DOMAIN);
        m.extend_from_slice(&channel.0);
        m.extend_from_slice(holder);
        m.extend_from_slice(payee);
        m.extend_from_slice(terms_hash);
        m.extend_from_slice(&max_amount.to_le_bytes());
        m.extend_from_slice(&expires_at.to_le_bytes());
        m
    }

    /// Whether this commitment is authentic AND still current at `now`: the holder signature
    /// verifies for its exact `(channel, holder, payee, terms_hash, max_amount, expires_at)`
    /// binding and `now < expires_at`. A forged/tampered/expired commitment returns `false`.
    pub fn is_valid(&self, now: UnixSeconds) -> bool {
        if now >= self.expires_at {
            return false;
        }
        match VerifyingKey::from_bytes(&self.holder) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(
                        &self.channel,
                        &self.holder,
                        &self.payee,
                        &self.terms_hash,
                        self.max_amount,
                        self.expires_at,
                    ),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    /// The **requiring agent's setup gate**: does this commitment authentically cover what the
    /// requirer demands — signed + unexpired ([`is_valid`](Self::is_valid)), for the expected
    /// `required_payee` and `required_terms_hash`, with a `max_amount` of at least `min_amount`?
    /// A channel that requires billing calls this at setup; `false` refuses the tunnel.
    pub fn satisfies(
        &self,
        now: UnixSeconds,
        required_payee: &[u8; 32],
        required_terms_hash: &[u8; 32],
        min_amount: u64,
    ) -> bool {
        self.is_valid(now)
            && &self.payee == required_payee
            && &self.terms_hash == required_terms_hash
            && self.max_amount >= min_amount
    }
}

/// The domain separating a settle-receipt preimage from every other signed object.
const SETTLE_RECEIPT_DOMAIN: &[u8] = b"ct-settle-receipt-v1";

/// A rolling digest over an A2A transfer's application byte stream (#132 SR1 — the `settle` step of
/// `quote → approve → settle`). Both peers fold the SAME plaintext bytes through it as they pump; at
/// close the **receiver** signs its finalized digest into a [`SettleReceipt`] and the sender/
/// verifier compares against its own — so "delivered" is *witnessed by the receiver*, never merely
/// asserted by the send side. sha2 is already a dependency; folding one hash update per pumped chunk
/// costs no extra round-trips.
#[derive(Clone)]
pub struct TransferDigest {
    hasher: sha2::Sha256,
    bytes: u64,
}

impl Default for TransferDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferDigest {
    pub fn new() -> Self {
        use sha2::Digest;
        Self { hasher: sha2::Sha256::new(), bytes: 0 }
    }

    /// Fold the next chunk of delivered application plaintext into the digest.
    pub fn update(&mut self, chunk: &[u8]) {
        use sha2::Digest;
        self.hasher.update(chunk);
        self.bytes += chunk.len() as u64;
    }

    /// Application bytes folded so far.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The digest of the stream folded so far (clones the hasher — does not consume it).
    pub fn digest(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.hasher.clone().finalize());
        out
    }
}

/// A **receiver-attested transfer receipt** for an A2A session (#132 SR1 — the `settle` step). The
/// **receiver** signs, with its ed25519 holder key, a digest over the application bytes it actually
/// received ([`TransferDigest`]), bound to the `channel`, the approve-time billing `terms_hash`
/// (from the [`BillingCommitment`]), and a per-session `session_nonce` — so the receipt cannot be
/// replayed onto another session, channel, or terms. It moves **no funds**: external settlement
/// consumes it; the tunnel only PRODUCES the verifiable proof-of-delivery. The sender/verifier
/// checks it against its OWN [`TransferDigest`], so the receiver can neither under-report nor forge
/// what was delivered — this is what defeats *ambient send-side trust*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleReceipt {
    pub channel: ChannelId,
    /// The attesting (delivered-to) member; the signature is checked against this holder pubkey.
    pub receiver: [u8; 32],
    /// The approve-time billing terms this delivery settles against (ties the receipt to the coupling).
    pub terms_hash: [u8; 32],
    /// Per-session binding (a fresh nonce agreed at setup) — prevents cross-session/channel replay.
    pub session_nonce: [u8; 32],
    /// Application bytes the receiver attests it received.
    pub bytes_delivered: u64,
    /// Digest over those delivered bytes ([`TransferDigest::digest`]).
    pub transfer_digest: [u8; 32],
    /// The receiver's ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    pub signature: [u8; 64],
}

impl SettleReceipt {
    /// Domain-separated preimage: `domain ‖ channel ‖ receiver ‖ terms_hash ‖ session_nonce ‖
    /// bytes_delivered(LE) ‖ transfer_digest`. Binding every field means a receipt can't be
    /// replayed onto another channel/session/terms nor have its byte count or digest altered
    /// without re-signing (which only the receiver's holder key can do).
    pub fn signing_bytes(
        channel: &ChannelId,
        receiver: &[u8; 32],
        terms_hash: &[u8; 32],
        session_nonce: &[u8; 32],
        bytes_delivered: u64,
        transfer_digest: &[u8; 32],
    ) -> Vec<u8> {
        let mut m = Vec::with_capacity(SETTLE_RECEIPT_DOMAIN.len() + 32 * 4 + 8);
        m.extend_from_slice(SETTLE_RECEIPT_DOMAIN);
        m.extend_from_slice(&channel.0);
        m.extend_from_slice(receiver);
        m.extend_from_slice(terms_hash);
        m.extend_from_slice(session_nonce);
        m.extend_from_slice(&bytes_delivered.to_le_bytes());
        m.extend_from_slice(transfer_digest);
        m
    }

    /// Whether the receipt is authentic: the receiver signature verifies for its exact binding. A
    /// forged/tampered receipt returns `false`.
    pub fn is_valid(&self) -> bool {
        match VerifyingKey::from_bytes(&self.receiver) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(
                        &self.channel,
                        &self.receiver,
                        &self.terms_hash,
                        &self.session_nonce,
                        self.bytes_delivered,
                        &self.transfer_digest,
                    ),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    /// The **sender/verifier's settle gate**: the receipt is authentic AND attests delivery of what
    /// we actually sent — same `channel`, the expected `terms_hash` and `session_nonce`, at least
    /// `min_bytes`, and a `transfer_digest` byte-equal to our own [`TransferDigest::digest`]. A
    /// truncated, tampered, or forged delivery claim → `false`. Only a receipt the RECEIVER signed
    /// over the true delivered bytes passes — no send-side assertion can.
    pub fn confirms_delivery(
        &self,
        expected_channel: &ChannelId,
        expected_terms_hash: &[u8; 32],
        expected_session_nonce: &[u8; 32],
        min_bytes: u64,
        sender_digest: &[u8; 32],
    ) -> bool {
        self.is_valid()
            && &self.channel == expected_channel
            && &self.terms_hash == expected_terms_hash
            && &self.session_nonce == expected_session_nonce
            && self.bytes_delivered >= min_bytes
            && &self.transfer_digest == sender_digest
    }
}

/// A **cross-user channel invitation** (#72 AF3): the operator invites a specific
/// *invitee identity* (another user's agent) to join a channel, **without yet knowing**
/// the member (holder) key that agent will use. The invitee's agent redeems it — proving
/// it holds the invitee identity key and choosing a holder key (see
/// [`invitation_redeem_bytes`]) — after which the operator/CP issues the real per-holder
/// [`SignedChannelGrant`]. Distinct from *sharing*: an invitation crosses users and is
/// meant to be redeemed **once** into a scoped membership. The invitation object itself is
/// stateless (a signed token with a static redemption proof), so single-use is **not**
/// self-enforcing — the redeeming CP MUST record consumption (keyed by the operator
/// signature) and reject a replay, exactly as `verify_fresh`/`ReplayCache` do for grants
/// (#88 SEC88b). Without that, a **revoked** member could replay the identical redemption
/// to restore membership until expiry (#108). Same claim shape as [`ChannelGrant`], but
/// bound to the invitee's *identity* key rather than a member key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelInvitation {
    /// The channel the invitee is invited to.
    pub channel: ChannelId,
    /// The invited user's agent **identity** public key — the invitee proves possession
    /// of the matching private key at redemption, so only the intended user can accept.
    pub invitee_identity: [u8; 32],
    /// The direction(s) the resulting membership will confer.
    pub direction: Direction,
    /// The data-exchange rights the resulting membership will confer.
    pub rights: Rights,
    /// Whether the resulting membership may re-delegate.
    pub delegable: bool,
    /// Expiry (unix seconds); the invitation is invalid at and after this instant.
    pub expires_at: UnixSeconds,
}

impl ChannelInvitation {
    /// Canonical bytes the operator signs — domain-separated from a grant so an
    /// invitation can never be mistaken for (or replayed as) a grant.
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "ct-chan-invite:v1|{}|{}|{}|{}|{}|{}",
            hex32(&self.channel.0),
            hex32(&self.invitee_identity),
            self.direction.label(),
            self.rights.label(),
            self.delegable as u8,
            self.expires_at,
        )
        .into_bytes()
    }
}

/// A channel invitation together with the operator's signature over its claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedChannelInvitation {
    pub invitation: ChannelInvitation,
    pub signature: [u8; 64],
}

impl SignedChannelInvitation {
    /// Fixed wire length — every field is fixed-size (mirrors [`SignedChannelGrant`]).
    pub const WIRE_LEN: usize = 64 + 32 + 32 + 1 + 1 + 1 + 8; // 139

    /// Encode to a fixed-layout binary wire form:
    /// `signature(64) | channel(32) | invitee_identity(32) | direction(1) | rights(1) | delegable(1) | expires_at(u64 LE)`.
    pub fn encode(&self) -> Vec<u8> {
        let i = &self.invitation;
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&i.channel.0);
        out.extend_from_slice(&i.invitee_identity);
        out.push(i.direction.as_byte());
        out.push(i.rights.as_byte());
        out.push(i.delegable as u8);
        out.extend_from_slice(&i.expires_at.to_le_bytes());
        out
    }

    /// Decode from [`SignedChannelInvitation::encode`]'s wire form.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], GrantError> {
            if cur.len() < n {
                return Err(GrantError::Malformed);
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }
        let mut cur = bytes;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(take(&mut cur, 64)?);
        let mut channel = [0u8; 32];
        channel.copy_from_slice(take(&mut cur, 32)?);
        let mut invitee_identity = [0u8; 32];
        invitee_identity.copy_from_slice(take(&mut cur, 32)?);
        let direction = Direction::from_byte(take(&mut cur, 1)?[0]).ok_or(GrantError::Malformed)?;
        let rights = Rights::from_byte(take(&mut cur, 1)?[0]).ok_or(GrantError::Malformed)?;
        let delegable = match take(&mut cur, 1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(GrantError::Malformed),
        };
        let expires_at = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap());
        if !cur.is_empty() {
            return Err(GrantError::Malformed);
        }
        Ok(SignedChannelInvitation {
            invitation: ChannelInvitation {
                channel: ChannelId(channel),
                invitee_identity,
                direction,
                rights,
                delegable,
                expires_at,
            },
            signature,
        })
    }
}

/// Verify a signed invitation against the channel `operator_pubkey` at time `now`
/// (mirrors [`verify`]): confirms the operator signature over the claims and that the
/// invitation has not expired. Does NOT check the invitee's acceptance — that is the
/// redemption proof ([`verify_invitation_redemption`]); this establishes the invitation
/// is authentic and current.
pub fn verify_invitation(
    operator_pubkey: &[u8; 32],
    signed: &SignedChannelInvitation,
    now: UnixSeconds,
) -> Result<(), GrantError> {
    let vk = VerifyingKey::from_bytes(operator_pubkey).map_err(|_| GrantError::BadKey)?;
    let sig = Signature::from_bytes(&signed.signature);
    vk.verify(&signed.invitation.signing_bytes(), &sig)
        .map_err(|_| GrantError::BadSignature)?;
    if now >= signed.invitation.expires_at {
        return Err(GrantError::Expired);
    }
    Ok(())
}

/// The domain-separated message the invitee signs with its **identity** key to redeem an
/// invitation (#72 AF3), binding the member `holder` key it will use on the channel.
/// Signing this proves two things at once: the intended invitee (only it holds the
/// identity private key) accepted, and it chose `holder` — so the operator/CP can then
/// issue a [`SignedChannelGrant`] for `holder` knowing the right user asked for it. The
/// binding to `(channel, invitee_identity, holder)` stops a captured invitation from
/// being redeemed to a different key or channel.
pub fn invitation_redeem_bytes(
    channel: &ChannelId,
    invitee_identity: &[u8; 32],
    holder: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(24 + 32 + 32 + 32);
    m.extend_from_slice(b"ct-chan-invite-redeem-v1");
    m.extend_from_slice(&channel.0);
    m.extend_from_slice(invitee_identity);
    m.extend_from_slice(holder);
    m
}

/// Verify an invitation redemption (#72 AF3): `signature` must be `invitee_identity`'s
/// ed25519 signature over [`invitation_redeem_bytes`]. Returns `false` on a bad key, a
/// wrong `(channel, invitee_identity, holder)` binding, or a bad signature — so only the
/// intended invitee can accept, and only into the holder key it actually chose.
pub fn verify_invitation_redemption(
    channel: &ChannelId,
    invitee_identity: &[u8; 32],
    holder: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    match VerifyingKey::from_bytes(invitee_identity) {
        Ok(vk) => vk
            .verify(
                &invitation_redeem_bytes(channel, invitee_identity, holder),
                &Signature::from_bytes(signature),
            )
            .is_ok(),
        Err(_) => false,
    }
}

/// The domain-separated message the invitee signs to redeem an invitation **against a
/// fresh, single-use CP challenge** (#108 defense-in-depth): like
/// [`invitation_redeem_bytes`] but also binding the `challenge` nonce the CP issued for
/// this redemption. Because the nonce is fresh and consumed at the CP, a captured
/// redemption signature is non-replayable **independent of** the single-use invitation
/// consumption — belt-and-braces over the [`redeem_invitation`] path. Domain `v2` keeps
/// it distinct from the static `v1` bytes so one can never be presented as the other.
pub fn invitation_redeem_challenge_bytes(
    channel: &ChannelId,
    invitee_identity: &[u8; 32],
    holder: &[u8; 32],
    challenge: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(27 + 32 + 32 + 32 + 32);
    m.extend_from_slice(b"ct-chan-invite-redeem-v2-chal");
    m.extend_from_slice(&channel.0);
    m.extend_from_slice(invitee_identity);
    m.extend_from_slice(holder);
    m.extend_from_slice(challenge);
    m
}

/// Verify a challenge-bound invitation redemption (#108): `signature` must be
/// `invitee_identity`'s ed25519 signature over [`invitation_redeem_challenge_bytes`].
/// Returns `false` on a bad key, a wrong `(channel, invitee_identity, holder, challenge)`
/// binding, or a bad signature — so a redemption signed for one fresh challenge can't be
/// replayed against another.
pub fn verify_invitation_redemption_challenge(
    channel: &ChannelId,
    invitee_identity: &[u8; 32],
    holder: &[u8; 32],
    challenge: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    match VerifyingKey::from_bytes(invitee_identity) {
        Ok(vk) => vk
            .verify(
                &invitation_redeem_challenge_bytes(channel, invitee_identity, holder, challenge),
                &Signature::from_bytes(signature),
            )
            .is_ok(),
        Err(_) => false,
    }
}

/// Verify a cross-user invitation **redemption end-to-end** (#72 AF3) and, on success,
/// return the membership claims the invitee earned. This is the two-proof gate the CP
/// runs when an invitee's agent presents a redemption:
///
/// 1. the operator invitation is authentic + current ([`verify_invitation`]), and
/// 2. the intended invitee accepted and bound `holder` ([`verify_invitation_redemption`]).
///
/// On success it returns the invitation's channel/direction/rights/delegable/expiry now
/// bound to the invitee's chosen `holder` — exactly the [`ChannelGrant`] claims the CP
/// records as membership. **No operator private key is needed at redeem time**: the
/// operator authority already rides in the signed invitation, so a provider-blind CP can
/// admit the member from the two public-key proofs alone. Errors mirror
/// [`verify`]: `BadKey`/`BadSignature`/`Expired` (a failed redemption proof surfaces as
/// `BadSignature`).
///
/// This is **pure verification** — like [`verify`] vs [`verify_fresh`], it does NOT
/// enforce single-use. The caller MUST record consumption of the invitation (by its
/// operator signature) and reject a replay, or a revoked member can replay this to
/// restore membership until expiry (#108). The live redeem endpoint does so via
/// `SqliteChannelStore::consume_invitation`.
pub fn redeem_invitation(
    operator_pubkey: &[u8; 32],
    signed: &SignedChannelInvitation,
    redeem_signature: &[u8; 64],
    holder: &[u8; 32],
    now: UnixSeconds,
) -> Result<ChannelGrant, GrantError> {
    verify_invitation(operator_pubkey, signed, now)?;
    let inv = &signed.invitation;
    if !verify_invitation_redemption(&inv.channel, &inv.invitee_identity, holder, redeem_signature) {
        return Err(GrantError::BadSignature);
    }
    Ok(ChannelGrant {
        channel: inv.channel,
        holder: *holder,
        direction: inv.direction,
        rights: inv.rights,
        delegable: inv.delegable,
        expires_at: inv.expires_at,
    })
}

/// Lowercase-hex a 32-byte value for the canonical signing bytes. Writes a static
/// nibble table directly into the pre-sized `String` — **byte-identical** output to
/// the old `format!("{:02x}")` loop (so the signature preimage is unchanged), but
/// without the ~64 throwaway `format!` allocations per call. `signing_bytes` calls
/// this twice on every grant/invitation verify, which is the per-connection A2A
/// admission gate (#114 #5).
fn hex32(b: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn hex32_is_byte_identical_to_the_format_loop() {
        // #114 #5 (frozen): the table-driven hex32 must produce EXACTLY the lowercase
        // hex the old `format!("{:02x}")` loop did — the signing preimage must not
        // change (a different preimage would invalidate every existing grant/invite
        // signature). Check fixed vectors + an arbitrary pattern against the reference.
        let reference = |b: &[u8; 32]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };

        let zero = [0x00u8; 32];
        let max = [0xffu8; 32];
        let mut pat = [0u8; 32];
        for (i, p) in pat.iter_mut().enumerate() {
            *p = (i as u8).wrapping_mul(37).wrapping_add(0x0a); // spans low/high nibbles
        }

        assert_eq!(hex32(&zero), "00".repeat(32));
        assert_eq!(hex32(&max), "ff".repeat(32));
        for v in [&zero, &max, &pat] {
            assert_eq!(hex32(v), reference(v), "table hex must equal the format! loop byte-for-byte");
            assert_eq!(hex32(v).len(), 64, "always 64 lowercase hex chars");
        }
    }

    /// Sign a grant with a deterministic operator key (no rng needed in tests).
    fn signed_grant(
        direction: Direction,
        rights: Rights,
        delegable: bool,
        expires_at: UnixSeconds,
    ) -> ([u8; 32], SignedChannelGrant) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let grant = ChannelGrant {
            channel: ChannelId([0xabu8; 32]),
            holder: [0xcdu8; 32],
            direction,
            rights,
            delegable,
            expires_at,
        };
        let signature = sk.sign(&grant.signing_bytes()).to_bytes();
        (sk.verifying_key().to_bytes(), SignedChannelGrant { grant, signature })
    }

    #[test]
    fn verify_ok_before_expiry() {
        let (pk, signed) = signed_grant(Direction::Both, Rights::ReadWrite, true, 1_000);
        assert_eq!(verify(&pk, &signed, 999), Ok(()));
    }

    #[test]
    fn verify_rejects_expired() {
        let (pk, signed) = signed_grant(Direction::Initiate, Rights::Read, false, 1_000);
        assert_eq!(verify(&pk, &signed, 1_000), Err(GrantError::Expired));
    }

    #[test]
    fn verify_rejects_wrong_operator_key() {
        let (_pk, signed) = signed_grant(Direction::Both, Rights::ReadWrite, true, 1_000);
        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes();
        assert_eq!(verify(&other, &signed, 500), Err(GrantError::BadSignature));
    }

    #[test]
    fn verify_fresh_admits_once_then_rejects_the_replay() {
        // #88 SEC88b: an authentic, unexpired grant is admitted the first time and
        // rejected as a replay on any later presentation of the same signature —
        // while a different grant (its own signature) is still admitted, and a
        // bad-key grant is rejected on the signature before ever touching the cache.
        use crate::replay::ReplayCache;
        let (pk, signed) = signed_grant(Direction::Both, Rights::ReadWrite, true, 1_000);
        let mut cache = ReplayCache::new();

        assert_eq!(verify_fresh(&pk, &signed, 500, &mut cache), Ok(()), "first use admitted");
        assert_eq!(
            verify_fresh(&pk, &signed, 600, &mut cache),
            Err(GrantError::Replayed),
            "the same grant again is a replay"
        );

        // A distinct grant has its own signature and is independently admitted.
        let (pk2, signed2) = signed_grant(Direction::Initiate, Rights::Read, false, 1_000);
        assert_eq!(verify_fresh(&pk2, &signed2, 600, &mut cache), Ok(()), "a different grant is fresh");

        // A forged grant fails signature verification and is never cached.
        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes();
        let (_pk3, signed3) = signed_grant(Direction::Both, Rights::ReadWrite, true, 1_000);
        assert_eq!(
            verify_fresh(&other, &signed3, 600, &mut cache),
            Err(GrantError::BadSignature),
            "a bad-key grant is rejected before the cache"
        );
    }

    #[test]
    fn verify_rejects_tampered_scope() {
        // Escalating rights/direction/delegable/holder after signing must break the
        // signature — a grant is not a flat bearer token whose scope can be edited.
        for tamper in 0..4 {
            let (pk, mut signed) = signed_grant(Direction::Initiate, Rights::Read, false, 1_000);
            match tamper {
                0 => signed.grant.rights = Rights::ReadWrite,
                1 => signed.grant.direction = Direction::Both,
                2 => signed.grant.delegable = true,
                _ => signed.grant.holder = [0xffu8; 32],
            }
            assert_eq!(
                verify(&pk, &signed, 500),
                Err(GrantError::BadSignature),
                "tamper case {tamper} must fail verification"
            );
        }
    }

    #[test]
    fn encode_decode_roundtrip_all_variants() {
        for dir in [Direction::Initiate, Direction::Accept, Direction::Both] {
            for rights in [Rights::Read, Rights::Write, Rights::ReadWrite] {
                for delegable in [false, true] {
                    let (_pk, signed) = signed_grant(dir, rights, delegable, 4_242);
                    let bytes = signed.encode();
                    assert_eq!(SignedChannelGrant::decode(&bytes), Ok(signed));
                }
            }
        }
    }

    #[test]
    fn decode_rejects_truncated_and_trailing_and_bad_enums() {
        let (_pk, signed) = signed_grant(Direction::Both, Rights::ReadWrite, true, 1_234);
        assert_eq!(SignedChannelGrant::decode(&[0u8; 10]), Err(GrantError::Malformed));
        let mut trailing = signed.encode();
        trailing.push(0xff);
        assert_eq!(SignedChannelGrant::decode(&trailing), Err(GrantError::Malformed));
        // An out-of-range direction byte (offset 64+32+32) is rejected.
        let mut bad_dir = signed.encode();
        bad_dir[128] = 9;
        assert_eq!(SignedChannelGrant::decode(&bad_dir), Err(GrantError::Malformed));
    }

    #[test]
    fn join_request_roundtrips_and_rejects_malformed() {
        let (_pk, signed) = signed_grant(Direction::Initiate, Rights::ReadWrite, false, 5_000);
        // Grant occupies exactly the advertised fixed prefix.
        assert_eq!(signed.encode().len(), SignedChannelGrant::WIRE_LEN);

        let req = ChannelJoinRequest {
            grant: signed.clone(),
            endpoint: "203.0.113.7:5001".to_string(),
        };
        let bytes = req.encode();
        assert_eq!(ChannelJoinRequest::decode(&bytes), Ok(req));

        // A grant with no trailing endpoint is malformed (endpoint required).
        assert_eq!(
            ChannelJoinRequest::decode(&signed.encode()),
            Err(GrantError::Malformed),
            "a join request must advertise an endpoint"
        );
        // Truncated below a full grant is malformed.
        assert_eq!(ChannelJoinRequest::decode(&[0u8; 10]), Err(GrantError::Malformed));
        // Invalid UTF-8 in the endpoint tail is malformed.
        let mut bad_utf8 = signed.encode();
        bad_utf8.extend_from_slice(&[0xff, 0xfe]);
        assert_eq!(ChannelJoinRequest::decode(&bad_utf8), Err(GrantError::Malformed));
    }

    #[test]
    fn relay_only_sentinel_is_recognized_and_is_not_a_socket_addr() {
        // #121 (frozen): the reserved relay-only sentinel is recognized by `is_relay_only`
        // and is deliberately NOT parseable as a SocketAddr, so it cannot collide with a real
        // advertised endpoint — the edge admits it as an explicit non-dialable marker, not as
        // an address, and `safe_endpoint` (which parses addresses) never sees it as one.
        let (_pk, signed) = signed_grant(Direction::Accept, Rights::ReadWrite, false, 1_000);
        let relay_only =
            ChannelJoinRequest { grant: signed.clone(), endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string() };
        assert!(relay_only.is_relay_only(), "the sentinel endpoint is recognized as relay-only");
        assert!(
            CHANNEL_ENDPOINT_RELAY_ONLY.parse::<std::net::SocketAddr>().is_err(),
            "the sentinel is not a socket address, so it can't collide with a real endpoint"
        );
        // A real advertised endpoint is not relay-only.
        let direct = ChannelJoinRequest { grant: signed, endpoint: "203.0.113.7:7001".to_string() };
        assert!(!direct.is_relay_only());
        // The sentinel round-trips through the join-request wire form (a normal non-empty tail).
        assert_eq!(ChannelJoinRequest::decode(&relay_only.encode()), Ok(relay_only));
    }

    #[test]
    fn reachability_class_maps_advertised_and_reflexive_to_a_class() {
        // #121 Phase B1 (frozen): the pure reachability classifier — the AutoNAT verdict the
        // edge computes from what a member advertised and the reflexive (post-NAT) source it
        // observed on the authenticated join. Five cases pin the whole matrix.
        use std::net::SocketAddr;
        let public: SocketAddr = "203.0.113.7:7001".parse().unwrap();
        let other_public: SocketAddr = "198.51.100.9:8008".parse().unwrap();
        let private_reflexive: SocketAddr = "192.168.1.5:5000".parse().unwrap();
        let loopback_reflexive: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        // public advertised == reflexive → directly reachable, no NAT rewrite.
        assert_eq!(
            reachability_class("203.0.113.7:7001", public),
            Reachability::Public,
            "a global-unicast address that equals the reflexive is Public",
        );
        // private advertised + global-unicast reflexive → NAT'd but punchable at the reflexive.
        assert_eq!(
            reachability_class("192.168.1.5:5000", public),
            Reachability::Nat { reflexive: public },
            "a private advertised address behind a global reflexive is punchable Nat",
        );
        // relay-only sentinel + global-unicast reflexive → still Nat (the reflexive is usable).
        assert_eq!(
            reachability_class(CHANNEL_ENDPOINT_RELAY_ONLY, other_public),
            Reachability::Nat { reflexive: other_public },
            "the relay-only sentinel with a global reflexive is punchable Nat at the reflexive",
        );
        // public advertised + private reflexive → the observed source is not routable: relay only.
        assert_eq!(
            reachability_class("203.0.113.7:7001", private_reflexive),
            Reachability::RelayOnly,
            "a private reflexive (symmetric/CGNAT) is RelayOnly even if the advertised addr is public",
        );
        // relay-only sentinel + loopback reflexive → double-NAT, pure relay.
        assert_eq!(
            reachability_class(CHANNEL_ENDPOINT_RELAY_ONLY, loopback_reflexive),
            Reachability::RelayOnly,
            "the relay-only sentinel with a non-global reflexive is RelayOnly",
        );
    }

    #[test]
    fn is_global_unicast_matches_the_edge_ssrf_filter_ranges() {
        // #121 Phase B1: the shared global-unicast test `ct_edge::safe_endpoint` is now defined
        // in terms of — it must reject every private/internal range and accept only public unicast.
        use std::net::SocketAddr;
        for bad in [
            "127.0.0.1:22", "0.0.0.0:80", "224.0.0.1:80", "10.0.0.5:22", "172.16.0.1:22",
            "192.168.1.1:22", "169.254.169.254:80", "100.64.0.1:22", "[::1]:22", "[fe80::1]:22",
            "[fc00::1]:22", "[fd12:3456::1]:22",
        ] {
            assert!(!is_global_unicast(bad.parse::<SocketAddr>().unwrap()), "{bad} must not be global-unicast");
        }
        for ok in ["203.0.113.10:7001", "8.8.8.8:443", "[2001:4860:4860::8888]:443"] {
            assert!(is_global_unicast(ok.parse::<SocketAddr>().unwrap()), "{ok} must be global-unicast");
        }
    }

    #[test]
    fn holder_possession_proof_verifies_only_the_real_holder() {
        // #81 gap 1: the holder proves possession by signing the edge challenge.
        let holder_sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let holder = holder_sk.verifying_key().to_bytes();
        let challenge = b"edge-nonce-0123456789abcdef";

        // The genuine holder's signature over the challenge verifies.
        let sig = holder_sk.sign(challenge).to_bytes();
        assert!(verify_holder_possession(&holder, challenge, &sig));

        // A different key cannot produce a valid proof for this holder.
        let other = SigningKey::from_bytes(&[0x43u8; 32]);
        let forged = other.sign(challenge).to_bytes();
        assert!(!verify_holder_possession(&holder, challenge, &forged), "wrong key rejected");

        // A signature over a DIFFERENT challenge is rejected (no replay of an old
        // proof against a fresh nonce).
        let stale = holder_sk.sign(b"a-different-nonce").to_bytes();
        assert!(!verify_holder_possession(&holder, challenge, &stale), "stale challenge rejected");

        // A tampered signature is rejected.
        let mut tampered = sig;
        tampered[0] ^= 0xff;
        assert!(!verify_holder_possession(&holder, challenge, &tampered), "tampered signature rejected");
    }

    #[test]
    fn member_noise_attestation_binds_the_key_to_holder_and_channel() {
        // #101: the member signs its Noise key with its HOLDER key, binding it to
        // (channel, holder). A DB-controlling operator who substitutes the key can't
        // forge this signature, so the initiator rejects the substituted key.
        let holder_sk = SigningKey::from_bytes(&[0x33u8; 32]);
        let holder = holder_sk.verifying_key().to_bytes();
        let channel = ChannelId([0xC1u8; 32]);
        let noise = [0xAAu8; 32];
        let sig = holder_sk.sign(&member_noise_attest_bytes(&channel, &holder, &noise)).to_bytes();

        assert!(verify_member_noise_attestation(&channel, &holder, &noise, &sig), "genuine attestation verifies");
        assert!(
            !verify_member_noise_attestation(&channel, &holder, &[0xBBu8; 32], &sig),
            "an operator-substituted Noise key is rejected"
        );
        assert!(
            !verify_member_noise_attestation(&ChannelId([0xC2u8; 32]), &holder, &noise, &sig),
            "the attestation is bound to its channel"
        );
        let other = SigningKey::from_bytes(&[0x99u8; 32]).verifying_key().to_bytes();
        assert!(
            !verify_member_noise_attestation(&channel, &other, &noise, &sig),
            "only the real holder can attest (a DB operator can't sign as the holder)"
        );
    }

    #[test]
    fn direction_and_rights_predicates() {
        assert!(Direction::Both.permits(Direction::Initiate));
        assert!(Direction::Both.permits(Direction::Accept));
        assert!(Direction::Initiate.permits(Direction::Initiate));
        assert!(!Direction::Initiate.permits(Direction::Accept));
        assert!(Rights::ReadWrite.can_read() && Rights::ReadWrite.can_write());
        assert!(Rights::Read.can_read() && !Rights::Read.can_write());
        assert!(!Rights::Write.can_read() && Rights::Write.can_write());
    }

    /// Operator-signed invitation for a deterministic invitee identity (no rng).
    fn signed_invitation(expires_at: UnixSeconds) -> ([u8; 32], SignedChannelInvitation) {
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let invitee = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key().to_bytes();
        let invitation = ChannelInvitation {
            channel: ChannelId([0xabu8; 32]),
            invitee_identity: invitee,
            direction: Direction::Both,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at,
        };
        let signature = op.sign(&invitation.signing_bytes()).to_bytes();
        (op.verifying_key().to_bytes(), SignedChannelInvitation { invitation, signature })
    }

    #[test]
    fn verify_invitation_checks_operator_signature_and_expiry() {
        let (op_pk, signed) = signed_invitation(1_000);
        assert_eq!(verify_invitation(&op_pk, &signed, 999), Ok(()));
        assert_eq!(verify_invitation(&op_pk, &signed, 1_000), Err(GrantError::Expired));
        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes();
        assert_eq!(verify_invitation(&other, &signed, 500), Err(GrantError::BadSignature));
    }

    #[test]
    fn signed_invitation_round_trips_through_the_wire_form() {
        let (_op, signed) = signed_invitation(4_242);
        let bytes = signed.encode();
        assert_eq!(bytes.len(), SignedChannelInvitation::WIRE_LEN);
        assert_eq!(SignedChannelInvitation::decode(&bytes), Ok(signed));
        // A truncated buffer is Malformed, not a panic.
        assert_eq!(
            SignedChannelInvitation::decode(&bytes[..bytes.len() - 1]),
            Err(GrantError::Malformed)
        );
    }

    #[test]
    fn only_the_intended_invitee_can_redeem_into_the_holder_it_chose() {
        let channel = ChannelId([0xabu8; 32]);
        let invitee_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let invitee = invitee_sk.verifying_key().to_bytes();
        let holder = [0xcdu8; 32]; // the member key the invitee chooses

        // The invitee signs the redemption with its IDENTITY key, binding `holder`.
        let sig = invitee_sk.sign(&invitation_redeem_bytes(&channel, &invitee, &holder)).to_bytes();
        assert!(verify_invitation_redemption(&channel, &invitee, &holder, &sig));

        // A different holder key -> the binding fails (can't redeem to another key).
        assert!(!verify_invitation_redemption(&channel, &invitee, &[0xee; 32], &sig));
        // A different channel -> fails (invitation can't be moved to another channel).
        assert!(!verify_invitation_redemption(&ChannelId([0x01; 32]), &invitee, &holder, &sig));
        // Someone else's signature over their own redeem bytes doesn't accept for the
        // invitee -> only the intended invitee can accept.
        let mallory = SigningKey::from_bytes(&[0x99u8; 32]);
        let m_sig = mallory.sign(&invitation_redeem_bytes(&channel, &invitee, &holder)).to_bytes();
        assert!(!verify_invitation_redemption(&channel, &invitee, &holder, &m_sig));
    }

    #[test]
    fn redeem_invitation_yields_membership_claims_bound_to_the_chosen_holder() {
        // End-to-end AF3: operator invites invitee_identity; the invitee accepts and
        // binds a *member* holder key; redeem_invitation checks both proofs and returns
        // the grant claims bound to the chosen holder (not the invitee identity).
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pk = op.verifying_key().to_bytes();
        let invitee_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let invitee = invitee_sk.verifying_key().to_bytes();
        let channel = ChannelId([0xabu8; 32]);
        let holder = [0xcdu8; 32];

        let invitation = ChannelInvitation {
            channel,
            invitee_identity: invitee,
            direction: Direction::Initiate,
            rights: Rights::Read,
            delegable: false,
            expires_at: 1_000,
        };
        let sig = op.sign(&invitation.signing_bytes()).to_bytes();
        let signed = SignedChannelInvitation { invitation, signature: sig };
        let redeem = invitee_sk.sign(&invitation_redeem_bytes(&channel, &invitee, &holder)).to_bytes();

        // Happy path -> the membership grant claims, bound to the chosen holder.
        let grant = redeem_invitation(&op_pk, &signed, &redeem, &holder, 999).unwrap();
        assert_eq!(grant.holder, holder, "claims bind the chosen member key, not the invitee identity");
        assert_eq!(grant.channel, channel);
        assert_eq!(grant.direction, Direction::Initiate);
        assert_eq!(grant.rights, Rights::Read);
        assert_eq!(grant.expires_at, 1_000);

        // Expired invitation -> Expired.
        assert_eq!(redeem_invitation(&op_pk, &signed, &redeem, &holder, 1_000), Err(GrantError::Expired));
        // Wrong operator key -> BadSignature.
        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes();
        assert_eq!(redeem_invitation(&other, &signed, &redeem, &holder, 999), Err(GrantError::BadSignature));
        // A redemption that bound a different holder -> BadSignature (can't swap the key).
        assert_eq!(
            redeem_invitation(&op_pk, &signed, &redeem, &[0xee; 32], 999),
            Err(GrantError::BadSignature)
        );
    }

    #[test]
    fn challenge_bound_redemption_is_tied_to_the_nonce_and_domain_separated() {
        // #108: a redemption signed for one fresh challenge doesn't verify against another
        // nonce, and the v2 challenge bytes differ from the static v1 bytes.
        let channel = ChannelId([0xabu8; 32]);
        let invitee_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let invitee = invitee_sk.verifying_key().to_bytes();
        let holder = [0xcdu8; 32];
        let nonce = [0x77u8; 32];

        let sig = invitee_sk
            .sign(&invitation_redeem_challenge_bytes(&channel, &invitee, &holder, &nonce))
            .to_bytes();
        assert!(verify_invitation_redemption_challenge(&channel, &invitee, &holder, &nonce, &sig));
        // A different nonce -> fails (non-replayable across challenges).
        assert!(!verify_invitation_redemption_challenge(&channel, &invitee, &holder, &[0x88; 32], &sig));
        // The v2 challenge bytes are domain-separated from the v1 static bytes.
        assert_ne!(
            invitation_redeem_challenge_bytes(&channel, &invitee, &holder, &nonce),
            invitation_redeem_bytes(&channel, &invitee, &holder)
        );
        // A static v1 signature does not satisfy the challenge check, and vice-versa.
        let static_sig = invitee_sk.sign(&invitation_redeem_bytes(&channel, &invitee, &holder)).to_bytes();
        assert!(!verify_invitation_redemption_challenge(&channel, &invitee, &holder, &nonce, &static_sig));
    }

    #[test]
    fn an_invitation_is_domain_separated_from_a_grant() {
        // Same fields, but the invitation and grant signing bytes differ, so an
        // operator signature over one can never be replayed as the other.
        let (_op, inv) = signed_invitation(1_000);
        let grant = ChannelGrant {
            channel: inv.invitation.channel,
            holder: inv.invitation.invitee_identity,
            direction: inv.invitation.direction,
            rights: inv.invitation.rights,
            delegable: inv.invitation.delegable,
            expires_at: inv.invitation.expires_at,
        };
        assert_ne!(inv.invitation.signing_bytes(), grant.signing_bytes());
    }

    // ---- E-fail-static: soft-state membership staples (invariant #7) ----------------------

    /// Mint a staple for `channel`/`holder` under operator key `op` (byte fill), signed over
    /// the canonical preimage. Returns the operator pubkey and the staple.
    fn stapled(
        op: u8,
        channel: [u8; 32],
        holder: [u8; 32],
        stapled_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> ([u8; 32], MembershipStaple) {
        let sk = SigningKey::from_bytes(&[op; 32]);
        let signature = sk
            .sign(&MembershipStaple::signing_bytes(
                &ChannelId(channel),
                &holder,
                stapled_at,
                expires_at,
            ))
            .to_bytes();
        (
            sk.verifying_key().to_bytes(),
            MembershipStaple {
                channel: ChannelId(channel),
                holder,
                stapled_at,
                expires_at,
                signature,
            },
        )
    }

    #[test]
    fn staple_cache_admits_offline_until_ttl_then_lapses() {
        // E-fail-static (frozen): a cached, operator-signed membership staple lets a node keep
        // admitting a known member with NO central round-trip, until the staple's TTL lapses —
        // fail-static, never fail-closed. Revocation latency is exactly the TTL (invariant #7):
        // stop refreshing and the cached staple dies within one TTL.
        let ch = [0x11u8; 32];
        let holder = [0xa1u8; 32];
        // Operator (op=7) staples the member at t=1000 for a 3600s TTL → expires at 4600.
        let (operator, staple) = stapled(7, ch, holder, 1_000, 4_600);

        let mut cache = StapleCache::new();
        assert!(
            cache.refresh(&operator, staple, 1_000),
            "an authentic, unexpired staple is accepted into the cache"
        );

        // (1) FAIL-STATIC: admission succeeds offline (no central) any time before expiry.
        assert!(
            cache.is_member(&operator, &ChannelId(ch), &holder, 1_100),
            "a known member is admitted from cache while central is unreachable"
        );
        assert!(
            cache.is_member(&operator, &ChannelId(ch), &holder, 4_599),
            "still admitted right up to the last second before the TTL lapses"
        );

        // (2) TTL BOUND / revocation latency (invariant #7): at expiry the staple is dead and
        // the entry is evicted, so a no-longer-refreshed (revoked) member is gone within the TTL.
        assert!(
            !cache.is_member(&operator, &ChannelId(ch), &holder, 4_600),
            "at expires_at the cached staple lapses — admission fails (revocation = TTL, #7)"
        );
        // A fresh mint would be needed to re-admit — the lapsed entry was dropped.
        let (_op, again) = stapled(7, ch, holder, 4_600, 8_200);
        assert!(cache.refresh(&operator, again, 4_600));
        assert!(cache.is_member(&operator, &ChannelId(ch), &holder, 5_000));
    }

    #[test]
    fn staple_cache_rejects_forged_and_never_regresses_validity() {
        let ch = [0x22u8; 32];
        let holder = [0xb2u8; 32];
        let (operator, long) = stapled(7, ch, holder, 1_000, 9_000); // long-lived, honest

        // (a) FORGED: a staple signed by a foreign operator (op=8) is neither cached nor trusted.
        let (_foreign, forged) = stapled(8, ch, holder, 1_000, 9_000);
        let mut cache = StapleCache::new();
        assert!(
            !cache.refresh(&operator, forged, 1_000),
            "a staple not signed by the channel operator is rejected, never cached"
        );
        assert!(
            !cache.is_member(&operator, &ChannelId(ch), &holder, 1_100),
            "nothing was cached, so the member is not admitted"
        );

        // (b) TAMPERED FIELD: the operator signed for THIS channel; presenting it under a
        // different channel breaks the binding, so it doesn't verify.
        let (_op, mut tampered) = stapled(7, ch, holder, 1_000, 9_000);
        tampered.channel = ChannelId([0x33u8; 32]);
        assert!(
            !tampered.is_valid(&operator, 1_100),
            "a staple whose channel was swapped after signing fails verification"
        );

        // (c) KEEP-LATEST: cache the long staple, then feed a SHORTER-lived one — it must not
        // shrink the member's validity (out-of-order/stale gossip can't regress it).
        assert!(cache.refresh(&operator, long, 1_000));
        let (_op2, short) = stapled(7, ch, holder, 1_000, 3_000); // shorter TTL
        assert!(cache.refresh(&operator, short, 1_000));
        assert!(
            cache.is_member(&operator, &ChannelId(ch), &holder, 5_000),
            "the longer-lived staple still governs at t=5000 — a stale short staple didn't regress it"
        );

        // (d) SCOPE: a staple for this pair grants nothing for a different holder.
        assert!(
            !cache.is_member(&operator, &ChannelId(ch), &[0xccu8; 32], 2_000),
            "membership is per-(channel,holder) — a different holder is not admitted"
        );
    }

    #[test]
    fn membership_staple_wire_roundtrips_and_rejects_malformed() {
        // E-staple-wire (frozen): the fixed 144-byte codec the gossip transport ships. A
        // staple round-trips byte-exact, the decoded copy still verifies (authenticity
        // survives the wire), and a truncated/over-long buffer is rejected as Malformed —
        // a partial staple is never half-decoded into a trusted one.
        let ch = [0x44u8; 32];
        let holder = [0xd4u8; 32];
        let (operator, staple) = stapled(7, ch, holder, 1_000, 4_600);

        let wire = staple.encode();
        assert_eq!(wire.len(), MembershipStaple::WIRE_LEN, "encoded length is the fixed WIRE_LEN");
        assert_eq!(wire.len(), 144);

        let decoded = MembershipStaple::decode(&wire).expect("a well-formed staple decodes");
        assert_eq!(decoded, staple, "encode -> decode is the identity");
        assert!(
            decoded.is_valid(&operator, 1_100),
            "the decoded staple still verifies under the operator key (authenticity survives the wire)"
        );

        // Truncated (one byte short) and over-long (one trailing byte) buffers are both
        // rejected — the codec never half-trusts a partial or padded record.
        assert_eq!(
            MembershipStaple::decode(&wire[..wire.len() - 1]),
            Err(GrantError::Malformed),
            "a truncated staple buffer is Malformed"
        );
        let mut too_long = wire.clone();
        too_long.push(0);
        assert_eq!(
            MembershipStaple::decode(&too_long),
            Err(GrantError::Malformed),
            "an over-long staple buffer is Malformed"
        );
    }

    #[test]
    fn staple_admission_policy_is_optional_and_only_ever_adds_a_requirement() {
        // #121 E-fail-static, option A (frozen, maintainer decision 2026-07-20): the staple
        // requirement is OPT-IN per channel. `Open` (default) is byte-for-byte today's
        // grant-only behaviour — it never consults a staple, so channels that don't opt in are
        // unaffected. `RequireStaple` additionally demands a fresh cached staple, so revocation
        // propagates within the TTL (#7). Enabling it can only ADD a requirement, never weaken
        // admission (the caller has already verified the grant before calling this).
        let ch = [0x55u8; 32];
        let holder = [0xd5u8; 32];
        let (operator, staple) = stapled(7, ch, holder, 1_000, 4_600);

        // Default policy is Open (grant-only) — the opt-out is the zero value.
        assert_eq!(ChannelAdmissionPolicy::default(), ChannelAdmissionPolicy::Open);

        let mut cache = StapleCache::new();

        // (1) OPEN: admitted with NO staple in the cache at all — grant-only, today's behaviour.
        assert!(
            cache.admits_under_policy(ChannelAdmissionPolicy::Open, &operator, &ChannelId(ch), &holder, 2_000),
            "Open admits a grant-verified member with no staple (backwards-compatible default)"
        );

        // (2) REQUIRE_STAPLE with no staple cached → denied (the freshness requirement bites).
        assert!(
            !cache.admits_under_policy(ChannelAdmissionPolicy::RequireStaple, &operator, &ChannelId(ch), &holder, 2_000),
            "RequireStaple denies a member with no fresh staple"
        );

        // (3) REQUIRE_STAPLE with a fresh staple cached → admitted...
        assert!(cache.refresh(&operator, staple, 1_000));
        assert!(
            cache.admits_under_policy(ChannelAdmissionPolicy::RequireStaple, &operator, &ChannelId(ch), &holder, 2_000),
            "RequireStaple admits once a fresh staple is present"
        );
        // ...and denied again once that staple lapses at its TTL (revocation latency = TTL, #7).
        assert!(
            !cache.admits_under_policy(ChannelAdmissionPolicy::RequireStaple, &operator, &ChannelId(ch), &holder, 4_600),
            "RequireStaple denies once the staple lapses (revocation propagates within the TTL)"
        );
        // Open still admits at the same instant — it never consults the staple.
        assert!(
            cache.admits_under_policy(ChannelAdmissionPolicy::Open, &operator, &ChannelId(ch), &holder, 4_600),
            "Open is unaffected by staple lapse — grant-only channels are never gated on staples"
        );
    }

    // ---- #107-nway: deterministic per-link channel id derivation --------------------------

    #[test]
    fn link_channel_id_is_canonical_operator_bound_and_collision_resistant() {
        // #107-nway (frozen): a topology's overlay link (holder_a, holder_b) under an operator
        // deterministically maps to a ChannelId both endpoints can derive locally — no round
        // trip. It must be order-independent, operator-bound (cross-operator isolation), and
        // collision-resistant across distinct pairs. It's an ADDRESS only; grants still gate.
        let op = [0x01u8; 32];
        let a = [0xaau8; 32];
        let b = [0xbbu8; 32];

        // Deterministic + canonical: both endpoints derive the SAME id regardless of order.
        let id_ab = channel_id_for_link(&op, &a, &b);
        assert_eq!(id_ab, channel_id_for_link(&op, &a, &b), "derivation is deterministic");
        assert_eq!(
            id_ab,
            channel_id_for_link(&op, &b, &a),
            "order-independent — a and b derive the same channel for their link"
        );

        // Operator-bound: a different operator gets a different id for the same pair, so two
        // operators can't collide onto one channel (cross-operator isolation).
        let op2 = [0x02u8; 32];
        assert_ne!(
            id_ab,
            channel_id_for_link(&op2, &a, &b),
            "binding the operator key isolates channels across operators"
        );

        // Collision-resistant: a distinct holder pair yields a distinct channel.
        let c = [0xccu8; 32];
        assert_ne!(id_ab, channel_id_for_link(&op, &a, &c), "a different link is a different channel");
        assert_ne!(
            channel_id_for_link(&op, &a, &c),
            channel_id_for_link(&op, &b, &c),
            "distinct pairs sharing one endpoint are still distinct channels"
        );

        // Sanity: it is a full 32-byte id and not the trivially-zero value.
        assert_ne!(id_ab.0, [0u8; 32], "a derived id is a real hash, not zero");
    }

    // ---- #132: optional agent-verifiable A2A billing commitment --------------------------

    /// Sign a billing commitment for `channel` under holder key `h` (byte fill).
    fn commit(
        h: u8,
        channel: [u8; 32],
        payee: [u8; 32],
        terms: [u8; 32],
        max_amount: u64,
        expires_at: UnixSeconds,
    ) -> BillingCommitment {
        let sk = SigningKey::from_bytes(&[h; 32]);
        let holder = sk.verifying_key().to_bytes();
        let sig = sk
            .sign(&BillingCommitment::signing_bytes(
                &ChannelId(channel),
                &holder,
                &payee,
                &terms,
                max_amount,
                expires_at,
            ))
            .to_bytes();
        BillingCommitment {
            channel: ChannelId(channel),
            holder,
            payee,
            terms_hash: terms,
            max_amount,
            expires_at,
            signature: sig,
        }
    }

    #[test]
    fn billing_commitment_verifies_and_gates_setup_only_on_matching_terms() {
        // #132 (frozen): the OPTIONAL, agent-verifiable billing coupling. A holder-signed
        // commitment is authentic + current only for its exact binding; the requiring agent's
        // `satisfies` gate at setup accepts it only for the demanded payee + terms and a
        // sufficient amount. It moves no funds — it is the verifiable coupling, not settlement.
        let ch = [0x11u8; 32];
        let payee = [0xa5u8; 32];
        let terms = [0x7eu8; 32];
        let c = commit(9, ch, payee, terms, 1_000, 5_000);

        // (1) Authentic + unexpired → valid; and satisfies the exact demanded terms with amount.
        assert!(c.is_valid(1_000), "an authentic, unexpired commitment verifies");
        assert!(
            c.satisfies(1_000, &payee, &terms, 500),
            "setup gate passes: right payee + terms, max_amount(1000) >= min(500)"
        );

        // (2) Expiry: at expires_at it is dead (#7-style TTL) — refuses setup.
        assert!(!c.is_valid(5_000), "expired commitment is invalid");
        assert!(!c.satisfies(5_000, &payee, &terms, 500), "expired → setup refused");

        // (3) Wrong payee / wrong terms / insufficient amount all refuse the setup gate.
        assert!(!c.satisfies(1_000, &[0xbbu8; 32], &terms, 500), "wrong payee refused");
        assert!(!c.satisfies(1_000, &payee, &[0xccu8; 32], 500), "wrong terms refused");
        assert!(!c.satisfies(1_000, &payee, &terms, 2_000), "amount below the demanded minimum refused");

        // (4) Tamper: flip a field after signing → the holder signature no longer verifies.
        let mut forged = c.clone();
        forged.max_amount = 1_000_000; // attacker inflates the committed cap
        assert!(!forged.is_valid(1_000), "a tampered max_amount breaks the signature (#132)");
        let mut wrong_payee = c.clone();
        wrong_payee.payee = [0xbbu8; 32];
        assert!(!wrong_payee.is_valid(1_000), "a swapped payee breaks the signature");

        // (5) Forged holder: an attacker signs with its own key but stamps the victim's holder
        // pubkey — the signature can't validate against the claimed holder.
        let victim = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
        let attacker = SigningKey::from_bytes(&[13u8; 32]);
        let sig = attacker
            .sign(&BillingCommitment::signing_bytes(&ChannelId(ch), &victim, &payee, &terms, 1_000, 5_000))
            .to_bytes();
        let impersonated = BillingCommitment {
            channel: ChannelId(ch), holder: victim, payee, terms_hash: terms,
            max_amount: 1_000, expires_at: 5_000, signature: sig,
        };
        assert!(!impersonated.is_valid(1_000), "a commitment not signed by its holder is rejected");
    }

    #[test]
    fn settle_receipt_attests_delivery_and_defeats_send_side_forgery() {
        // #132 SR1 (frozen): the `settle` receipt. Both peers fold the same delivered bytes through
        // a TransferDigest; the RECEIVER signs a SettleReceipt over its digest; the sender confirms
        // it against its OWN digest. A short/tampered/forged/replayed claim is rejected — so
        // "delivered" is witnessed by the receiver, never asserted by the send side.
        let ch = ChannelId([0x21u8; 32]);
        let terms = [0x7eu8; 32];
        let nonce = [0x5au8; 32];
        let payload = b"the exact application bytes that crossed the tunnel";

        // Both ends fold the identical delivered stream (in the live path, as the pump moves it).
        let mut sender = TransferDigest::new();
        let mut receiver = TransferDigest::new();
        for chunk in payload.chunks(7) {
            sender.update(chunk);
            receiver.update(chunk);
        }
        assert_eq!(sender.digest(), receiver.digest(), "identical streams → identical digest");
        assert_eq!(sender.bytes(), payload.len() as u64);

        // The receiver signs a receipt over what it received.
        let recv_sk = SigningKey::from_bytes(&[0x31u8; 32]);
        let receiver_id = recv_sk.verifying_key().to_bytes();
        let sign = |rid: &[u8; 32], bytes: u64, digest: &[u8; 32], sk: &SigningKey| SettleReceipt {
            channel: ch,
            receiver: *rid,
            terms_hash: terms,
            session_nonce: nonce,
            bytes_delivered: bytes,
            transfer_digest: *digest,
            signature: sk
                .sign(&SettleReceipt::signing_bytes(&ch, rid, &terms, &nonce, bytes, digest))
                .to_bytes(),
        };
        let receipt = sign(&receiver_id, receiver.bytes(), &receiver.digest(), &recv_sk);

        // (1) Authentic + matches the sender's own digest/terms/session → confirmed.
        assert!(receipt.is_valid(), "a receiver-signed receipt verifies");
        assert!(
            receipt.confirms_delivery(&ch, &terms, &nonce, payload.len() as u64, &sender.digest()),
            "settle gate passes: right channel/terms/session, full byte count, matching digest"
        );

        // (2) Under-report / truncated delivery: the receiver only got a prefix → its digest and
        // byte count differ from the sender's, so the sender's gate rejects the receipt.
        let mut short = TransferDigest::new();
        short.update(&payload[..20]);
        let short_receipt = sign(&receiver_id, short.bytes(), &short.digest(), &recv_sk);
        assert!(short_receipt.is_valid(), "the short receipt is itself authentically signed");
        assert!(
            !short_receipt.confirms_delivery(&ch, &terms, &nonce, payload.len() as u64, &sender.digest()),
            "a truncated delivery digest does NOT match what was sent → rejected"
        );

        // (3) Wrong channel / terms / session / insufficient min_bytes all refuse the gate.
        assert!(!receipt.confirms_delivery(&ChannelId([0u8; 32]), &terms, &nonce, 1, &sender.digest()), "wrong channel");
        assert!(!receipt.confirms_delivery(&ch, &[0u8; 32], &nonce, 1, &sender.digest()), "wrong terms");
        assert!(!receipt.confirms_delivery(&ch, &terms, &[0u8; 32], 1, &sender.digest()), "wrong session nonce (replay)");
        assert!(!receipt.confirms_delivery(&ch, &terms, &nonce, payload.len() as u64 + 1, &sender.digest()), "below min_bytes");

        // (4) Tamper: inflate the byte count after signing → the receiver signature breaks.
        let mut forged = receipt.clone();
        forged.bytes_delivered = 1_000_000;
        assert!(!forged.is_valid(), "a tampered byte count breaks the receiver signature");

        // (5) Send-side forgery: an attacker signs a full-delivery receipt with ITS key but stamps
        // the receiver's id — it can't validate against the claimed receiver.
        let attacker = SigningKey::from_bytes(&[0x99u8; 32]);
        let forged_by_sender = sign(&receiver_id, payload.len() as u64, &sender.digest(), &attacker);
        assert!(!forged_by_sender.is_valid(), "a receipt not signed by the receiver is rejected (no ambient send-side trust)");
    }
}
