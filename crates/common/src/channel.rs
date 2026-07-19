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

/// What an agent presents to the edge to join/operate a channel: its signed
/// [`ChannelGrant`] plus the direct endpoint it advertises for the peer to reach it
/// (host:port — the edge brokers the two advertised endpoints, ADR-0015). The
/// channel and holder are inside the grant, so they are not repeated here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelJoinRequest {
    pub grant: SignedChannelGrant,
    pub endpoint: String,
}

impl ChannelJoinRequest {
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

/// A **cross-user channel invitation** (#72 AF3): the operator invites a specific
/// *invitee identity* (another user's agent) to join a channel, **without yet knowing**
/// the member (holder) key that agent will use. The invitee's agent redeems it — proving
/// it holds the invitee identity key and choosing a holder key (see
/// [`invitation_redeem_bytes`]) — after which the operator/CP issues the real per-holder
/// [`SignedChannelGrant`]. Distinct from *sharing*: an invitation crosses users and is
/// redeemed once into a scoped grant. Same claim shape as [`ChannelGrant`], but bound to
/// the invitee's *identity* key rather than a member key.
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

/// Lowercase-hex a 32-byte value for the canonical signing bytes.
fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

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
}
