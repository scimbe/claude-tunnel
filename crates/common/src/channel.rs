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
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantError::BadSignature => write!(f, "channel grant signature invalid"),
            GrantError::Expired => write!(f, "channel grant expired"),
            GrantError::BadKey => write!(f, "operator public key invalid"),
            GrantError::Malformed => write!(f, "channel grant bytes malformed"),
        }
    }
}

impl std::error::Error for GrantError {}

impl SignedChannelGrant {
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
    fn direction_and_rights_predicates() {
        assert!(Direction::Both.permits(Direction::Initiate));
        assert!(Direction::Both.permits(Direction::Accept));
        assert!(Direction::Initiate.permits(Direction::Initiate));
        assert!(!Direction::Initiate.permits(Direction::Accept));
        assert!(Rights::ReadWrite.can_read() && Rights::ReadWrite.can_write());
        assert!(Rights::Read.can_read() && !Rights::Read.can_write());
        assert!(!Rights::Write.can_read() && Rights::Write.can_write());
    }
}
