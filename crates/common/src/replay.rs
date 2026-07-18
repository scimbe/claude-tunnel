//! Replay cache for single-presentation trust primitives (#88 SEC88a).
//!
//! `SignedCredential` and `ChannelGrant` are signature + expiry only, so a captured
//! token is replayable until it expires. A [`ReplayCache`] records an identifier for
//! each accepted token until that token's own expiry and rejects any later
//! presentation of the same identifier — turning "valid until expiry, any number of
//! times" into "valid once". The identifier is caller-chosen and opaque: the token's
//! 64-byte signature works (a replay carries the identical signature) as does an
//! explicit nonce.
//!
//! Time is caller-supplied (the same wall-clock seconds the verifiers already take as
//! `now`) so this stays deterministic and testable, mirroring [`crate::ratelimit`].
//! Entries whose expiry has passed are evicted on access, so the cache never has to
//! retain more than the set of currently-unexpired tokens.

use std::collections::HashMap;

/// A bounded-lifetime set of seen token identifiers. Each identifier is remembered
/// only until its token's `expires_at`, after which the token would be rejected on
/// expiry anyway and the entry is dropped.
#[derive(Default)]
pub struct ReplayCache {
    /// identifier bytes -> the token's `expires_at` (caller time units, e.g. seconds)
    seen: HashMap<Vec<u8>, u64>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `id` (valid until `expires_at`) as seen at time `now`, returning
    /// whether it is **fresh** — `true` the first time an unexpired `id` is
    /// presented, `false` if the same `id` was already recorded and has not yet
    /// expired (a replay). An `id` whose `expires_at <= now` is treated as already
    /// invalid: it is not admitted as fresh and not stored (the caller's expiry
    /// check rejects it regardless). Every call first evicts entries that have
    /// expired by `now`, so the map only ever holds currently-valid identifiers.
    pub fn check_and_record(&mut self, id: &[u8], expires_at: u64, now: u64) -> bool {
        self.evict_expired(now);
        // An already-expired token is never fresh and never stored — expiry alone
        // rejects it, and storing it would only add an entry we'd evict next call.
        if expires_at <= now {
            return false;
        }
        if self.seen.contains_key(id) {
            return false;
        }
        self.seen.insert(id.to_vec(), expires_at);
        true
    }

    /// Drop every entry whose token has expired at `now` (`expires_at <= now`).
    fn evict_expired(&mut self, now: u64) {
        self.seen.retain(|_, &mut expires_at| expires_at > now);
    }

    /// Number of currently-retained (unexpired-as-of-last-access) identifiers.
    /// Exposed for tests/observability; not part of the trust decision.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXP: u64 = 100;

    #[test]
    fn first_presentation_is_fresh_and_a_replay_is_rejected() {
        let mut c = ReplayCache::new();
        let sig = [7u8; 64];
        assert!(c.check_and_record(&sig, EXP, 10), "first presentation is fresh");
        assert!(!c.check_and_record(&sig, EXP, 20), "the same id again is a replay");
        assert!(!c.check_and_record(&sig, EXP, 99), "still a replay right up to expiry");
    }

    #[test]
    fn distinct_ids_are_independent() {
        let mut c = ReplayCache::new();
        assert!(c.check_and_record(&[1u8; 64], EXP, 10));
        assert!(c.check_and_record(&[2u8; 64], EXP, 10), "a different id is its own token");
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn an_already_expired_token_is_not_fresh_and_not_stored() {
        let mut c = ReplayCache::new();
        // expires_at == now and < now are both already invalid.
        assert!(!c.check_and_record(&[3u8; 64], 50, 50), "expires_at == now is not fresh");
        assert!(!c.check_and_record(&[4u8; 64], 40, 50), "expires_at < now is not fresh");
        assert!(c.is_empty(), "expired tokens are never retained");
    }

    #[test]
    fn entries_are_evicted_after_expiry_bounding_the_cache() {
        let mut c = ReplayCache::new();
        let sig = [9u8; 64];
        assert!(c.check_and_record(&sig, EXP, 10), "fresh before expiry");
        assert_eq!(c.len(), 1);
        // A later access past this token's expiry evicts it, so the map doesn't grow
        // without bound — and the id could even be admitted again as a brand-new
        // token (it would only reach here if it also passed a fresh expiry check).
        assert!(
            c.check_and_record(&[0u8; 64], 300, EXP + 1),
            "an access after expiry admits a new token"
        );
        assert_eq!(c.len(), 1, "the expired entry was evicted, not accumulated");
    }
}
