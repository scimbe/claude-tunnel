//! Per-token rate limiting (ADR-0018).
//!
//! A fixed-window counter caps rendezvous attempts per Routing Token, layered
//! on top of the PoW gate. Time is caller-supplied (a window index) so this
//! stays deterministic and wall-clock-free.

use crate::RoutingToken;
use std::collections::HashMap;
use std::hash::Hash;

/// Fixed-window rate limiter keyed by an arbitrary key `K` (a Routing Token, an
/// account subject, …). Time is caller-supplied (a window index) so this stays
/// deterministic and wall-clock-free; the caller buckets wall-clock into windows.
pub struct KeyedRateLimiter<K> {
    max_per_window: u32,
    /// key -> (current window, count in that window)
    counters: HashMap<K, (u64, u32)>,
}

impl<K: Eq + Hash + Clone> KeyedRateLimiter<K> {
    pub fn new(max_per_window: u32) -> Self {
        Self {
            max_per_window,
            counters: HashMap::new(),
        }
    }

    /// Record an attempt for `key` in `window`; returns whether it is allowed
    /// (strictly under the per-window limit). A new window resets the count.
    pub fn allow(&mut self, key: &K, window: u64) -> bool {
        let entry = self.counters.entry(key.clone()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= self.max_per_window {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// Per-Routing-Token fixed-window limiter (ADR-0018): rendezvous-attempt cap
/// layered on the PoW gate.
pub type RateLimiter = KeyedRateLimiter<RoutingToken>;

#[cfg(test)]
mod tests {
    use super::*;

    fn token(b: u8) -> RoutingToken {
        RoutingToken([b; 32])
    }

    #[test]
    fn allows_up_to_limit_then_rejects() {
        let mut rl = RateLimiter::new(3);
        let t = token(1);
        assert!(rl.allow(&t, 0));
        assert!(rl.allow(&t, 0));
        assert!(rl.allow(&t, 0));
        assert!(!rl.allow(&t, 0), "the 4th attempt in the window is rejected");
    }

    #[test]
    fn resets_on_new_window() {
        let mut rl = RateLimiter::new(1);
        let t = token(1);
        assert!(rl.allow(&t, 0));
        assert!(!rl.allow(&t, 0));
        assert!(rl.allow(&t, 1), "a new window resets the counter");
    }

    #[test]
    fn tokens_are_independent() {
        let mut rl = RateLimiter::new(1);
        assert!(rl.allow(&token(1), 0));
        assert!(rl.allow(&token(2), 0), "a different token has its own budget");
        assert!(!rl.allow(&token(1), 0));
    }

    #[test]
    fn keyed_limiter_works_for_string_subjects() {
        // The generalized limiter caps per arbitrary key (e.g. an account
        // subject), independently per key, resetting each window.
        let mut rl: KeyedRateLimiter<String> = KeyedRateLimiter::new(2);
        let a = "user-a".to_string();
        let b = "user-b".to_string();
        assert!(rl.allow(&a, 0));
        assert!(rl.allow(&a, 0));
        assert!(!rl.allow(&a, 0), "user-a is capped at 2 per window");
        assert!(rl.allow(&b, 0), "user-b has an independent budget");
        assert!(rl.allow(&a, 1), "a new window resets user-a");
    }
}
