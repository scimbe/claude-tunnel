//! Per-token rate limiting (ADR-0018).
//!
//! A fixed-window counter caps rendezvous attempts per Routing Token, layered
//! on top of the PoW gate. Time is caller-supplied (a window index) so this
//! stays deterministic and wall-clock-free.

use crate::RoutingToken;
use std::collections::HashMap;

/// Fixed-window per-token rate limiter.
pub struct RateLimiter {
    max_per_window: u32,
    /// token -> (current window, count in that window)
    counters: HashMap<RoutingToken, (u64, u32)>,
}

impl RateLimiter {
    pub fn new(max_per_window: u32) -> Self {
        Self {
            max_per_window,
            counters: HashMap::new(),
        }
    }

    /// Record an attempt for `token` in `window`; returns whether it is allowed
    /// (strictly under the per-window limit). A new window resets the count.
    pub fn allow(&mut self, token: &RoutingToken, window: u64) -> bool {
        let entry = self.counters.entry(token.clone()).or_insert((window, 0));
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
}
