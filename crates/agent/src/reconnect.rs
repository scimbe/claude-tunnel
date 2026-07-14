//! Reconnect backoff (issue #5 / P1.2b).
//!
//! When the Agent's Edge connection drops, it re-dials and re-registers rather
//! than dying. [`Backoff`] paces those attempts: delays grow exponentially from
//! `base`, cap at `max`, and `next_delay` yields `None` once `max_attempts` is
//! reached — so the caller gives up cleanly with a clear error instead of
//! busy-looping forever. Pure and deterministic (no clock), so it is fully
//! unit-testable; the serve loop supplies the actual sleeping.

use std::time::Duration;

/// Bounded exponential backoff for reconnect attempts.
pub struct Backoff {
    base: Duration,
    max: Duration,
    max_attempts: u32,
    attempt: u32,
}

impl Backoff {
    /// `base` is the first delay; each subsequent delay doubles, capped at `max`;
    /// after `max_attempts` delays, [`Backoff::next_delay`] returns `None`.
    pub fn new(base: Duration, max: Duration, max_attempts: u32) -> Self {
        Self {
            base,
            max,
            max_attempts,
            attempt: 0,
        }
    }

    /// The delay to wait before the next reconnect attempt, or `None` once
    /// `max_attempts` have been handed out (the caller should then give up).
    pub fn next_delay(&mut self) -> Option<Duration> {
        if self.attempt >= self.max_attempts {
            return None;
        }
        let shift = self.attempt.min(31);
        let delay = self
            .base
            .checked_mul(1u32 << shift)
            .unwrap_or(self.max)
            .min(self.max);
        self.attempt += 1;
        Some(delay)
    }

    /// Reset the counter after a successful (re)connection, so the next drop
    /// starts backing off from `base` again.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// How many delays have been handed out since the last reset.
    pub fn attempts_made(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delays_grow_exponentially_and_cap_at_max() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(1), 10);
        assert_eq!(b.next_delay(), Some(Duration::from_millis(100)));
        assert_eq!(b.next_delay(), Some(Duration::from_millis(200)));
        assert_eq!(b.next_delay(), Some(Duration::from_millis(400)));
        assert_eq!(b.next_delay(), Some(Duration::from_millis(800)));
        assert_eq!(b.next_delay(), Some(Duration::from_secs(1)), "capped at max");
        assert_eq!(b.next_delay(), Some(Duration::from_secs(1)), "stays capped");
    }

    #[test]
    fn gives_up_after_max_attempts() {
        let mut b = Backoff::new(Duration::from_millis(1), Duration::from_millis(10), 3);
        assert!(b.next_delay().is_some());
        assert!(b.next_delay().is_some());
        assert!(b.next_delay().is_some());
        assert_eq!(b.next_delay(), None, "gives up cleanly after max_attempts");
        assert_eq!(b.attempts_made(), 3);
    }

    #[test]
    fn reset_restarts_from_base() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(1), 10);
        b.next_delay();
        b.next_delay();
        b.reset();
        assert_eq!(b.attempts_made(), 0);
        assert_eq!(b.next_delay(), Some(Duration::from_millis(100)), "back to base");
    }
}
