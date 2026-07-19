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

    /// The next delay with **equal jitter** applied, given a uniform random sample
    /// `rand01` in `[0, 1)`: the result is `d/2 + rand01 * d/2`, i.e. uniformly in
    /// `[d/2, d]` where `d` is the deterministic exponential delay from
    /// [`Backoff::next_delay`]. This desynchronizes a fleet's reconnect attempts after
    /// a shared-edge outage/restart, so agents don't all re-dial in lockstep and
    /// re-overload the edge exactly as it recovers (#114 #3). It preserves the
    /// exponential growth, the `max` cap (the jitter never exceeds `d ≤ max`), and the
    /// give-up after `max_attempts`. The caller supplies the randomness, so `Backoff`
    /// stays pure and deterministically unit-testable.
    pub fn next_delay_jittered(&mut self, rand01: f64) -> Option<Duration> {
        let d = self.next_delay()?;
        let half = d / 2;
        // span == d - half (half for even nanos, +1ns otherwise); result lands in [half, d].
        let span = d - half;
        Some(half + span.mul_f64(rand01.clamp(0.0, 1.0)))
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
    fn jitter_within_half_to_full_delay_and_still_gives_up() {
        // #114 #3 (frozen): equal jitter spreads each delay uniformly in [d/2, d] so a
        // fleet doesn't reconnect in lockstep, while never exceeding the exponential
        // delay (hence never exceeding max), and the give-up semantics are unchanged.
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(1);
        assert_eq!(
            Backoff::new(base, max, 10).next_delay_jittered(1.0),
            Some(base),
            "rand01=1 -> the full deterministic delay"
        );
        assert_eq!(
            Backoff::new(base, max, 10).next_delay_jittered(0.0),
            Some(base / 2),
            "rand01=0 -> half the delay (the floor, still a real wait)"
        );

        // Across the exponential growth + cap, every jittered delay lands in [d/2, d]
        // and never exceeds max — compared against a lockstep deterministic backoff.
        for attempt in 0..6u32 {
            let mut det = Backoff::new(base, max, 10);
            for _ in 0..attempt {
                det.next_delay();
            }
            let d = det.next_delay().unwrap();
            for &r in &[0.0f64, 0.33, 0.66, 0.999] {
                let mut jit = Backoff::new(base, max, 10);
                for _ in 0..attempt {
                    jit.next_delay();
                }
                let j = jit.next_delay_jittered(r).unwrap();
                assert!(j >= d / 2 && j <= d, "attempt {attempt} r={r}: {j:?} not in [{:?}, {d:?}]", d / 2);
                assert!(j <= max, "jitter never exceeds the max cap");
            }
        }

        let mut b = Backoff::new(base, max, 2);
        assert!(b.next_delay_jittered(0.5).is_some());
        assert!(b.next_delay_jittered(0.5).is_some());
        assert_eq!(b.next_delay_jittered(0.5), None, "gives up after max_attempts, jitter or not");
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
