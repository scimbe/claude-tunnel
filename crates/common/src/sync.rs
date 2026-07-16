//! Poison-resilient locking (#24).
//!
//! `std::sync::Mutex` poisons **permanently** if a thread panics while holding
//! the lock: every later `lock().unwrap()` then panics too, so a single
//! panic in one critical section takes a whole subsystem down (the Edge routing
//! registry, or a control-plane store) until the process restarts — a narrow bug
//! becomes an indefinite outage. For shared state, availability matters more than
//! refusing to touch possibly-torn state (ADR-0018): recover the guard instead of
//! cascading the failure. Use for SHARED state (registries, stores, limiters); a
//! recovered map/connection is at worst slightly inconsistent, which is
//! preferable to 500ing every request forever. Do NOT use it to paper over a
//! torn invariant that must fail closed.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Extension adding a poison-recovering lock to [`std::sync::Mutex`].
pub trait MutexExt<T: ?Sized> {
    /// Lock, recovering the guard if the mutex was poisoned by a panic in a
    /// previous critical section (instead of panicking again).
    fn lock_safe(&self) -> MutexGuard<'_, T>;
}

impl<T: ?Sized> MutexExt<T> for Mutex<T> {
    fn lock_safe(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn lock_safe_recovers_a_poisoned_mutex() {
        let m = Arc::new(Mutex::new(0u32));
        let m2 = Arc::clone(&m);
        // Poison the mutex: panic while holding the lock, mid-update.
        let _ = std::thread::spawn(move || {
            let mut g = m2.lock().unwrap();
            *g = 1;
            panic!("poison the lock");
        })
        .join();
        assert!(m.lock().is_err(), "std lock() sees the mutex as poisoned");
        // lock_safe still yields a usable guard (the last write survived).
        let g = m.lock_safe();
        assert_eq!(*g, 1, "recovered the guard instead of panicking");
    }
}
