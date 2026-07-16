//! In-memory ACME challenge record store (#31 FD4 / #23 BP4c).
//!
//! Maps a challenge name (`_acme-challenge.<host>`, lowercased) to its TXT
//! value(s). The localhost HTTP API mutates it (a later sub-packet); the DNS
//! responder reads it. Poison-safe locking so one panicked writer can't wedge
//! cert issuance.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// Thread-safe store of challenge name -> TXT values.
#[derive(Default)]
pub struct AcmeDnsStore {
    txt: Mutex<HashMap<String, Vec<String>>>,
}

impl AcmeDnsStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<String>>> {
        self.txt.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Publish a TXT value for `name` (ACME may need two challenges live at once,
    /// so values accumulate). Names are matched case-insensitively.
    pub fn add_txt(&self, name: &str, value: &str) {
        self.lock()
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(value.to_string());
    }

    /// Replace all TXT values for `name` with a single value.
    pub fn set_txt(&self, name: &str, value: &str) {
        self.lock()
            .insert(name.to_ascii_lowercase(), vec![value.to_string()]);
    }

    /// Remove all TXT values for `name` (challenge cleanup).
    pub fn clear(&self, name: &str) {
        self.lock().remove(&name.to_ascii_lowercase());
    }

    /// The TXT values currently published for `name` (empty if none).
    pub fn txt(&self, name: &str) -> Vec<String> {
        self.lock()
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_publishes_accumulates_and_clears_case_insensitively() {
        let s = AcmeDnsStore::new();
        assert!(s.txt("_acme-challenge.host.test").is_empty());

        // add accumulates (two live challenges); lookup is case-insensitive.
        s.add_txt("_acme-challenge.Host.Test", "tok-a");
        s.add_txt("_acme-challenge.host.test", "tok-b");
        assert_eq!(
            s.txt("_ACME-CHALLENGE.HOST.TEST"),
            vec!["tok-a".to_string(), "tok-b".to_string()]
        );

        // set replaces; clear removes.
        s.set_txt("_acme-challenge.host.test", "only");
        assert_eq!(s.txt("_acme-challenge.host.test"), vec!["only".to_string()]);
        s.clear("_acme-challenge.host.test");
        assert!(s.txt("_acme-challenge.host.test").is_empty());
    }
}
