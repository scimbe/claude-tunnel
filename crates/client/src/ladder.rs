//! #31 FD3 — the client's transport fallback ladder. Restrictive client networks
//! (HAW field evidence: `:8090`/`:4433`/UDP all time out) allow only outbound TCP
//! :443, so a client must try a sequence of `(transport, port)` rungs and remember
//! which one worked *per network* — not just today's two-rung QUIC:4433 →
//! TLS-TCP:4433. This module (FD3-a) is the pure ordering + per-network cache; the
//! live socket dialing is injected (FD3-b), so the ladder logic is fully testable
//! without real sockets or timeouts.

use std::collections::HashMap;

/// One rung of the fallback ladder: a transport over a port on the edge host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rung {
    /// QUIC (UDP) on the given port.
    Quic(u16),
    /// TLS-over-TCP on the given port.
    TlsTcp(u16),
}

/// The default ladder: `QUIC:4433 → TLS-TCP:4433 → QUIC:443 → TLS-TCP:443`.
/// Ordered most-direct/fastest first (QUIC on the dedicated port), most
/// restrictive-network-friendly last (TLS-TCP on :443, the one port such networks
/// reliably allow). The `:443` rungs reach the unified front door (FD2).
pub fn default_ladder() -> Vec<Rung> {
    vec![
        Rung::Quic(4433),
        Rung::TlsTcp(4433),
        Rung::Quic(443),
        Rung::TlsTcp(443),
    ]
}

/// Remembers the last rung that worked, keyed by an opaque network signature, so a
/// re-connect on the same restrictive network skips straight to the rung that
/// succeeded before instead of re-paying a timeout on every blocked rung first.
#[derive(Default, Clone)]
pub struct LadderCache {
    by_network: HashMap<String, Rung>,
}

impl LadderCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The rung last known to work on `network`, if any.
    pub fn remembered(&self, network: &str) -> Option<Rung> {
        self.by_network.get(network).copied()
    }

    /// Record `rung` as the working rung for `network`.
    pub fn remember(&mut self, network: &str, rung: Rung) {
        self.by_network.insert(network.to_string(), rung);
    }
}

/// The order to attempt rungs for `network`: the cached-good rung first (when it
/// is still part of `ladder`), then the rest of `ladder` in its natural order,
/// with the cached rung not repeated. A stale cached rung (no longer in `ladder`)
/// is ignored, and an empty cache yields `ladder` unchanged.
pub fn attempt_order(cache: &LadderCache, network: &str, ladder: &[Rung]) -> Vec<Rung> {
    let mut order: Vec<Rung> = Vec::with_capacity(ladder.len());
    if let Some(cached) = cache.remembered(network) {
        if ladder.contains(&cached) {
            order.push(cached);
        }
    }
    for r in ladder {
        if Some(*r) != order.first().copied() {
            order.push(*r);
        }
    }
    order
}

/// Try each rung in [`attempt_order`] via the injected async `dial`, returning the
/// first rung that connects together with its connection, and recording that rung
/// in `cache` for `network`. `dial` yields `None` for an unreachable rung (a
/// timeout/refusal in the live path), so the ladder walks on to the next rung.
/// Returns `None` only when every rung fails.
pub async fn connect_via_ladder<T, F, Fut>(
    cache: &mut LadderCache,
    network: &str,
    ladder: &[Rung],
    mut dial: F,
) -> Option<(Rung, T)>
where
    F: FnMut(Rung) -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    for rung in attempt_order(cache, network, ladder) {
        if let Some(conn) = dial(rung).await {
            cache.remember(network, rung);
            return Some((rung, conn));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn default_ladder_is_direct_first_restrictive_last() {
        assert_eq!(
            default_ladder(),
            vec![
                Rung::Quic(4433),
                Rung::TlsTcp(4433),
                Rung::Quic(443),
                Rung::TlsTcp(443),
            ]
        );
    }

    #[test]
    fn attempt_order_puts_the_cached_rung_first_without_duplicating() {
        let ladder = default_ladder();
        let mut cache = LadderCache::new();

        // Empty cache -> the ladder unchanged.
        assert_eq!(attempt_order(&cache, "net-a", &ladder), ladder);

        // A remembered rung is tried first, and appears exactly once.
        cache.remember("net-a", Rung::TlsTcp(443));
        assert_eq!(
            attempt_order(&cache, "net-a", &ladder),
            vec![
                Rung::TlsTcp(443),
                Rung::Quic(4433),
                Rung::TlsTcp(4433),
                Rung::Quic(443),
            ]
        );

        // A different network is unaffected by net-a's cache.
        assert_eq!(attempt_order(&cache, "net-b", &ladder), ladder);

        // A stale cached rung (not in this ladder) is ignored.
        cache.remember("net-c", Rung::TlsTcp(8443));
        assert_eq!(attempt_order(&cache, "net-c", &ladder), ladder);
    }

    #[tokio::test]
    async fn connect_via_ladder_picks_first_reachable_and_caches_it() {
        let ladder = default_ladder();
        let mut cache = LadderCache::new();
        let tried: Arc<Mutex<Vec<Rung>>> = Arc::new(Mutex::new(Vec::new()));

        // Only TLS-TCP:443 is reachable (a :443-only restrictive network). The
        // ladder must walk past the three blocked rungs and land there.
        let tried1 = Arc::clone(&tried);
        let got = connect_via_ladder(&mut cache, "haw", &ladder, |rung| {
            let tried = Arc::clone(&tried1);
            async move {
                tried.lock().unwrap().push(rung);
                (rung == Rung::TlsTcp(443)).then_some("conn")
            }
        })
        .await;
        assert_eq!(got, Some((Rung::TlsTcp(443), "conn")));
        assert_eq!(
            *tried.lock().unwrap(),
            ladder,
            "all rungs attempted in order until the reachable one"
        );
        assert_eq!(cache.remembered("haw"), Some(Rung::TlsTcp(443)), "working rung cached");

        // Re-connect on the same network: the cached rung is tried FIRST, so the
        // blocked rungs are not re-attempted.
        tried.lock().unwrap().clear();
        let tried2 = Arc::clone(&tried);
        let got2 = connect_via_ladder(&mut cache, "haw", &ladder, |rung| {
            let tried = Arc::clone(&tried2);
            async move {
                tried.lock().unwrap().push(rung);
                (rung == Rung::TlsTcp(443)).then_some("conn")
            }
        })
        .await;
        assert_eq!(got2, Some((Rung::TlsTcp(443), "conn")));
        assert_eq!(
            tried.lock().unwrap().first().copied(),
            Some(Rung::TlsTcp(443)),
            "cached rung attempted first on re-connect"
        );
        assert_eq!(tried.lock().unwrap().len(), 1, "no blocked rung re-attempted");
    }

    #[tokio::test]
    async fn connect_via_ladder_returns_none_when_every_rung_fails() {
        let ladder = default_ladder();
        let mut cache = LadderCache::new();
        let got: Option<(Rung, &str)> =
            connect_via_ladder(&mut cache, "dead", &ladder, |_rung| async { None }).await;
        assert_eq!(got, None);
        assert_eq!(cache.remembered("dead"), None, "nothing cached when all fail");
    }
}
