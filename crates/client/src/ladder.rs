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

/// The ladder to attempt, honoring `CT_CLIENT_FORCE_TCP` (#31 FD3-c): when TCP is
/// forced (the UDP-blocked smoke, or a known QUIC-hostile network) keep only the
/// TLS-TCP rungs, so the client doesn't burn a timeout on every QUIC rung first.
pub fn filtered_ladder(force_tcp: bool) -> Vec<Rung> {
    let full = default_ladder();
    if force_tcp {
        full.into_iter()
            .filter(|r| matches!(r, Rung::TlsTcp(_)))
            .collect()
    } else {
        full
    }
}

/// The cache key for the current network (#31 FD3-c). Prefers an explicit
/// `CT_CLIENT_NET_SIG` (operators/tests pin it); else a best-effort key from the
/// default egress interface's IPv4 /24 (stable per LAN, distinct across networks);
/// else `"default"`. It only needs to be stable-per-network and distinct-across —
/// it is a local cache key and never leaves the host.
pub fn network_signature() -> String {
    network_signature_from(
        std::env::var("CT_CLIENT_NET_SIG").ok(),
        local_egress_ip(),
    )
}

/// Pure core of [`network_signature`] (testable): explicit override wins, else the
/// egress IP is reduced to a stable per-network key.
fn network_signature_from(override_env: Option<String>, egress: Option<std::net::IpAddr>) -> String {
    if let Some(s) = override_env
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return s;
    }
    match egress {
        Some(std::net::IpAddr::V4(ip)) => {
            let o = ip.octets();
            format!("v4:{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Some(std::net::IpAddr::V6(ip)) => format!("v6:{ip}"),
        None => "default".to_string(),
    }
}

/// Best-effort local egress IP: "connect" a UDP socket to an unrouted public
/// address (no packet is sent — it only makes the OS pick the default-route source
/// interface) and read the socket's local address. `None` when there is no route.
fn local_egress_ip() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    // 192.0.2.1 is TEST-NET-1 (RFC 5737): never a real host, so nothing is
    // contacted; connect() only fixes the source interface via the routing table.
    sock.connect(("192.0.2.1", 9)).ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};

    #[test]
    fn filtered_ladder_keeps_only_tcp_when_forced() {
        assert_eq!(filtered_ladder(false), default_ladder());
        assert_eq!(
            filtered_ladder(true),
            vec![Rung::TlsTcp(4433), Rung::TlsTcp(443)],
            "force-TCP drops the QUIC rungs"
        );
    }

    #[test]
    fn network_signature_prefers_override_then_reduces_egress_ip() {
        let v4 = Some(IpAddr::V4(Ipv4Addr::new(141, 22, 33, 44)));
        // Explicit override wins verbatim.
        assert_eq!(network_signature_from(Some("pinned-net".into()), v4), "pinned-net");
        // A blank override is ignored -> fall through to the egress key.
        assert_eq!(network_signature_from(Some("  ".into()), v4), "v4:141.22.33.0/24");
        // IPv4 is reduced to its /24; IPv6 kept whole; no route -> "default".
        assert_eq!(network_signature_from(None, v4), "v4:141.22.33.0/24");
        assert_eq!(
            network_signature_from(None, Some(IpAddr::V6(Ipv6Addr::LOCALHOST))),
            "v6:::1"
        );
        assert_eq!(network_signature_from(None, None), "default");
    }

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
