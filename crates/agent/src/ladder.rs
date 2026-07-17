//! #46 FB-a — the agent's edge-connection fallback ladder. An agent whose
//! outbound `:4433` (QUIC + TLS-TCP) is firewall-blocked must still reach the edge
//! to register (`'A'`/`'B'`) and revoke (`'R'`). The edge's unified `:443` front
//! door (#31 FD2) already routes `ALPN=ct-edge` to the agent relay, so the missing
//! piece is agent-side: try the configured port first, then fall back to `:443`.
//!
//! This module is the pure ordering (FB-a); the live dialing + `ALPN=ct-edge` on
//! the TLS-TCP rung is FB-b, so the ordering stays unit-testable without sockets.

use std::net::SocketAddr;

/// One edge endpoint to try: a transport at an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeRung {
    /// QUIC (UDP) at this address — the primary, fastest path.
    Quic(SocketAddr),
    /// TLS-over-TCP at this address — the firewall-friendlier fallback.
    TlsTcp(SocketAddr),
}

/// The ordered endpoints an agent attempts to reach the edge (#46): QUIC then
/// TLS-TCP on the configured `edge` port, and — when `fallback_443` is on — the
/// unified `:443` front door (TLS-TCP) as the last rung. The `:443` rung is only
/// appended when the configured port isn't already `443`, so it is never doubled.
pub fn edge_ladder(edge: SocketAddr, fallback_443: bool) -> Vec<EdgeRung> {
    let mut rungs = vec![EdgeRung::Quic(edge), EdgeRung::TlsTcp(edge)];
    if fallback_443 && edge.port() != 443 {
        rungs.push(EdgeRung::TlsTcp(SocketAddr::new(edge.ip(), 443)));
    }
    rungs
}

/// The TLS-TCP addresses to try, in order, for the TCP-fallback path (#46 FB-c):
/// the configured edge port first, then the `:443` front door when `fallback_443`
/// is on. Derived from [`edge_ladder`] by keeping the TLS-TCP rungs — QUIC is
/// dialed separately on the primary path.
pub fn tcp_rungs(edge: SocketAddr, fallback_443: bool) -> Vec<SocketAddr> {
    edge_ladder(edge, fallback_443)
        .into_iter()
        .filter_map(|r| match r {
            EdgeRung::TlsTcp(a) => Some(a),
            EdgeRung::Quic(_) => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 2], port))
    }

    #[test]
    fn tcp_rungs_are_the_tls_tcp_addresses_in_order() {
        assert_eq!(tcp_rungs(addr(4433), false), vec![addr(4433)]);
        assert_eq!(tcp_rungs(addr(4433), true), vec![addr(4433), addr(443)]);
        assert_eq!(tcp_rungs(addr(443), true), vec![addr(443)], "no duplicate :443");
    }

    #[test]
    fn ladder_without_fallback_is_quic_then_tls_tcp_on_the_configured_port() {
        assert_eq!(
            edge_ladder(addr(4433), false),
            vec![EdgeRung::Quic(addr(4433)), EdgeRung::TlsTcp(addr(4433))]
        );
    }

    #[test]
    fn ladder_with_fallback_appends_the_443_front_door() {
        assert_eq!(
            edge_ladder(addr(4433), true),
            vec![
                EdgeRung::Quic(addr(4433)),
                EdgeRung::TlsTcp(addr(4433)),
                EdgeRung::TlsTcp(addr(443)),
            ]
        );
    }

    #[test]
    fn ladder_does_not_double_the_443_rung_when_already_configured_on_443() {
        assert_eq!(
            edge_ladder(addr(443), true),
            vec![EdgeRung::Quic(addr(443)), EdgeRung::TlsTcp(addr(443))],
            "no duplicate :443 rung"
        );
    }
}
