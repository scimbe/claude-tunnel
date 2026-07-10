//! Tunnel Registry (ADR-0006, ADR-0017).
//!
//! Maps a Routing Token to the tunnel currently serving it. The control plane
//! owns the registry; the Edge consults it to route a Client to the right Agent
//! without revealing a hostname. In-memory for now (P2.1); replication
//! (ADR-0006) and rendezvous info (ADR-0015) are later packets.

use std::collections::HashMap;

use ct_common::{AgentId, RoutingToken, TenantId};

/// What a Routing Token resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelInfo {
    pub tenant: TenantId,
    pub agent: AgentId,
}

/// In-memory Tunnel Registry.
#[derive(Default)]
pub struct TunnelRegistry {
    tunnels: HashMap<RoutingToken, TunnelInfo>,
}

impl TunnelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) the tunnel served by `token`.
    pub fn register(&mut self, token: RoutingToken, info: TunnelInfo) {
        self.tunnels.insert(token, info);
    }

    /// Look up the tunnel for `token`.
    pub fn lookup(&self, token: &RoutingToken) -> Option<&TunnelInfo> {
        self.tunnels.get(token)
    }

    /// Remove the tunnel for `token`; returns whether it existed.
    pub fn unregister(&mut self, token: &RoutingToken) -> bool {
        self.tunnels.remove(token).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> TunnelInfo {
        TunnelInfo {
            tenant: TenantId("tenant-1".into()),
            agent: AgentId("agent-1".into()),
        }
    }

    #[test]
    fn register_then_lookup() {
        let mut registry = TunnelRegistry::new();
        let token = RoutingToken([1u8; 32]);
        registry.register(token.clone(), info());
        assert_eq!(registry.lookup(&token), Some(&info()));
    }

    #[test]
    fn lookup_unknown_is_none() {
        let registry = TunnelRegistry::new();
        assert_eq!(registry.lookup(&RoutingToken([9u8; 32])), None);
    }

    #[test]
    fn unregister_removes() {
        let mut registry = TunnelRegistry::new();
        let token = RoutingToken([1u8; 32]);
        registry.register(token.clone(), info());
        assert!(registry.unregister(&token));
        assert_eq!(registry.lookup(&token), None);
        assert!(!registry.unregister(&token), "second unregister is a no-op");
    }

    #[test]
    fn re_register_overwrites() {
        let mut registry = TunnelRegistry::new();
        let token = RoutingToken([1u8; 32]);
        registry.register(token.clone(), info());
        let updated = TunnelInfo {
            tenant: TenantId("tenant-2".into()),
            agent: AgentId("agent-2".into()),
        };
        registry.register(token.clone(), updated.clone());
        assert_eq!(registry.lookup(&token), Some(&updated));
    }
}
