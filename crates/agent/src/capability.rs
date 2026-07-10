//! Capability minting (ADR-0014).
//!
//! The Agent mints a self-contained Capability (Routing Token + Origin Identity
//! + Edge address) that the customer distributes out of band. P2.2 mints the
//! Capability with a fresh random Routing Token; its token is what the control
//! plane registers in the Tunnel Registry (ADR-0006).

use ct_common::{Capability, OriginIdentity, RoutingToken};
use rand::RngCore;

/// Mint a Capability for an Origin reachable via `edge_addr`, generating a fresh
/// random Routing Token.
pub fn mint_capability(origin: OriginIdentity, edge_addr: String) -> Capability {
    let mut token = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);
    Capability {
        token: RoutingToken(token),
        origin,
        edge_addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mints_distinct_tokens() {
        let a = mint_capability(OriginIdentity([1u8; 32]), "edge:443".into());
        let b = mint_capability(OriginIdentity([1u8; 32]), "edge:443".into());
        assert_ne!(a.token, b.token, "each Capability gets a fresh Routing Token");
        assert_eq!(a.origin, OriginIdentity([1u8; 32]));
        assert_eq!(a.edge_addr, "edge:443");
    }

    #[test]
    fn capability_token_registers_in_registry() {
        use ct_common::{AgentId, TenantId};
        use ct_control_plane::registry::{TunnelInfo, TunnelRegistry};

        let cap = mint_capability(OriginIdentity([2u8; 32]), "edge.example:443".into());
        let mut registry = TunnelRegistry::new();
        let info = TunnelInfo {
            tenant: TenantId("tenant-1".into()),
            agent: AgentId("agent-1".into()),
        };
        registry.register(cap.token.clone(), info.clone());
        assert_eq!(registry.lookup(&cap.token), Some(&info));
    }
}
