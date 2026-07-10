//! Shared wire types for Claude Tunnel (P0.2).
//!
//! Logic-free and serde-serializable. Terms follow `CONTEXT.md`; see ADR-0013
//! (Origin Identity) and ADR-0014 (Capability). This crate must not depend on
//! `ct-agent` or `ct-edge`.

use serde::{Deserialize, Serialize};

pub mod credential;
pub mod noise;

/// Stable crate identifier, used by downstream smoke tests.
pub const CRATE_NAME: &str = "ct-common";

/// The customer account that owns Agents, hostnames, and Tunnels; the unit of
/// authorization and isolation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);

/// A single Agent's stable identifier within a Tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

/// Opaque identifier that addresses a Tunnel in the Mesh Plane; routes a Client
/// to the right Agent without revealing a hostname to the operator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoutingToken(pub [u8; 32]);

/// The Origin's static Noise public key, pinned by Clients to authenticate the
/// Origin end-to-end.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OriginIdentity(pub [u8; 32]);

/// Self-contained connection grant the customer distributes out of band
/// (ADR-0014): possession is sufficient to reach and authenticate an Origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub token: RoutingToken,
    pub origin: OriginIdentity,
    pub edge_addr: String,
}

/// Minimal control-plane framing for the Mesh Plane. Logic-free; variants gain
/// fields as the transport (P1.x) and rendezvous (P1.1) packets land.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlFrame {
    /// Client asks the Edge to rendezvous with the Agent holding `token`.
    RendezvousRequest { token: RoutingToken },
    /// Edge acknowledges with opaque rendezvous coordination bytes.
    RendezvousAccept { coordination: Vec<u8> },
    /// Opaque ciphertext relayed on the fallback path (never decrypted by Edge).
    Relay { payload: Vec<u8> },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(v: &T)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(v).expect("serialize");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, &back, "round-trip mismatch for {json}");
    }

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "ct-common");
    }

    #[test]
    fn roundtrip_ids() {
        roundtrip(&TenantId("tenant-1".into()));
        roundtrip(&AgentId("agent-1".into()));
    }

    #[test]
    fn roundtrip_keys_and_tokens() {
        roundtrip(&RoutingToken([7u8; 32]));
        roundtrip(&OriginIdentity([9u8; 32]));
    }

    #[test]
    fn roundtrip_capability() {
        roundtrip(&Capability {
            token: RoutingToken([1u8; 32]),
            origin: OriginIdentity([2u8; 32]),
            edge_addr: "edge.example:443".into(),
        });
    }

    #[test]
    fn roundtrip_control_frames() {
        roundtrip(&ControlFrame::RendezvousRequest {
            token: RoutingToken([3u8; 32]),
        });
        roundtrip(&ControlFrame::RendezvousAccept {
            coordination: vec![1, 2, 3],
        });
        roundtrip(&ControlFrame::Relay {
            payload: vec![9, 9, 9],
        });
    }
}
