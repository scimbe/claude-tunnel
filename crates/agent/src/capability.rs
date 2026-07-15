//! Capability minting (ADR-0014).
//!
//! The Agent mints a self-contained Capability (Routing Token + Origin Identity
//! + Edge address) that the customer distributes out of band. P2.2 mints the
//! Capability with a fresh random Routing Token; its token is what the control
//! plane registers in the Tunnel Registry (ADR-0006).

use crate::origin::OriginKey;
use ct_common::{Capability, OriginIdentity, RoutingToken};
use rand::RngCore;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

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

/// The Agent's serving identity: the Origin static private key (to terminate the
/// Client↔Origin Noise handshake) and the Capability (Routing Token + Origin
/// Identity) that Clients pin.
pub struct ServingIdentity {
    pub cap: Capability,
    pub origin_private: [u8; 32],
}

/// Resolve the Agent's serving identity, writing the Capability to `cap_path`.
///
/// With `key_path = Some(p)`, the Origin key + Capability are **persisted and
/// shared**: the first Agent generates them and writes the key to `p` (owner-only)
/// and the capability to `cap_path`; later Agents pointed at the same paths
/// **load** them and therefore serve the **same Routing Token** — i.e. multiple
/// Agents back one tunnel (redundancy/failover, #8 R4). Start the first Agent
/// before the peers so the shared files exist.
///
/// With `key_path = None`, a fresh single-Agent identity is minted (the default).
pub fn resolve_serving_identity(
    key_path: Option<&str>,
    cap_path: &str,
    edge: &str,
) -> Result<ServingIdentity, BoxError> {
    if let Some(kp) = key_path {
        // Shared identity: reuse the persisted key + capability if both exist.
        if let (Ok(key), Ok(capb)) = (std::fs::read(kp), std::fs::read(cap_path)) {
            if key.len() == 32 {
                let mut origin_private = [0u8; 32];
                origin_private.copy_from_slice(&key);
                let cap = Capability::decode(&capb)?;
                return Ok(ServingIdentity { cap, origin_private });
            }
        }
        // First agent: generate the identity and persist both for peers to share.
        let origin_key = OriginKey::generate();
        let cap = mint_capability(origin_key.origin_identity(), edge.to_string());
        write_owner_only(kp, &origin_key.private_bytes())?;
        std::fs::write(cap_path, cap.encode())?;
        return Ok(ServingIdentity {
            cap,
            origin_private: origin_key.private_bytes(),
        });
    }
    // Default: a fresh, unique single-agent identity.
    let origin_key = OriginKey::generate();
    let cap = mint_capability(origin_key.origin_identity(), edge.to_string());
    std::fs::write(cap_path, cap.encode())?;
    Ok(ServingIdentity {
        cap,
        origin_private: origin_key.private_bytes(),
    })
}

/// Write `bytes` to `path`, restricting to owner read/write (0600) on Unix — a
/// persisted Origin private key must never be world-readable.
fn write_owner_only(path: &str, bytes: &[u8]) -> Result<(), BoxError> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("ct-{}-{}", std::process::id(), name))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn shared_identity_lets_multiple_agents_serve_one_token() {
        // #8 R4: with a shared origin-key path, the first agent persists the
        // identity and later agents load it — so they serve the SAME token
        // (redundant registrations for one tunnel). Without it, each agent is a
        // unique single-agent identity.
        let key = tmp("origin.key");
        let cap = tmp("cap.bin");
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);

        // "Agent 1" generates + persists; "agent 2" loads the same files.
        let a = resolve_serving_identity(Some(&key), &cap, "edge:443").unwrap();
        let b = resolve_serving_identity(Some(&key), &cap, "edge:443").unwrap();
        assert_eq!(a.cap.token, b.cap.token, "shared routing token → redundancy");
        assert_eq!(a.origin_private, b.origin_private, "shared origin key");
        assert_eq!(a.cap.origin, b.cap.origin, "shared origin identity");
        assert_eq!(b.cap.origin, a.cap.origin);

        // Default (no shared key path) mints unique identities.
        let c = resolve_serving_identity(None, &tmp("c.bin"), "edge:443").unwrap();
        let d = resolve_serving_identity(None, &tmp("d.bin"), "edge:443").unwrap();
        assert_ne!(c.cap.token, d.cap.token, "single-agent identities are unique");

        for f in [&key, &cap, &tmp("c.bin"), &tmp("d.bin")] {
            let _ = std::fs::remove_file(f);
        }
    }

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
