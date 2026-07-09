# 0015. Peer-to-peer Mesh data path with Edge rendezvous and relay fallback

Status: accepted (refines ADR-0002 and ADR-0006)

Mesh Clients establish a direct peer-to-peer path to the Agent via NAT hole-punching, with the Edge acting as **Rendezvous** coordinator; traffic then flows Client↔Agent directly and the operator is out of the data path. When a direct path cannot be formed (symmetric NAT, restrictive firewalls) the connection falls back to Edge relay. This follows the Tailscale/DERP model.

## Consequences

- **Metadata (ADR-0002):** on a direct path the operator observes only the brief Rendezvous coordination, not per-connection timing/volume; only relayed connections expose those. This strengthens the zero-knowledge guarantee.
- **Edge role (ADR-0006):** the Edge is primarily a Rendezvous coordinator + fallback relay, not an always-on relay; the Tunnel Registry maps a Routing Token to the Agent's Rendezvous info rather than to a fixed relay node.
- Lower operator bandwidth cost and no central payload chokepoint — improving censorship-resistance and sustainability.
- Requires NAT-traversal engineering (STUN-like probing, hole-punching, path selection) in Agent and Client; the direct path exposes Client and Agent IPs to each other (both customer-controlled, acceptable).
