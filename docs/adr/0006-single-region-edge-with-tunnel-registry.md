# 0006. Single-region Edge for v1, built around a first-class Tunnel Registry

Status: accepted

A Client connection can land on any Edge node but must reach the specific node holding its Agent's outbound tunnel, so routing depends on a hostname → Edge-node mapping at every scale. v1 launches in a single region / small shared cluster where every Edge node reads one Tunnel Registry. The registry and the node-lookup path are built as first-class components now, so that expanding to multi-region anycast with cross-PoP forwarding is a deployment change rather than a rewrite. Operating a global backbone is deferred until load justifies it.

## Consequences

- The Tunnel Registry is a core component from day one, even with a single region.
- Cross-PoP forwarding is designed for but not deployed in v1.
- GeoDNS / region-pinning is explicitly rejected because it would forfeit the anycast upgrade path.
