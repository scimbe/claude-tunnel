# 0010. Mesh Plane is the v1 access plane; Browser Plane deferred

Status: accepted (revises Decision 2, which had sequenced browsers first)

Choosing a censorship-resistant, metadata-minimising posture makes the client-software **Mesh Plane** the priority: it routes by opaque token (hiding the hostname from the operator), supports any protocol including UDP, and gives Clients a fully client-authenticated end-to-end path. The anonymous **Browser Plane** — SNI-routed TLS passthrough — is deferred, because it structurally leaks the hostname to the operator and cannot serve metadata-sensitive users. This reverses the earlier "browsers first" sequencing.

## Consequences

- v1 requires operator client software; there is no "paste a URL, any browser visits it" in v1.
- Mesh data-plane security uses client-authenticated, pinned/tunnel-native keys (e.g. Noise or mTLS with pinned identities), so the Agent-side public-CA ACME flow (ADR-0003) applies only when the Browser Plane ships.
- QUIC (ADR-0004) is reinforced: DATAGRAM support lets the Mesh carry UDP as well as TCP.
- The Edge + Tunnel Registry (ADR-0006) still route Mesh connections; peer-to-peer / NAT-hole-punched Client↔Agent paths with the Edge as fallback relay are a possible later optimisation.
