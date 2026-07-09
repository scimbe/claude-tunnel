# 0017. Thin, self-hostable-ready control plane

Status: accepted

Prior decisions hollow out the operator's central role: it is not in the trust path (ADR-0013/0014), not in the data path when P2P succeeds (ADR-0015), and not a data collector (ADR-0016). The control plane is therefore a thin, API-first coordination service — Agent enrollment, Tunnel Registry, Rendezvous endpoint, billing — with a minimal dashboard as one client. Because a hosted control plane is the single seizable point a censor would target, every component is architected to be self-hostable, so customers can run their own coordination instance and survive operator takedown. Full self-hosting and full decentralization are deferred beyond v1.

## Consequences

- CLI/API is the primary interface; the dashboard is thin and optional.
- Capability minting stays Agent-side (ADR-0014); the control plane never brokers trust material.
- Self-hostability is a design constraint from day one (clean component boundaries, documented interfaces) even though the hosted instance ships first.
- "Self-host if we are taken down" becomes the flagship resilience / censorship-resistance feature on the roadmap.
