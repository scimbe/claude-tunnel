# Backlog

Parked items from the product grilling session (see `SPEC.md` and `docs/adr/`). Not scheduled; revisit before the relevant build phase.

## Open risks (need resolution before/at build)

- **Billing-side sybil/abuse** — PoW (ADR-0018) deters floods but not a funded adversary; free-tier / billing fraud without KYC is unsolved. Levers to explore: prepaid credit, resource caps, per-Capability economics.
- **Jurisdiction, hosting & payment rails** — incorporation jurisdiction, censorship-tolerant upstreams, crypto billing. Counsel-adjacent; determines whether the ADR-0011 posture is operable at all.
- **CSAM operational process** — concrete report-intake → Termination → metadata-preservation procedure required by the Lawful Floor (ADR-0011).

## Deferred features (post-v1)

- **Browser Plane** — anonymous-browser SNI-passthrough exposure (ADR-0003/0010).
- **Full self-hosting & decentralised coordination** — beyond the self-hostable-ready thin control plane (ADR-0017).
- **Agent redundancy** — multiple Agents per Tunnel / failover.
- **Key-rotation UX** — Capability/Origin-key rotation flows (ADR-0013/0014).
- **Operator opt-in aggregated telemetry** — bounded, opt-in (ADR-0016).
