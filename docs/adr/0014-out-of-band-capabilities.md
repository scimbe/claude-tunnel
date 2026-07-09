# 0014. Out-of-band capability links for Mesh trust bootstrapping

Status: accepted

Clients need the Routing Token and pinned Origin Identity before the Noise handshake (ADR-0013) can run, and the operator must not become a trust anchor. The Agent therefore generates a self-contained **Capability** — Routing Token + Origin Identity + Edge address — which the customer distributes to authorized Clients through their own out-of-band channel. The operator stores only the opaque token-to-tunnel mapping and never holds the Origin key, so it cannot forge or be compelled to surrender end-to-end trust. Revocation is rotation of the Token and/or Origin key. Trust-on-first-use is offered only as an explicit low-friction fallback, with its first-connection MITM window documented.

## Consequences

- Distribution UX is the customer's problem; the product should make Capabilities easy to generate, share, and rotate, but does not broker them.
- Leaking a Capability is equivalent to leaking access; rotation must be cheap and immediate.
- Client onboarding requires a manual step (import a Capability), heavier than the Browser Plane's "just open a URL."
