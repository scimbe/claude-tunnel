# 0018. Availability and blind DoS resistance

Status: accepted

Under the P2P data path (ADR-0015), established direct connections survive an Edge outage; only new-connection setup needs the Rendezvous. Availability therefore reduces to replicating the Rendezvous endpoint and Tunnel Registry across multiple nodes. For denial-of-service the operator is blind and has dropped WAF, abuse feeds (ADR-0011), and KYC (ADR-0012), so it relies on a layered scheme: expensive operations (requesting a Rendezvous, allocating a relay slot) require a valid signed Capability or a small proof-of-work; per-Token/identity rate limits apply; and Edge/anycast capacity absorbs volumetric floods. The proof-of-work also serves as the primary sybil-resistance lever in the absence of KYC.

## Consequences

- Clients incur a proof-of-work cost on connection setup; difficulty must be tuned to deter floods without harming legitimate use, and a funded adversary can still pay it — **billing-side sybil/abuse remains an open branch**.
- Rendezvous and Tunnel Registry must be replicated (multi-node, replicated state); established P2P flows are unaffected by their outage.
- No upstream DDoS-scrubbing third party is used, to avoid introducing a metadata-seeing pressure point.
