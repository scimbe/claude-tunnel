# 0016. Agent-side, customer-owned observability

Status: accepted

Because the operator is provider-blind and, under the P2P data path (ADR-0015), often out of the data path entirely, per-connection observability can only exist at the customer's Agent/Client. The Agent emits logs and metrics locally in open formats (OpenTelemetry / Prometheus) that the customer owns and can export to their own stack. The operator's dashboard is limited to what it structurally knows: tunnel online/offline, Rendezvous success rate, and relay-fallback byte counts required for billing. The operator does not collect per-connection detail.

## Consequences

- Support is harder: the operator cannot see customer traffic to debug; troubleshooting relies on customer-shared Agent telemetry.
- The product demo is less flashy than a rich central dashboard — an accepted trade for the ZK / censorship-resistance brand.
- Relay-fallback billing must be derivable from the minimal counters the Edge keeps for relayed connections only.
- Any future operator-side aggregated telemetry must be opt-in and explicitly bounded.
