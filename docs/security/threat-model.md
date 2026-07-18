# Threat model & secrets management (production)

Production security posture for the hosted + self-hostable service. Updates the
v1 academic posture (SPEC §7–§9) for the productionization pivot: conventional
Keycloak/OIDC accounts everywhere (the pseudonymity marketing claim is dropped),
while the end-to-end Noise payload encryption is retained.

## Assets

- **Payload traffic** between a client and its origin.
- **Account / identity** data (Keycloak subject ↔ tunnel account, credit ledger).
- **Enrollment + registry state** (join tokens, agent bindings, tunnel routes).
- **Signing material**: the edge's internal CA key, the Keycloak realm keys.

## Trust boundaries & what each party sees

| Party | Sees | Does **not** see |
|-------|------|------------------|
| Edge / control plane (operator) | Ciphertext, routing metadata, account id, billing | **Payload plaintext** (Noise E2E terminates at client↔origin) |
| Control plane | Keycloak subject, credit balance, tunnel registry | Origin private key, payload |
| Client | Its own payload, the edge CA root | Other tenants' traffic |

The operator can route and bill your traffic but cannot read it — the honest
claim is "we can't read what you send", not anonymity.

## Adversaries & controls

| Adversary / abuse | Control | Status |
|-------------------|---------|--------|
| On-path eavesdropper | Noise_IK E2E; QUIC/TLS transport; edge sees only ciphertext | shipped (M8, M20) |
| Rogue/rotated edge cert | Internal CA, clients trust the CA root (rotation without re-pinning) | shipped (M20) |
| Unauthenticated actor | OIDC bearer verification on `/me/*`; account derived from the token subject | shipped (M19) |
| Rendezvous flood (unfunded) | PoW gate (always on) + per-token rendezvous rate limit and per-edge connection cap, both opt-in via `CT_EDGE_RENDEZVOUS_MAX_PER_MIN` / `CT_EDGE_MAX_CONNECTIONS` | shipped (ADR-0018; #86) |
| Single account exhausting issuance | Per-subject issuance rate limit → 429 before any ledger touch | shipped (M23.1) |
| Vulnerable dependency | `cargo audit` against a committed, pinned `Cargo.lock` | shipped (M23.2) |
| Committed credential leak | `scripts/check-no-secrets.sh` guard (PEM keys, cloud keys, tracked `.env`) | shipped (M23.3) |
| State loss on restart | Durable SQLite (enrollment/registry/ledger) | shipped (M18) |
| Poisoned local build (gate write-mount) | Server-side CI (`.github/workflows/ci.yml`) re-runs build+test+audit+secret-guard on `main`, independent of the local gate | accepted residual (#78 SEC78c; mitigated by SEC78b) |
| Funded sybil / billing fraud | **unresolved** — PoW does not deter a paying adversary | open (SPEC §9.1) |

## Secrets inventory & handling

| Secret | Where it lives | Handling |
|--------|----------------|----------|
| Keycloak realm signing key | Keycloak; the verifier fetches/holds the public half | never in this repo; issuer URL is public config, not a secret |
| Edge internal CA key | Generated at edge startup, in memory | not persisted or committed; only the CA **root cert** is distributed |
| Origin Noise private key | Agent process (custodian) | only the public half travels (in the Capability) |
| Deployment env (`CT_OIDC_ISSUER`, ports) | `docker/deploy/.env` (self-host) / K8s Secret (hosted) | `.env` is **gitignored**; only `.env.example` templates are committed; K8s secrets supplied out-of-band (sealed-secrets / external-secrets) |
| Join token | Operator → agent, single-use | short-lived, consumed on first redeem |

**Rules:** no real secret is ever committed; `Cargo.lock` is committed and pinned;
`scripts/check-no-secrets.sh` runs in CI to enforce the no-committed-secrets rule;
rotate the edge CA by restart (clients trust the CA root, so no re-pinning).

## Residual risks

1. **Funded sybil / billing fraud** — accounts are now real (Keycloak), which
   raises the bar, but a paying adversary is still not deterred (SPEC §9.1).
2. **Control-plane metadata** — the operator sees account id, routing and billing
   metadata (not payload). Minimize retention; document in the privacy policy.
3. **Jurisdiction / lawful-floor process** — operational, not code (SPEC §9.2–9.3).
