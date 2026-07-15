# Operations runbook

How to deploy, operate, and respond to incidents for a Claude Tunnel deployment.
Commands assume the repo root.

## Deploy

### Self-host (Docker Compose)

```bash
cp docker/deploy/.env.example docker/deploy/.env   # then edit secrets
docker compose -f docker/deploy/compose.selfhost.yml --env-file docker/deploy/.env up --build -d
```

Brings up the control plane (durable `cpdata` volume) and one edge, both with
`restart: unless-stopped` and a `/readyz` healthcheck.

### Hosted (Kubernetes)

```bash
kubectl kustomize docker/deploy/k8s   # review
kubectl apply -k docker/deploy/k8s
```

Deploys into namespace `ct-system`: control plane (PVC-backed, liveness/readiness
probes), edge (LoadBalancer UDP+TCP), and a TLS-terminating ingress.

## Configuration

| Variable | Component | Purpose |
|----------|-----------|---------|
| `CT_CONTROL_PLANE_LISTEN` | control plane | bind address (default `0.0.0.0:8090`) |
| `CT_CONTROL_PLANE_DB` | control plane | SQLite path (put it on durable storage) |
| `CT_OIDC_ISSUER` | control plane | Keycloak realm issuer URL (with `CT_OIDC_PUBKEY_PATH`, enables `/me/*`) |
| `CT_OIDC_PUBKEY_PATH` | control plane | PEM file with the realm's RSA public key; set with `CT_OIDC_ISSUER` to mount the authenticated `/me/*` endpoints |
| `CT_PAYMENT_WEBHOOK_SECRET` | control plane | provider webhook signing secret (unset ⇒ payment disabled) |
| `CT_EDGE_LISTEN` | edge | bind address (default `0.0.0.0:4433`) |
| `CT_EDGE_POW_DIFFICULTY` | edge | rendezvous PoW cost |
| `CT_EDGE_CERT_OUT` | edge | path the edge writes its CA root to |

Secrets come from `.env` (self-host, gitignored) or Kubernetes Secrets (hosted) —
never commit them. Verify with `./scripts/check-no-secrets.sh`.

## Monitor

- **Dashboard**: `GET /` on the control plane — a self-contained operator
  landing page showing health plus live counts (tunnels, agents, accounts,
  confirmed payments, uptime), auto-refreshing. Open `http://<host>:8090/`.
  It shows metadata and health only; the payload is end-to-end encrypted and
  never visible here.
- **Status (JSON)**: `GET /status` — the machine-readable data behind the
  dashboard: `{ready, tunnels, agents, accounts, payments_confirmed, uptime_seconds}`.
  Scrape or alert on it.
- **Liveness**: `GET /healthz` on the control plane (always 200 while up).
- **Readiness**: `GET /readyz` (200 only when the database is reachable; 503
  otherwise — orchestrators route around it).
- **Metrics**: agent-side Prometheus `/metrics` (per ADR-0016; customer-owned).

Alert on: `/readyz` flapping (DB reachability), edge TCP-listener down,
sustained `429`s on `/me/issue` (a client hitting the rate limit), and webhook
`401`s (misconfigured `CT_PAYMENT_WEBHOOK_SECRET` or a forgery attempt).

## Routine procedures

### Rotate the edge certificate
Restart the edge. It mints a fresh CA leaf under its internal CA on startup;
clients trust the CA root, so no client change is needed.

### Rotate the payment webhook secret
Update it in the provider dashboard and in `CT_PAYMENT_WEBHOOK_SECRET`, then
restart the control plane. Expect brief webhook `401`s until both sides match;
providers retry, and delivery is idempotent, so no credit is lost.

### Back up state
Snapshot the control-plane database (the `cpdata` volume / PVC). It holds
enrollment, the tunnel registry, and the credit ledger. Restores are a file copy.

### Audit dependencies
`./scripts/security-audit.sh` — run before each release and on any `Cargo.lock`
change; a non-zero exit means a new advisory affects a pinned crate.

### Verify a deployment end to end (smoke)
`./scripts/e2e-smoke.sh` — the standard one-command cross-host check. It mints a
join token, onboards an agent against the central control plane + edge, runs a
client through the tunnel to a local echo origin, and prints `SMOKE OK via=<quic|tcp>`
(exit 0) or `SMOKE FAIL: <reason>` (exit 1). Run it from the agent host after a
deploy or change:

```bash
CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der ./scripts/e2e-smoke.sh
# force the TCP fallback (UDP blocked):
CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der CT_CLIENT_FORCE_TCP=1 ./scripts/e2e-smoke.sh
```

Requires the built binaries (`docker run --rm -v "$PWD":/work -w /work rust:1-slim
cargo build --workspace`), plus `socat` and `curl`. `EDGE_CERT` is the edge CA
root (public trust material) copied from the central host.

### Demo in 2 minutes (show a human the tunnel works)
Where the smoke above prints a machine verdict for operators, `./scripts/demo.sh`
*shows* a person that real client traffic reaches a **private** origin only through
the tunnel, and how fast. It starts a private echo origin bound to `127.0.0.1`
(unreachable from outside), narrates that contrast, onboards the agent, sends a
recognizable payload through the tunnel, then measures live latency over the same
path. Same prerequisites as the smoke (built binaries, `socat`, `curl`, the edge
CA root):

```bash
BIN=./target/debug CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der ./scripts/demo.sh
# show the TCP fallback path instead of QUIC:
CT_CLIENT_FORCE_TCP=1 BIN=./target/debug CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der ./scripts/demo.sh
# more samples for the latency read:
CT_CLIENT_ITERATIONS=50 BIN=./target/debug CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der ./scripts/demo.sh
```

Example output:

```text
=== claude-tunnel demo: reaching a PRIVATE origin through the tunnel ===
▶ Starting a PRIVATE origin on 127.0.0.1:8080 (echo; logs each request)
✓ Origin is up on 127.0.0.1:8080 — bound to loopback, so it is NOT reachable from another host.
▶ Contrast — is the origin reachable directly from outside loopback?
✓ Direct connection to the origin from the public side is refused — it is genuinely private.
▶ Onboarding the agent against the central control plane + edge
✓ Agent onboarded and registered on the edge (<central-host>:4433).
▶ A client sends "private-origin-1752570000" through the tunnel (path: QUIC) …
✓ The client received "private-origin-1752570000" back THROUGH the tunnel — via=quic, round-trip 6 ms.
   ↳ The PRIVATE origin's own log confirms it was reached only via the tunnel:
     [origin] served a request at 14:20:03
▶ Measuring live performance — 20 round-trips through the tunnel (path: QUIC) …
✓ Live latency over the tunnel — 20/20: mean 1.83ms p95 3.10ms.
=== DEMO OK — real client traffic reached the private origin over the tunnel (via=quic) ===
```

Cross-host `via=quic` requires the agent-side keepalive (issue #2, on `main`);
without it the demo can still run locally/loopback.

### Run redundant agents (HA origin, issue #8)
Run **two or more agents for one tunnel** so it survives an agent (or host) dying.
Redundant agents must share **one identity** (same routing token + origin key), so
point them at the same `CT_AGENT_ORIGIN_KEY` + `CT_AGENT_CAPABILITY_OUT` paths on a
shared volume. The **first** agent generates and persists the identity; later
agents load it. Start the primary first so the shared files exist:

```bash
# agent 1 (primary — creates the shared identity):
CT_AGENT_JOIN_TOKEN=<tok> CT_AGENT_ORIGIN_KEY=/shared/origin.key \
  CT_AGENT_CAPABILITY_OUT=/shared/capability.bin CT_AGENT_ORIGIN=127.0.0.1:8081 ct-agent onboard
# agent 2+ (redundant — load the same identity, same origin):
CT_AGENT_JOIN_TOKEN=<tok2> CT_AGENT_ORIGIN_KEY=/shared/origin.key \
  CT_AGENT_CAPABILITY_OUT=/shared/capability.bin CT_AGENT_ORIGIN=127.0.0.1:8081 ct-agent onboard
```

The edge tracks every agent registered for the token and **routes to the most
recent**, failing over to a survivor when one drops — evicting only the dropped
agent's registration, never the others. Verify it end to end with:

```bash
CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der ./scripts/redundancy-smoke.sh
```

which brings up two agents on one origin, establishes a client round-trip, kills
the serving agent, and confirms the client still gets `via=quic` off the survivor
(`REDUNDANCY OK`). With `CT_EDGE_TRACE=1` on the edge you'll see the `agent 2/2`
failover line. Keep the shared `origin.key` owner-only — it's the origin's static
Noise secret.

### Edge data-plane metrics (issue #10)
The edge exposes Prometheus metrics for the relay itself (complementing the
control-plane landing page and the agent `/metrics`). Enable with
`CT_EDGE_METRICS_LISTEN` (off by default) and scrape `GET /metrics`:

```bash
CT_EDGE_METRICS_LISTEN=0.0.0.0:9101 ct-edge   # or set it in the edge container env
curl -s http://<edge-host>:9101/metrics
```

Exposed series (metadata only — the edge stays provider-blind):

| metric | type | meaning |
|--------|------|---------|
| `ct_edge_active_tunnels` | gauge | distinct routing tokens with ≥1 live agent |
| `ct_edge_active_agents` | gauge | live agent registrations (redundant agents #8 counted) |
| `ct_edge_registrations_total` | counter | agent registrations accepted since start |
| `ct_edge_relays_total` | counter | client relays served |
| `ct_edge_relay_bytes_total` | counter | bytes relayed (both directions) |
| `ct_edge_failovers_total` | counter | relays that failed over to a non-primary agent (#8) |

The compose overlay `docker/docker-compose.metrics.yml` sets it for the testbed
(edge on `:9101`, agent on `:9100`). With redundant agents (#8) up you'll see
`ct_edge_active_agents` exceed `ct_edge_active_tunnels`.

## Incident response

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| `/readyz` returns 503 | DB unreachable / volume detached | check the `cpdata` volume mount; restart once storage is back |
| All webhooks `401` | wrong/blank `CT_PAYMENT_WEBHOOK_SECRET` | set it to match the provider; restart |
| Clients can't connect after cert change | should not happen (CA-root trust) | confirm clients hold the CA root, not a pinned leaf |
| One account floods issuance | working as designed | per-account rate limit returns `429`; adjust the cap if legitimate |
| Suspected committed secret | credential in a commit | run `./scripts/check-no-secrets.sh`; rotate the exposed secret |

## Enabling authenticated endpoints

The `/me/*` endpoints (OIDC bearer verification, account derived from the token
subject) are mounted only when **both** `CT_OIDC_ISSUER` and `CT_OIDC_PUBKEY_PATH`
are set — the latter pointing at a PEM file with the realm's RSA public key. With
neither set they are absent (any `/me/*` request → `404`); the unauthenticated
billing/webhook flow works regardless.

## Escalation & scope

Availability against a **funded** abuser and censorship/lawful-process handling
are operational/jurisdictional, not covered by the software — see
[SPEC §9](../SPEC.md) and the [threat model](../security/threat-model.md).
