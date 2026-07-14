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
