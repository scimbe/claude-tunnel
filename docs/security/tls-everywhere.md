# TLS everywhere

Encryption posture for every hop, and how the deployment enforces it (M23.4).

## Hops

| Hop | Protection | Enforced by |
|-----|-----------|-------------|
| Client ↔ Origin (payload) | **End-to-end Noise_IK** — the operator never sees plaintext | ct-common noise / M8 |
| Client/Agent ↔ Edge | QUIC (TLS 1.3) with a TLS-over-TCP fallback; edge cert chains to the internal CA | ct-edge transport / M20 |
| External ↔ Control-plane API | **HTTPS terminated at the ingress**; plaintext HTTP is redirected to HTTPS | `control-plane-ingress.yaml` (hosted) / edge `:443` front door or a reverse proxy (self-host) |
| Ingress ↔ Control-plane (in-cluster) | Cluster-internal only; optionally mTLS via a service mesh | cluster network policy |

The only component that speaks plain HTTP is the control-plane API, and it is
never exposed directly: the hosted bundle puts a TLS-terminating Ingress in
front of it, and the self-host bundle terminates TLS at the edge's `:443`
front door (or a TLS reverse proxy of your own). So no external hop is ever
plaintext.

## Hosted (Kubernetes)

`docker/deploy/k8s/control-plane-ingress.yaml` terminates TLS:

- `spec.tls[].secretName` (`ct-control-plane-tls`) holds the server cert/key —
  issued by cert-manager via the `cert-manager.io/cluster-issuer` annotation, or
  supplied out-of-band. It is a Kubernetes Secret, never committed.
- `nginx.ingress.kubernetes.io/ssl-redirect: "true"` forces HTTP → HTTPS.
- The backend routes to the `ct-control-plane` Service on port 8090 (the plain
  HTTP the control plane serves), which stays cluster-internal.

Render/validate offline:

```bash
kubectl kustomize docker/deploy/k8s
```

## Self-host

Add the optional `:443` front-door overlay
(`docker/deploy/compose.frontdoor.yml`, #31/#60): the edge itself terminates
HTTPS with a BYO certificate (`CT_EDGE_PORTAL_CERT`/`CT_EDGE_PORTAL_KEY`) and
reverse-proxies the Portal to `control-plane:8090` (`CT_CP_PROXY_ADDR`); see
the [runbook](../ops/runbook.md#deploy). A separate TLS reverse proxy (Caddy,
nginx, Traefik) in front of `control-plane:8090` works too if you'd rather not
use the built-in front door. Either way, do **not** publish port 8090 to the
public internet directly.

## Checklist before exposing a deployment

- [ ] Control-plane API reachable only via HTTPS (ingress / proxy), never :8090 directly.
- [ ] Valid, auto-renewing server certificate (cert-manager or equivalent).
- [ ] HTTP→HTTPS redirect on.
- [ ] Edge reachable on 4433 (QUIC + TLS-TCP); clients hold the edge CA root.
