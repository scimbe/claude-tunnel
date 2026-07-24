# Demo: `https://flappy-demo.bunsenbrenner.org` — a role-chain Pipeline Service

An optional **demo subsystem** that shows the claude-tunnel infrastructure end to
end: a customer opens the site, customizes a Flappy Bird, and the **pipeline builds
their product**. It is published the **same way as `help.bunsenbrenner.org`**
(`examples/help-site/`) — a Caddy origin served **through a claude-tunnel demo
tunnel** with a publicly-trusted HTTPS certificate, payload-blind at the edge.

It is designed to be **easy to enable and disable** so you can take it offline at
any time — it never touches the core plane's lifecycle.

## Enable / disable (take it offline)
```bash
# ENABLE — mint a join token, bring up the origin + Browser-Plane agent, wait for HTTPS:
examples/flappy-demo/run-demo.sh up
#   override targets if needed:
CP_URL=http://127.0.0.1:8090 EDGE=127.0.0.1:4433 examples/flappy-demo/run-demo.sh up

# DISABLE — take the demo offline (stops the origin + agent, leaves the plane running):
examples/flappy-demo/run-demo.sh down

# status:
examples/flappy-demo/run-demo.sh status
```
`up` prints `✓ LIVE` once `https://flappy-demo.bunsenbrenner.org/` serves the studio,
or actionable hints (DNS / cert / agent / edge).

## The demo password (never committed, #168)
The first-layer gate password is **not** in any committed file. Set it out-of-band as
`FLAPPY_DEMO_PASSWORD` in the untracked `docker/deploy/.env`; `run-demo.sh up` derives
its **SHA-256 hash** into a gitignored `gate.json` (from `gate.json.example`) that Caddy
serves next to the page. The page compares `sha256(input)` to that hash client-side —
so neither the plaintext nor git nor the served config ever carries the secret. The
**production-grade** gate is Caddy basic auth in front of the origin (the client gate is
just friendly first-layer UX); add a `basic_auth` block to the `Caddyfile` with a bcrypt
hash for a real access control.

## How it works (published like help-site, payload-blind)
```
Browser ──TLS(SNI=flappy-demo.bunsenbrenner.org)──▶ Plane edge :443 (SNI passthrough, blind)
                                                          │ host → routing token
                                                          ▼
                                                 ct-agent (browser mode) ──raw TLS──▶ Caddy origin
                                                                                      (terminates TLS,
                                                                                       LE cert via deSEC DNS-01,
                                                                                       serves the studio page)
```
The edge never sees plaintext — TLS terminates at the Caddy **origin**, which holds
the Let's Encrypt certificate (obtained itself via **DNS-01 against deSEC**). Same
shape and prerequisites as `examples/help-site/README.md` (a running plane with
`CT_EDGE_BROWSER_LISTEN=:443`, `DESEC_TOKEN` in `docker/deploy/.env`, and DNS for the
hostname → the plane IP). For the recommended public-`:443` hostname-authorization
path (#23 BP4b), see the help-site README — the flags are identical.

## The customer's product
The site is a **Pipeline Service**: the visitor customizes inputs (bird, theme,
physics) and the pipeline emits a finished, standalone `.html` game they download and
run anywhere. The in-page **ⓘ Info** panel explains the inputs → template → artifact
flow step by step.

## Roadmap — generate *through* the production agent pipeline
Today the "Generate" step runs the template client-side (the honest MVP). The next
step (planned as **#flappy-demo · B** in `docs/planning/v1-first-task-packets.md`) is
to route generation **through our LLM-agent marketplace**: the customer's request
clears an offer and calls a `service/code_generation` tool over the authenticated
Agent-Fabric channel, so a real provider agent's LLM actually produces the game — a
live proof of the marketplace (#147), the declared-service gate (#149-A.1 / #167), and
the cleared-match → service-call binding (#166). That step needs a live agent + LLM
CLI, so it is built behind the plane (live-mesh), not hermetically.
