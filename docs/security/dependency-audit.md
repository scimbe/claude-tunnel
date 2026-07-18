# Dependency audit

Reproducible vulnerability audit of the workspace's dependency tree.

## How to run

```bash
./scripts/security-audit.sh
```

This runs [`cargo-audit`](https://github.com/rustsec/rustsec) against the
committed `Cargo.lock` inside the hermetic `rust:1-slim` container, checking
every resolved dependency against the [RustSec advisory
database](https://github.com/RustSec/advisory-db). It exits non-zero if any
advisory matches, so it can gate CI.

## Latest result

| Field | Value |
|-------|-------|
| Date | 2026-07-18 |
| Tool | cargo-audit 0.22.2 |
| Dependencies scanned | ~219 |
| **Vulnerabilities** | **0** (1 documented-accepted advisory ignored — see below) |
| **Warnings** (unmaintained / yanked) | **1** (`rustls-pemfile` unmaintained — see below) |
| Exit code | 0 (clean, with the `.cargo/audit.toml` ignore) |

**Accepted advisory (#80):** `RUSTSEC-2023-0071` — `rsa` "Marvin Attack" timing
side-channel (no fixed upgrade available) — is ignored in `.cargo/audit.toml` with a
documented rationale: `rsa` is a **dev-dependency only** (runtime RSA key generation
+ RS256 signing in the OIDC/portal JWKS tests), is not in any shipped service binary,
and the timing side-channel is not reachable via test key generation. Revisit if a
fix lands or if `rsa` ever enters a runtime path.

**Open warning (#80 SEC80b):** `RUSTSEC-2025-0134` — `rustls-pemfile 2.2.0`
unmaintained. This one **is** a runtime dependency of `ct-edge` (PEM cert parsing for
the `:443` front door), so it is a real supply-chain-hygiene follow-up: replace it
(e.g. with `rustls-pki-types` PEM parsing). Tracked as a non-failing `unmaintained`
warning meanwhile.

## Pinning policy

- `Cargo.lock` **is committed** and pins every transitive dependency to an exact
  version, so builds and audits are reproducible and a dependency cannot silently
  float to a compromised release.
- Re-run this audit before each release and whenever `Cargo.lock` changes; a
  non-zero exit means a new advisory affects a pinned crate — bump or replace it,
  do not ignore.
