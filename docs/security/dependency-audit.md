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
| Date | 2026-07-23 |
| Tool | cargo-audit 0.22.2 |
| Dependencies scanned | 378 |
| **Vulnerabilities** | **0** (3 documented-accepted advisories ignored — see below) |
| **Warnings** (unmaintained / yanked) | **1** (`paste` — unmaintained, `RUSTSEC-2024-0436`; allowed, non-fatal) |
| Exit code | 0 (clean, with the `.cargo/audit.toml` ignores + the one allowed warning) |

**Accepted advisories (#78/#80), all in `.cargo/audit.toml`:**

- `RUSTSEC-2023-0071` (#80) — `rsa` "Marvin Attack" timing side-channel (no fixed
  upgrade available): pulled only by the **test-side** `jsonwebtoken::encode` that
  mints test JWTs (control-plane tests), not in any release binary; production only
  **verifies** RS256 JWTs via a public-key `DecodingKey` (`portal.rs`), and the
  Marvin attack targets RSA private-key operations this service never performs in
  production. Revisit if a fix lands or if `rsa` ever enters a runtime path.
- `RUSTSEC-2026-0118` / `RUSTSEC-2026-0119` (#78) — `hickory-proto` (NSEC3
  unbounded loop / O(n²) name compression): present only as resolved-but-inactive
  optional deps of libp2p's `dns`/`mdns` features, which this workspace does not
  enable (libp2p features are
  `tokio,noise,yamux,tcp,quic,relay,dcutr,identify,kad,macros` — raw multiaddr
  dialing, no DNS/mDNS); `ct-dns` is a hand-rolled codec that does not use
  `hickory`. Not in the compiled graph.

**Resolved (#80 SEC80b):** `RUSTSEC-2025-0134` — the unmaintained `rustls-pemfile`
was a **runtime** dependency of `ct-edge` (PEM cert parsing for the `:443` front
door). It has been **removed** — replaced with the maintained `rustls-pki-types` PEM
decoders — so it no longer appears in `Cargo.lock` and the unmaintained warning is
gone.

## Pinning policy

- `Cargo.lock` **is committed** and pins every transitive dependency to an exact
  version, so builds and audits are reproducible and a dependency cannot silently
  float to a compromised release.
- Re-run this audit before each release and whenever `Cargo.lock` changes; a
  non-zero exit means a new advisory affects a pinned crate — bump or replace it,
  do not ignore.
