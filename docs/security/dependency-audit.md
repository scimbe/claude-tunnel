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
| Date | 2026-07-12 |
| Tool | cargo-audit 0.22.2 |
| Advisories loaded | 1160 |
| Dependencies scanned | 206 |
| **Vulnerabilities** | **0** |
| **Warnings** (unmaintained / yanked) | **0** |
| Exit code | 0 (clean) |

No known-vulnerable, yanked, or unmaintained crates are present in the
dependency tree.

## Pinning policy

- `Cargo.lock` **is committed** and pins every transitive dependency to an exact
  version, so builds and audits are reproducible and a dependency cannot silently
  float to a compromised release.
- Re-run this audit before each release and whenever `Cargo.lock` changes; a
  non-zero exit means a new advisory affects a pinned crate — bump or replace it,
  do not ignore.
