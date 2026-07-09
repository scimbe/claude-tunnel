# 0007. Rust for the data plane (Agent and Edge)

Status: accepted

The Agent and Edge are internet-facing, QUIC-based, performance-sensitive, and the Agent is a custodian of customer key material. We build both in Rust (`quinn`/`s2n-quic` for QUIC, `rustls` for TLS) for memory safety on the key-custodian and ciphertext-relaying paths, top-tier throughput, and a single static Agent binary. The control plane and dashboard language is decided separately and may differ (e.g. Go or TypeScript) where iteration speed outweighs raw safety.

## Consequences

- Data-plane development is slower and hiring is narrower than an all-Go stack; accepted for the security and performance guarantees.
- The Agent ships as a self-contained static binary across platforms.
- A later control-plane/data-plane language split means maintaining two toolchains.
