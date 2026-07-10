# Claude Tunnel testbed image (M5.4).
#
# Multi-stage: build all three node binaries in release, then ship them in a
# slim runtime. docker compose runs this one image with per-node commands
# (ct-edge / ct-agent / ct-client). Build context is the repo root:
#   docker build -f docker/Dockerfile -t ct-testbed .

FROM rust:1-slim AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --workspace --bins

FROM debian:bookworm-slim AS runtime
# iproute2 for tc/netem inside the node containers; ca-certificates is harmless.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iptables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/ct-edge /usr/local/bin/ct-edge
COPY --from=builder /build/target/release/ct-agent /usr/local/bin/ct-agent
COPY --from=builder /build/target/release/ct-client /usr/local/bin/ct-client
CMD ["ct-edge"]
