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
    && apt-get install -y --no-install-recommends iproute2 iptables ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/ct-edge /usr/local/bin/ct-edge
COPY --from=builder /build/target/release/ct-agent /usr/local/bin/ct-agent
COPY --from=builder /build/target/release/ct-client /usr/local/bin/ct-client
COPY --from=builder /build/target/release/ct-control-plane /usr/local/bin/ct-control-plane
COPY --from=builder /build/target/release/cp_selftest /usr/local/bin/cp_selftest
COPY --from=builder /build/target/release/metrics_probe /usr/local/bin/metrics_probe
COPY --from=builder /build/target/release/udp_echo /usr/local/bin/udp_echo
COPY docker/netem-entrypoint.sh /usr/local/bin/netem-entrypoint.sh
RUN chmod +x /usr/local/bin/netem-entrypoint.sh
CMD ["ct-edge"]
