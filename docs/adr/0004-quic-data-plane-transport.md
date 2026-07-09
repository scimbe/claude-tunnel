# 0004. QUIC data-plane transport with HTTP/2-over-TCP fallback

Status: accepted

The Agent establishes the tunnel by dialing **outbound** to the Edge, so customers never open inbound ports. The primary transport is QUIC over UDP/443: it provides per-stream multiplexing (one Client connection maps to one stream), connection migration across IP changes, no head-of-line blocking under loss, and fast reconnection. Where outbound UDP/443 is blocked (common on corporate/hotel networks), the Agent falls back to HTTP/2 over TCP/443.

## Consequences

- Two transports to implement and test; the Agent must probe UDP reachability and downgrade gracefully.
- The Edge listens for both QUIC and TCP on 443 and demultiplexes Client streams onto the correct Agent tunnel.
- The Client↔Origin TLS session is nested inside this transport and relayed byte-for-byte; the Edge never decrypts it (Decision 1).
