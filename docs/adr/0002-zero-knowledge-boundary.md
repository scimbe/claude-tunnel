# 0002. Zero-knowledge boundary: payload-blind, metadata-visible

Status: accepted

The zero-knowledge guarantee is scoped to **payload** confidentiality and integrity: the operator can never read or alter tunneled bytes. In browser mode the Edge must read the TLS SNI from the ClientHello to route the connection, and it can observe per-tunnel timing and byte volume. We therefore document that hostname and traffic-shape metadata are visible to the operator, rather than claim total blindness.

## Consequences

- Marketing and docs must state the metadata caveat plainly; overclaiming "we see nothing" is prohibited.
- Encrypted Client Hello (ECH) is incompatible with browser-mode routing, since the Edge needs the SNI to route.
- Metadata-sensitive customers are directed to the v2 client-software mesh plane, which can conceal the hostname via opaque routing tokens.
