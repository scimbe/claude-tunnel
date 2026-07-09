# 0013. Noise Protocol for the Mesh Plane Client↔Origin handshake

Status: accepted

The Mesh Plane (ADR-0010) needs a provider-blind, forward-secret, mutually authenticated Client↔Origin channel in which the operator is never in the trust path. We use the Noise Protocol Framework (a Noise_IK-style pattern) with static X25519 keypairs: the Client pins the Origin's static public key (the **Origin Identity**), and both sides authenticate via their static keys. There is no CA or PKI, which suits censorship-resistance (no external issuer that can be pressured) and avoids identity-bearing X.509 certificates. The Noise session runs as an inner handshake over the QUIC stream, independent of the TLS that secures the Agent↔Edge hop (ADR-0004).

## Consequences

- Key distribution is the customer's responsibility: Clients must obtain the Origin Identity out of band or via the control plane; trust-on-first-use is a fallback (see later ADR).
- No certificate expiry/renewal machinery on the mesh path; key rotation is an explicit operation.
- The Browser Plane, when it ships, still uses TLS (ADR-0003); the two planes deliberately run different crypto stacks.
