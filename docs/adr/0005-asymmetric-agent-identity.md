# 0005. Asymmetric Agent identity with short-lived mTLS

Status: accepted

Agent authentication gates who can claim a hostname's tunnel and who can drive the DNS-01 API — and therefore who can obtain a valid certificate for a hostname and intercept its traffic. To prevent a single leaked secret from enabling certificate issuance and MITM, Agents use an asymmetric identity rather than a long-lived bearer token. At enrollment the operator issues a one-time join token; the Agent generates an identity keypair, proves possession, and the control plane binds the public key to the Tenant. Steady-state authentication to both the control plane and the Edge uses short-lived, rotated mTLS credentials minted from that identity. All hostname claims and DNS-01 operations are authorized against the identity's Tenant.

## Consequences

- The control plane must implement enrollment (join-token redemption), identity binding, and a short-lived-credential minting/rotation service.
- Compromise of a steady-state credential is time-boxed by its short lifetime; the join token is single-use and low-value after enrollment.
- Bare-VM and laptop Agents are supported — no dependency on cloud workload identity.
