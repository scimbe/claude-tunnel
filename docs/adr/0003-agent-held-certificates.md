# 0003. Agent-held certificates via ACME, with bring-your-own-cert fallback

Status: accepted

To keep the operator provider-blind, the TLS private key for every public hostname must live only on the customer's Agent. By default the Agent generates the keypair and obtains a publicly-trusted certificate via ACME (Let's Encrypt); the operator assists only by satisfying the DNS-01 challenge in the operator-controlled zone. The DNS-01 challenge value derives from the ACME account-key thumbprint, not the certificate key, so the operator never sees key material that could decrypt traffic. Strict or air-gapped customers may instead supply their own certificate and key directly to the Agent. Operator-issued certificates are prohibited: they would place the decrypting key on the operator side and break Decision 1.

## Consequences

- The operator must run authoritative DNS for the tunnel apex and expose an authenticated API letting an Agent place DNS-01 TXT records for its own hostnames only.
- The Agent must implement an ACME client with auto-renewal, plus a bring-your-own-cert loader.
- Custom domains require the customer to delegate `_acme-challenge` (CNAME) so the Agent can complete DNS-01 for their domain.
