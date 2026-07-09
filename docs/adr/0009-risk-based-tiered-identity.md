# 0009. Risk-based, tiered identity (KYC)

Status: superseded by ADR-0012 (ICP pivoted to censorship-resistance; mandatory KYC dropped)

Termination (ADR-0008) and law-enforcement cooperation only have teeth if abusers can be identified and re-entry carries a cost — but heavy upfront KYC is off-brand for a privacy-first product, and payment processors already impose a baseline. We therefore collect identity on a risk-based, tiered basis: frictionless entry requires only an email and a valid payment instrument (the baseline identity and the sybil-resistance cost), and stronger verification is triggered only by risk signals — abuse reports, sudden traffic volume, or opting into high-risk usage. This keeps default friction low and avoids proactively profiling the majority (consistent with ADR-0008), while providing a payment-rail identity for compelled disclosure and an escalation lever where needed.

## Consequences

- A valid payment instrument is required even for free/low tiers — no fully anonymous accounts.
- The control plane must define the risk signals and an escalation workflow to step up verification or suspend.
- The enterprise/regulated market may still require a separate, heavier verified tier later.
