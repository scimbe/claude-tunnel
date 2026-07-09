# 0008. Abuse handling: responsive termination on legal orders and trusted feeds

Status: superseded by ADR-0011 (ICP pivoted to censorship-resistance; third-party abuse feeds dropped)

Because the operator is provider-blind it cannot inspect content, and its only enforcement action is **Termination** at hostname or Tenant granularity. The operator acts on (a) binding legal orders and (b) high-confidence third-party **Abuse Feeds** keyed on hostname/domain (phishing, malware, CSAM) — neither of which requires payload access. It preserves available metadata for law enforcement, publishes an Acceptable Use Policy and a periodic transparency report, and does **not** proactively surveil customer metadata for policing.

Rationale: shared Edge-IP reputation means pure neutrality would externalise abuse onto good customers (blocklisted IPs harm everyone), while proactive metadata policing would corrode the zero-knowledge trust that is the product's value. The responsive-plus-feeds posture is the balance.

## Consequences

- The operator must ingest and act on external Abuse Feeds and run a legal-order intake + takedown process with a response SLA.
- Enforcement is coarse (whole hostname/Tenant); there is no content-level remediation.
- CSAM and other mandatory-reporting duties are met via report-driven Termination and metadata preservation, not scanning (see later branch).
- KYC depth and jurisdiction (open branches) determine how much teeth Termination and LE cooperation actually have.
