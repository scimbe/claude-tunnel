# 0011. Censorship-resistant posture: terminate only at a Lawful Floor

Status: accepted (supersedes ADR-0008)

The product's ICP is censorship-resistance, so the operator commits to resisting discretionary, political, and third-party-pressure takedown. Its only enforcement action, **Termination**, is applied solely at the **Lawful Floor**: a narrow binding legal order in the operator's jurisdiction, or verified CSAM. The third-party abuse feeds that were the basis of the superseded ADR-0008 are dropped. CSAM is retained both as a moral floor and as a practical requirement for remaining bankable and hosted at all.

## Consequences

- No ingestion of or action on external abuse feeds; phishing/malware complaints without a binding order do not trigger Termination.
- Shared Edge-IP reputation risk is accepted and must be managed structurally (per-tenant IP diversity, upstream selection) rather than by content policing.
- Choice of incorporation jurisdiction and of upstream/hosting providers becomes load-bearing and must tolerate this posture (open branch, likely needs counsel).
- A published AUP documents the Lawful Floor and nothing broader.
