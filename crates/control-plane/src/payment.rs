//! Crypto-payment intake stub (M15.3, ADR-0012, SPEC §9).
//!
//! Models topping up a pseudonymous account's prepaid credit by confirming an
//! out-of-band crypto payment. This is deliberately a stub: it does not talk to
//! a chain. A customer creates a payment *intent* (returns an opaque
//! [`PaymentId`] they reference their on-chain payment by), and once the payment
//! is "confirmed" the account is credited. The real integration (watch an
//! address / verify a transaction) replaces [`PaymentIntake::confirm_payment`]'s
//! body later.
//!
//! Confirmation is idempotent — a payment credits the account at most once — so
//! a replayed confirmation cannot double-credit.

use std::collections::HashMap;

use rand::RngCore;

use crate::accounts::{AccountId, Ledger, LedgerError};

/// Opaque payment reference (32 random bytes; e.g. an invoice / memo id).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaymentId(pub [u8; 32]);

/// Why a payment operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentError {
    /// No payment intent with this id.
    UnknownPayment,
    /// The payment was already confirmed and credited; ignored to avoid a
    /// double top-up.
    AlreadyConfirmed,
    /// The credit could not be applied (e.g. the account no longer exists).
    Ledger(LedgerError),
}

impl std::fmt::Display for PaymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentError::UnknownPayment => write!(f, "unknown payment"),
            PaymentError::AlreadyConfirmed => write!(f, "payment already confirmed"),
            PaymentError::Ledger(e) => write!(f, "credit failed: {e}"),
        }
    }
}

impl std::error::Error for PaymentError {}

impl From<LedgerError> for PaymentError {
    fn from(e: LedgerError) -> Self {
        PaymentError::Ledger(e)
    }
}

struct PendingPayment {
    account: AccountId,
    credits: u64,
    confirmed: bool,
}

/// In-memory crypto-payment intake (stub).
#[derive(Default)]
pub struct PaymentIntake {
    payments: HashMap<PaymentId, PendingPayment>,
}

impl PaymentIntake {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a payment intent: the customer will pay for `credits` worth of
    /// top-up against `account`. Returns an opaque [`PaymentId`]; the payment is
    /// unconfirmed until [`confirm_payment`](Self::confirm_payment).
    pub fn create_intent(&mut self, account: AccountId, credits: u64) -> PaymentId {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let id = PaymentId(bytes);
        self.payments.insert(
            id.clone(),
            PendingPayment {
                account,
                credits,
                confirmed: false,
            },
        );
        id
    }

    /// Confirm a payment (stub for on-chain verification) and credit the
    /// account. Idempotent: a second confirmation returns
    /// [`PaymentError::AlreadyConfirmed`] and does not credit again. Returns the
    /// account's new balance on the first, successful confirmation.
    pub fn confirm_payment(
        &mut self,
        id: &PaymentId,
        ledger: &mut Ledger,
    ) -> Result<u64, PaymentError> {
        let payment = self.payments.get_mut(id).ok_or(PaymentError::UnknownPayment)?;
        if payment.confirmed {
            return Err(PaymentError::AlreadyConfirmed);
        }
        // Credit first; only mark confirmed if the credit actually applied, so a
        // credit failure (e.g. unknown account) can be retried.
        let new_balance = ledger.credit(&payment.account, payment.credits)?;
        payment.confirmed = true;
        Ok(new_balance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::issue_token_for_payment;

    #[test]
    fn confirming_a_payment_tops_up_the_account() {
        let mut ledger = Ledger::new();
        let acct = ledger.open_account();
        let mut intake = PaymentIntake::new();

        let payment = intake.create_intent(acct.clone(), 100);
        let balance = intake.confirm_payment(&payment, &mut ledger).unwrap();
        assert_eq!(balance, 100, "confirmation credited the intent amount");
        assert_eq!(ledger.balance(&acct).unwrap(), 100);
    }

    #[test]
    fn confirmation_is_idempotent() {
        let mut ledger = Ledger::new();
        let acct = ledger.open_account();
        let mut intake = PaymentIntake::new();
        let payment = intake.create_intent(acct.clone(), 50);

        intake.confirm_payment(&payment, &mut ledger).unwrap();
        // A replayed confirmation is rejected and does not credit again.
        assert_eq!(
            intake.confirm_payment(&payment, &mut ledger),
            Err(PaymentError::AlreadyConfirmed)
        );
        assert_eq!(ledger.balance(&acct).unwrap(), 50, "credited exactly once");
    }

    #[test]
    fn unknown_payment_is_rejected() {
        let mut ledger = Ledger::new();
        let mut intake = PaymentIntake::new();
        let ghost = PaymentId([3u8; 32]);
        assert_eq!(
            intake.confirm_payment(&ghost, &mut ledger),
            Err(PaymentError::UnknownPayment)
        );
    }

    #[test]
    fn account_topup_then_gated_issuance_end_to_end() {
        // The M15 chain in miniature: open account -> pay to top up -> the
        // credit gates a token issuance; a broke account is denied.
        let mut ledger = Ledger::new();
        let mut intake = PaymentIntake::new();

        let acct = ledger.open_account();
        // Broke: cannot buy a token yet.
        assert!(issue_token_for_payment(&mut ledger, &acct, 1).is_err());

        // Top up with a confirmed payment.
        let payment = intake.create_intent(acct.clone(), 3);
        intake.confirm_payment(&payment, &mut ledger).unwrap();

        // Now issuance succeeds and debits the credit.
        let token = issue_token_for_payment(&mut ledger, &acct, 1).unwrap();
        assert_ne!(token.0, [0u8; 32]);
        assert_eq!(ledger.balance(&acct).unwrap(), 2, "one credit spent on the token");
    }
}
