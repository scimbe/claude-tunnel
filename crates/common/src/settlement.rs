//! #147-L4 — dedicated settlement chain for LLM-token payments.
//!
//! A minimal **hash-linked, signature-verified, append-only ledger** — the "real chain" the maintainer
//! green-lit (#147 req 3), explicitly distinct from the *symbolic* `SettleReceipt`/`BillingCommitment`
//! family in [`crate::channel`]. This is the **L4.1 foundation**: block linkage, ed25519-signed
//! transfers, balances with no overdraft, and per-sender replay nonces — the integrity core a
//! settlement currency needs. It is deliberately **single-writer** (no consensus yet) and in-memory:
//!
//! NOT in this slice (explicit follows): consensus / Byzantine agreement across writers, P2P gossip of
//! blocks, and the marketplace integration — the auction (#147-L2) that decides *what* transfers to
//! settle, and the consumption-proof (#147-L3) that gates *when* a credit finalizes. This layer only
//! guarantees that, given a set of transfers, the resulting ledger is tamper-evident and conserves
//! value (no forgery, no double-spend, no overdraft).
//!
//! Accounts are ed25519 holder public keys — the same key family used everywhere else — so an agent's
//! settlement account is its identity, and a transfer is authorized only by the holder's own signature.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// A settlement account — an ed25519 holder public key.
pub type Account = [u8; 32];
/// The chain's currency unit (smallest denomination).
pub type Amount = u64;

/// Domain separating a [`Transfer`] preimage from every other signed object in the codebase.
const TRANSFER_DOMAIN: &[u8] = b"ct-settlement-transfer-v1";
/// Domain for a block hash — so a block hash can never be confused with any other digest.
const BLOCK_DOMAIN: &[u8] = b"ct-settlement-block-v1";

/// Why appending / validating failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A transfer's signature does not verify against its `from` account.
    BadSignature,
    /// The `from` account tried to spend more than its balance.
    Overdraft { from: Account, balance: Amount, amount: Amount },
    /// The transfer's nonce isn't the sender's next expected nonce (replay / gap).
    BadNonce { from: Account, expected: u64, got: u64 },
    /// A stored block's hash or `prev_hash` linkage is wrong (tamper detected).
    BrokenChain { height: u64 },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::BadSignature => write!(f, "transfer signature does not verify"),
            ChainError::Overdraft { balance, amount, .. } => {
                write!(f, "overdraft: balance {balance} < amount {amount}")
            }
            ChainError::BadNonce { expected, got, .. } => {
                write!(f, "bad nonce: expected {expected}, got {got}")
            }
            ChainError::BrokenChain { height } => write!(f, "broken chain at block {height}"),
        }
    }
}

impl std::error::Error for ChainError {}

/// A signed token transfer. Authorized ONLY by `from`'s ed25519 signature over its canonical preimage,
/// so no one can move another account's funds. `nonce` is the sender's monotonic counter (0-based),
/// which makes a transfer single-use — a replayed transfer has a stale nonce and is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub from: Account,
    pub to: Account,
    pub amount: Amount,
    pub nonce: u64,
    pub signature: [u8; 64],
}

impl Transfer {
    /// Canonical fixed-wire preimage: `domain ‖ from ‖ to ‖ amount(LE) ‖ nonce(LE)`. All fields are
    /// fixed-size, so the encoding is injective without length prefixes.
    pub fn signing_bytes(from: &Account, to: &Account, amount: Amount, nonce: u64) -> Vec<u8> {
        let mut m = Vec::with_capacity(TRANSFER_DOMAIN.len() + 32 + 32 + 8 + 8);
        m.extend_from_slice(TRANSFER_DOMAIN);
        m.extend_from_slice(from);
        m.extend_from_slice(to);
        m.extend_from_slice(&amount.to_le_bytes());
        m.extend_from_slice(&nonce.to_le_bytes());
        m
    }

    /// Construct + sign a transfer from the sender's `SigningKey` (derives `from` from the key, so a
    /// caller cannot spend from an account it does not hold).
    pub fn sign_new(from_key: &SigningKey, to: Account, amount: Amount, nonce: u64) -> Transfer {
        let from = from_key.verifying_key().to_bytes();
        let signature = from_key
            .sign(&Self::signing_bytes(&from, &to, amount, nonce))
            .to_bytes();
        Transfer { from, to, amount, nonce, signature }
    }

    /// Whether `from`'s signature authentically authorizes this transfer.
    pub fn verify(&self) -> bool {
        match VerifyingKey::from_bytes(&self.from) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(&self.from, &self.to, self.amount, self.nonce),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }
}

/// One block: its height, the hash of the previous block (linkage), the transfers it commits, and its
/// own content hash. Tampering any field changes `hash`, and the next block's `prev_hash` no longer
/// matches — so a single edit anywhere breaks [`Chain::is_valid`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub transfers: Vec<Transfer>,
    pub hash: [u8; 32],
}

/// The domain-separated content hash of a block: `sha256(domain ‖ height ‖ prev_hash ‖ count ‖
/// ⟨each transfer's from‖to‖amount‖nonce‖signature⟩)`. Includes each signature, so tampering a
/// transfer's authorization also invalidates the block hash.
fn block_hash(height: u64, prev_hash: &[u8; 32], transfers: &[Transfer]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BLOCK_DOMAIN);
    h.update(height.to_le_bytes());
    h.update(prev_hash);
    h.update((transfers.len() as u32).to_le_bytes());
    for t in transfers {
        h.update(t.from);
        h.update(t.to);
        h.update(t.amount.to_le_bytes());
        h.update(t.nonce.to_le_bytes());
        h.update(t.signature);
    }
    h.finalize().into()
}

/// An append-only, hash-linked settlement ledger (#147-L4.1). Starts from genesis balances (how the
/// currency is initially allocated — e.g. minted to capacity sellers as they earn) and grows one block
/// at a time. **Single-writer**: this owns the whole chain in memory; multi-writer consensus is a later
/// slice. Every append is fully validated (signatures, nonces, no overdraft) before it is committed, and
/// [`is_valid`](Self::is_valid) re-derives the entire state from genesis so a stored chain is
/// tamper-evident end to end.
#[derive(Debug, Clone)]
pub struct Chain {
    genesis: BTreeMap<Account, Amount>,
    blocks: Vec<Block>,
}

impl Chain {
    /// A new chain with the given genesis allocations. The genesis block is height 0, `prev_hash` all
    /// zero, no transfers.
    pub fn new(genesis: BTreeMap<Account, Amount>) -> Self {
        let genesis_block = Block {
            height: 0,
            prev_hash: [0u8; 32],
            transfers: Vec::new(),
            hash: block_hash(0, &[0u8; 32], &[]),
        };
        Self { genesis, blocks: vec![genesis_block] }
    }

    /// The hash of the current tip (the block a new block links to).
    pub fn tip_hash(&self) -> [u8; 32] {
        self.blocks.last().expect("chain always has the genesis block").hash
    }

    /// The current height (the tip's height).
    pub fn height(&self) -> u64 {
        self.blocks.last().expect("genesis").height
    }

    /// Fold genesis + all committed transfers into `(balances, next_nonce per sender)`.
    fn state(&self) -> (BTreeMap<Account, Amount>, BTreeMap<Account, u64>) {
        let balances = self.genesis.clone();
        let nonces = BTreeMap::new();
        let mut acc = (balances, nonces);
        for block in &self.blocks {
            for t in &block.transfers {
                // Committed transfers were validated at append time; apply unconditionally.
                Self::apply(&mut acc.0, &mut acc.1, t);
            }
        }
        acc
    }

    fn apply(balances: &mut BTreeMap<Account, Amount>, nonces: &mut BTreeMap<Account, u64>, t: &Transfer) {
        *balances.entry(t.from).or_insert(0) = balances.get(&t.from).copied().unwrap_or(0).saturating_sub(t.amount);
        *balances.entry(t.to).or_insert(0) = balances.get(&t.to).copied().unwrap_or(0).saturating_add(t.amount);
        *nonces.entry(t.from).or_insert(0) += 1;
    }

    /// Validate a candidate transfer against a working `(balances, nonces)` state; on success mutate the
    /// state to reflect it. Rejects a bad signature, a stale/gapped nonce, or an overdraft.
    fn validate_and_apply(
        balances: &mut BTreeMap<Account, Amount>,
        nonces: &mut BTreeMap<Account, u64>,
        t: &Transfer,
    ) -> Result<(), ChainError> {
        if !t.verify() {
            return Err(ChainError::BadSignature);
        }
        let expected = nonces.get(&t.from).copied().unwrap_or(0);
        if t.nonce != expected {
            return Err(ChainError::BadNonce { from: t.from, expected, got: t.nonce });
        }
        let balance = balances.get(&t.from).copied().unwrap_or(0);
        if balance < t.amount {
            return Err(ChainError::Overdraft { from: t.from, balance, amount: t.amount });
        }
        Self::apply(balances, nonces, t);
        Ok(())
    }

    /// Append a block of `transfers`, committing them only if ALL validate (signatures, nonces, no
    /// overdraft) against the current state applied in order. Rejects the whole block on the first bad
    /// transfer — the chain is never left in a partially-applied state.
    pub fn append(&mut self, transfers: Vec<Transfer>) -> Result<(), ChainError> {
        let (mut balances, mut nonces) = self.state();
        for t in &transfers {
            Self::validate_and_apply(&mut balances, &mut nonces, t)?;
        }
        let height = self.height() + 1;
        let prev_hash = self.tip_hash();
        let hash = block_hash(height, &prev_hash, &transfers);
        self.blocks.push(Block { height, prev_hash, transfers, hash });
        Ok(())
    }

    /// The balance of `account` = its genesis allocation plus/minus every committed transfer.
    pub fn balance(&self, account: &Account) -> Amount {
        self.state().0.get(account).copied().unwrap_or(0)
    }

    /// Re-derive the whole chain from genesis and check it is intact: every block's stored `hash` is
    /// the true content hash, every `prev_hash` links to the previous block, and every transfer in
    /// sequence has a valid signature, the right nonce, and no overdraft. Any tamper anywhere → `Err`.
    pub fn is_valid(&self) -> Result<(), ChainError> {
        let mut balances = self.genesis.clone();
        let mut nonces: BTreeMap<Account, u64> = BTreeMap::new();
        let mut prev_hash = [0u8; 32];
        for (i, block) in self.blocks.iter().enumerate() {
            let expected_height = i as u64;
            if block.height != expected_height
                || block.prev_hash != prev_hash
                || block.hash != block_hash(block.height, &block.prev_hash, &block.transfers)
            {
                return Err(ChainError::BrokenChain { height: expected_height });
            }
            // The genesis block carries no transfers.
            for t in &block.transfers {
                Self::validate_and_apply(&mut balances, &mut nonces, t)?;
            }
            prev_hash = block.hash;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn acct(sk: &SigningKey) -> Account {
        sk.verifying_key().to_bytes()
    }

    #[test]
    fn a_chain_of_signed_transfers_conserves_value_and_stays_valid() {
        // #147-L4.1 (frozen): genesis funds an account; signed transfers move value; balances update;
        // the whole chain re-validates from genesis (hash links + signatures + nonces + no overdraft).
        let alice = key(1);
        let bob = key(2);
        let carol = key(3);
        let (a, b, c) = (acct(&alice), acct(&bob), acct(&carol));

        let mut chain = Chain::new(BTreeMap::from([(a, 100)]));
        assert!(chain.is_valid().is_ok(), "genesis chain is valid");
        assert_eq!(chain.balance(&a), 100);
        assert_eq!(chain.height(), 0);

        // Block 1: alice → bob 30, alice → carol 20 (alice's nonces 0 then 1).
        chain
            .append(vec![
                Transfer::sign_new(&alice, b, 30, 0),
                Transfer::sign_new(&alice, c, 20, 1),
            ])
            .expect("valid block appends");
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.balance(&a), 50, "alice spent 50");
        assert_eq!(chain.balance(&b), 30);
        assert_eq!(chain.balance(&c), 20);

        // Block 2: bob → carol 30 (bob's first send, nonce 0). Value is conserved (30+50=80... total 100).
        chain.append(vec![Transfer::sign_new(&bob, c, 30, 0)]).expect("appends");
        assert_eq!(chain.balance(&b), 0);
        assert_eq!(chain.balance(&c), 50);
        assert_eq!(
            chain.balance(&a) + chain.balance(&b) + chain.balance(&c),
            100,
            "total value is conserved across the chain"
        );
        assert!(chain.is_valid().is_ok(), "the full chain re-validates");
    }

    #[test]
    fn overdraft_forgery_replay_are_all_rejected() {
        let alice = key(1);
        let bob = key(2);
        let mallory = key(9);
        let (a, b) = (acct(&alice), acct(&bob));

        let mut chain = Chain::new(BTreeMap::from([(a, 10)]));

        // Overdraft: alice has 10, tries to send 11.
        assert!(
            matches!(chain.append(vec![Transfer::sign_new(&alice, b, 11, 0)]), Err(ChainError::Overdraft { .. })),
            "spending more than the balance is rejected"
        );
        assert_eq!(chain.height(), 0, "the bad block was not committed");

        // Forgery: mallory signs a transfer FROM alice's account (from=a but signed by mallory's key).
        let mut forged = Transfer::sign_new(&mallory, b, 5, 0);
        forged.from = a; // claim it's from alice, but the signature is mallory's
        assert!(matches!(chain.append(vec![forged]), Err(ChainError::BadSignature)), "forged sender rejected");

        // Replay: a valid transfer, then the SAME transfer again (stale nonce 0).
        let t = Transfer::sign_new(&alice, b, 4, 0);
        chain.append(vec![t.clone()]).expect("first spend ok");
        assert!(
            matches!(chain.append(vec![t]), Err(ChainError::BadNonce { expected: 1, got: 0, .. })),
            "replaying a spent transfer (stale nonce) is rejected"
        );
        assert_eq!(chain.balance(&a), 6, "alice spent exactly 4, not 8");
    }

    #[test]
    fn tampering_a_committed_block_breaks_is_valid() {
        // #147-L4.1 (frozen): the chain is tamper-evident — editing a committed transfer's amount (even
        // if you don't touch the hash) is caught, because the stored hash no longer matches the content.
        let alice = key(1);
        let bob = key(2);
        let (a, b) = (acct(&alice), acct(&bob));

        let mut chain = Chain::new(BTreeMap::from([(a, 100)]));
        chain.append(vec![Transfer::sign_new(&alice, b, 10, 0)]).unwrap();
        assert!(chain.is_valid().is_ok());

        // Tamper: inflate the committed transfer amount (attacker rewriting history).
        let mut tampered = chain.clone();
        tampered.blocks[1].transfers[0].amount = 90;
        assert!(
            matches!(tampered.is_valid(), Err(ChainError::BrokenChain { height: 1 })),
            "a rewritten amount breaks the block hash"
        );

        // Tamper: break the prev_hash linkage (splice/reorder).
        let mut relinked = chain.clone();
        relinked.blocks[1].prev_hash = [0xAAu8; 32];
        // recompute the block's own hash so only the LINK is wrong, not the content hash
        relinked.blocks[1].hash =
            block_hash(relinked.blocks[1].height, &relinked.blocks[1].prev_hash, &relinked.blocks[1].transfers);
        assert!(
            matches!(relinked.is_valid(), Err(ChainError::BrokenChain { height: 1 })),
            "a broken prev_hash link is caught"
        );
    }
}
