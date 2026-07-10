//! Proof-of-work gating (ADR-0018).
//!
//! Expensive Edge operations (rendezvous, relay-slot allocation) are gated
//! behind a small proof-of-work so floods and sybil creation carry a cost
//! without KYC. The Edge issues a Challenge; the Client solves it; the Edge
//! verifies cheaply. P4.1 is the primitive.

use sha2::{Digest, Sha256};

/// A proof-of-work challenge: find a `solution` such that
/// `SHA-256(nonce || solution)` has at least `difficulty` leading zero bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: [u8; 16],
    pub difficulty: u8,
}

fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

fn hash(nonce: &[u8; 16], solution: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(solution.to_le_bytes());
    hasher.finalize().into()
}

/// Verify that `solution` satisfies `challenge`. Cheap — a single hash.
pub fn verify(challenge: &Challenge, solution: u64) -> bool {
    leading_zero_bits(&hash(&challenge.nonce, solution)) >= challenge.difficulty as u32
}

/// Solve `challenge` by brute force. Expected cost grows ~2^difficulty.
pub fn solve(challenge: &Challenge) -> u64 {
    let mut solution = 0u64;
    loop {
        if verify(challenge, solution) {
            return solution;
        }
        solution += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(difficulty: u8) -> Challenge {
        Challenge {
            nonce: [0xAB; 16],
            difficulty,
        }
    }

    #[test]
    fn solve_then_verify() {
        let c = challenge(12);
        let s = solve(&c);
        assert!(verify(&c, s));
    }

    #[test]
    fn solution_meets_difficulty() {
        let c = challenge(12);
        let s = solve(&c);
        assert!(leading_zero_bits(&hash(&c.nonce, s)) >= 12);
    }

    #[test]
    fn zero_difficulty_always_valid() {
        assert!(verify(&challenge(0), 0));
    }

    #[test]
    fn verify_rejects_insufficient_bits() {
        // Solve an easy challenge, then demand one more leading-zero bit than
        // this solution actually provides — it must be rejected. Deterministic.
        let c = challenge(4);
        let s = solve(&c);
        let actual = leading_zero_bits(&hash(&c.nonce, s));
        let harder = Challenge {
            nonce: c.nonce,
            difficulty: (actual + 1) as u8,
        };
        assert!(!verify(&harder, s));
    }
}
