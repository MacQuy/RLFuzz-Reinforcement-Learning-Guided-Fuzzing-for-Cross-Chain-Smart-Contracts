/// oracles/integer_overflow.rs — Integer overflow / underflow oracle
///
/// Detects SC6 (Web3Bugs) and Solidity <0.8 unchecked arithmetic bugs.
///
/// Detection strategy:
///   We track pairs of (pre_value, post_value) for any storage slot that
///   changed during execution. A wrap is flagged when:
///
///     Overflow:  pre > 0  AND  post < pre  AND  (post - pre) wraps around
///                — value decreased but no subtraction was the semantics
///     Underflow: pre < threshold  AND  post > (EVMU256::MAX / 2)
///                — a small value "became" a huge value (uint wraparound)
///
///   In practice: any slot that went from a small value to a value near MAX
///   is almost certainly an underflow; any slot that went from a large value
///   to near zero without a legit subtraction is an overflow.
///
/// Also integrated with the cross-chain executor:
///   A token amount (value field) that exceeds OVERFLOW_THRESHOLD after
///   arithmetic is flagged directly.

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::evm::types::{EVMAddress, EVMU256};

pub const INTEGER_OVERFLOW_BUG_IDX: u64 = 11; // reuses existing ItyFuzz idx

/// Values above this are considered "near MAX" (potential underflow result).
/// = 2^255 (half of 256-bit max)
pub fn overflow_threshold() -> EVMU256 {
    EVMU256::from(1u64) << 255
}

// ============================================================
// IntegerOverflowOracle
// ============================================================

pub struct IntegerOverflowOracle;

impl IntegerOverflowOracle {
    pub fn new() -> Self {
        Self
    }

    /// Inspect a single (pre, post) value pair for a storage slot.
    /// Returns INTEGER_OVERFLOW_BUG_IDX if overflow or underflow is detected.
    pub fn check_slot(pre: EVMU256, post: EVMU256) -> bool {
        let threshold = overflow_threshold();

        // Underflow: small value → huge value (wrapped around via subtraction)
        if pre < EVMU256::from(1_000_000u64) && post > threshold {
            warn!("[IntegerOverflow] Underflow detected: pre={} post={}", pre, post);
            return true;
        }

        // Overflow: huge value → near zero (wrapped around via addition)
        if pre > threshold && post < EVMU256::from(1_000_000u64) {
            warn!("[IntegerOverflow] Overflow detected: pre={} post={}", pre, post);
            return true;
        }

        false
    }

    /// Scan a set of (slot → (pre, post)) pairs and return bug indices.
    pub fn inspect(
        slot_changes: &[(EVMU256, EVMU256, EVMU256)], // (slot, pre, post)
    ) -> Vec<u64> {
        let mut bugs = vec![];
        for (slot, pre, post) in slot_changes {
            if Self::check_slot(*pre, *post) {
                warn!("[IntegerOverflow] Flagged slot={:?}", slot);
                bugs.push(INTEGER_OVERFLOW_BUG_IDX);
                break; // one report per execution
            }
        }
        bugs
    }

    /// Quick check for a single value used in cross-chain context
    /// (e.g. a token amount that wrapped during relay accounting).
    pub fn inspect_value(pre: EVMU256, post: EVMU256) -> Vec<u64> {
        if Self::check_slot(pre, post) {
            vec![INTEGER_OVERFLOW_BUG_IDX]
        } else {
            vec![]
        }
    }
}

impl Default for IntegerOverflowOracle {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::types::EVMU256;

    #[test]
    fn test_underflow_detected() {
        let pre  = EVMU256::from(1u64);
        let post = EVMU256::MAX - EVMU256::from(1u64); // result of 1 - 2 in unchecked uint
        assert!(IntegerOverflowOracle::check_slot(pre, post));
    }

    #[test]
    fn test_overflow_detected() {
        let pre  = EVMU256::MAX - EVMU256::from(1u64);
        let post = EVMU256::from(5u64); // wrapped past MAX
        assert!(IntegerOverflowOracle::check_slot(pre, post));
    }

    #[test]
    fn test_normal_increment_no_bug() {
        let pre  = EVMU256::from(100u64);
        let post = EVMU256::from(101u64);
        assert!(!IntegerOverflowOracle::check_slot(pre, post));
    }

    #[test]
    fn test_normal_decrement_no_bug() {
        let pre  = EVMU256::from(100u64);
        let post = EVMU256::from(99u64);
        assert!(!IntegerOverflowOracle::check_slot(pre, post));
    }

    #[test]
    fn test_inspect_vec_returns_idx_11() {
        let pre  = EVMU256::from(1u64);
        let post = EVMU256::MAX - EVMU256::from(1u64);
        let bugs = IntegerOverflowOracle::inspect(&[(EVMU256::ZERO, pre, post)]);
        assert!(bugs.contains(&11u64));
    }
}
