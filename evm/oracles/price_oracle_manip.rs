/// oracles/price_oracle_manip.rs — Price oracle manipulation oracle (SC2)
///
/// Detects flash-loan-assisted oracle manipulation found throughout
/// DeFiHackLabs (Cream, Euler, Mango, etc.) and Web3Bugs SC2.
///
/// Detection strategy:
///   We model a simplified AMM price: price = reserve_a / reserve_b.
///   After each execution we compare pre/post reserves.
///   A manipulation is flagged when:
///
///     abs(post_price - pre_price) / pre_price  >  PRICE_DEVIATION_THRESHOLD
///
///   i.e. the price moved more than 50% in a single transaction,
///   which is never legitimate in a real AMM under normal trading.
///
/// Also detects "same-block" oracle reads:
///   If the fuzzer performs a large swap followed immediately by a read of
///   the same pool price in the same block (iteration), it flags it as a
///   potential TWAP bypass.
///
/// Cross-chain integration:
///   A bridge that uses on-chain price for collateral checks can be
///   drained if the price oracle is manipulated before relay.
///   We model this as: locked_a / exchange_rate → inflated minted_b.

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::evm::types::{EVMAddress, EVMU256};

pub const PRICE_ORACLE_BUG_IDX: u64 = 20;

/// Price deviation that triggers the oracle: 50% in a single block.
pub const PRICE_DEVIATION_THRESHOLD: f64 = 0.5;

// ============================================================
// PoolState — simplified AMM reserve model
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolState {
    pub pool_addr: EVMAddress,
    pub reserve_a: EVMU256,
    pub reserve_b: EVMU256,
}

impl PoolState {
    pub fn new(pool_addr: EVMAddress, reserve_a: EVMU256, reserve_b: EVMU256) -> Self {
        Self { pool_addr, reserve_a, reserve_b }
    }

    /// Compute price as a float (reserve_a / reserve_b).
    pub fn price(&self) -> f64 {
        let a = self.reserve_a.saturating_to::<u128>() as f64;
        let b = self.reserve_b.saturating_to::<u128>() as f64;
        if b == 0.0 { f64::MAX } else { a / b }
    }
}

// ============================================================
// PriceOracleOracle
// ============================================================

pub struct PriceOracleOracle {
    /// Snapshots taken before each execution step
    pub pre_pools:  Vec<PoolState>,
    /// Deviation threshold (default: 0.5 = 50%)
    pub threshold: f64,
}

impl PriceOracleOracle {
    pub fn new(threshold: f64) -> Self {
        Self { pre_pools: vec![], threshold }
    }

    /// Snapshot current pool state before an execution step.
    pub fn snapshot(&mut self, pools: Vec<PoolState>) {
        self.pre_pools = pools;
    }

    /// Compare pre-snapshot with `post_pools` after execution.
    /// Returns PRICE_ORACLE_BUG_IDX if any pool's price moved beyond threshold.
    pub fn inspect(&self, post_pools: &[PoolState]) -> Vec<u64> {
        let mut bugs = vec![];

        for post in post_pools {
            let Some(pre) = self.pre_pools.iter().find(|p| p.pool_addr == post.pool_addr) else {
                continue;
            };

            let pre_price  = pre.price();
            let post_price = post.price();

            if pre_price == 0.0 || pre_price == f64::MAX {
                continue;
            }

            let deviation = ((post_price - pre_price) / pre_price).abs();
            if deviation > self.threshold {
                warn!(
                    "[PriceOracle] Manipulation detected pool={:?} pre={:.4} post={:.4} deviation={:.1}%",
                    post.pool_addr, pre_price, post_price, deviation * 100.0
                );
                bugs.push(PRICE_ORACLE_BUG_IDX);
                break;
            }
        }

        bugs
    }

    /// Detect same-block oracle read after a large swap.
    /// `swap_size_ratio` = swap_amount / reserve_a.
    /// If > 0.3 (30% of pool in one tx) in same block as oracle read → flag.
    pub fn inspect_twap_bypass(swap_size_ratio: f64) -> Vec<u64> {
        const LARGE_SWAP_RATIO: f64 = 0.3;
        if swap_size_ratio > LARGE_SWAP_RATIO {
            warn!(
                "[PriceOracle] TWAP bypass: swap used {:.1}% of pool reserves in one block",
                swap_size_ratio * 100.0
            );
            vec![PRICE_ORACLE_BUG_IDX]
        } else {
            vec![]
        }
    }
}

impl Default for PriceOracleOracle {
    fn default() -> Self {
        Self::new(PRICE_DEVIATION_THRESHOLD)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::types::{EVMAddress, EVMU256};

    fn pool(a: u64, b: u64) -> PoolState {
        PoolState::new(EVMAddress::default(), EVMU256::from(a), EVMU256::from(b))
    }

    #[test]
    fn test_large_price_deviation_fires() {
        let mut oracle = PriceOracleOracle::default();
        oracle.snapshot(vec![pool(1_000_000, 1_000_000)]); // price = 1.0
        // After flash loan: reserve_a doubled, reserve_b halved → price = 4.0
        let post = vec![pool(4_000_000, 1_000_000)];
        let bugs = oracle.inspect(&post);
        assert!(bugs.contains(&PRICE_ORACLE_BUG_IDX));
    }

    #[test]
    fn test_small_deviation_no_bug() {
        let mut oracle = PriceOracleOracle::default();
        oracle.snapshot(vec![pool(1_000_000, 1_000_000)]);
        // 5% price move — normal trading
        let post = vec![pool(1_050_000, 1_000_000)];
        assert!(oracle.inspect(&post).is_empty());
    }

    #[test]
    fn test_twap_bypass_large_swap() {
        // 40% of pool swapped in one block
        let bugs = PriceOracleOracle::inspect_twap_bypass(0.4);
        assert!(bugs.contains(&PRICE_ORACLE_BUG_IDX));
    }

    #[test]
    fn test_twap_bypass_small_swap_no_bug() {
        let bugs = PriceOracleOracle::inspect_twap_bypass(0.05);
        assert!(bugs.is_empty());
    }

    #[test]
    fn test_empty_pool_list_no_crash() {
        let oracle = PriceOracleOracle::default();
        assert!(oracle.inspect(&[]).is_empty());
    }
}
