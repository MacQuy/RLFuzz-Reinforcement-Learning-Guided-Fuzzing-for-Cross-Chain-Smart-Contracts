/// oracles/reentrancy_crosschain.rs — Cross-chain reentrancy oracle
///
/// The original ReentrancyOracle requires full EVM opcode tracing via
/// ReentrancyTracer middleware and EVMState.reentrancy_metadata. That
/// pipeline is not available in the DualChainExecutor's lightweight model.
///
/// This oracle detects the cross-chain variant of reentrancy that is
/// specific to bridge contracts (SC3 in Web3Bugs / DeFiHackLabs):
///
///   A reentrancy is flagged when a relay call (Chain B execution) triggers
///   a *new deposit* on Chain A before the original relay has completed —
///   i.e. the queue grows during relay processing.
///
/// Detection rule:
///   pending_count AFTER relay  >  pending_count BEFORE relay
///   AND the relay has not yet marked its message as Processed
///
/// This matches the "checks-effects-interactions" violation pattern:
///   relay() → external call → fallback → deposit() → re-enters relay()
///
/// The full EVM-level ReentrancyOracle (reentrancy.rs) still runs via
/// ItyFuzz's existing oracle pipeline for non-cross-chain contracts.

use tracing::warn;

pub const CROSS_CHAIN_REENTRANCY_BUG_IDX: u64 = 21;

/// Check for cross-chain reentrancy:
/// `pending_before` = queue.pending_count() before relay started
/// `pending_during` = queue.pending_count() sampled mid-relay (after external call)
/// `relay_msg_id`   = the message id being relayed (must still be Pending at sample time)
pub fn inspect_reentrancy(
    pending_before: usize,
    pending_during: usize,
    relay_still_pending: bool,
) -> Vec<u64> {
    // If new messages appeared while the relay message is still pending,
    // a re-entrant deposit occurred before the relay completed.
    if pending_during > pending_before && relay_still_pending {
        warn!(
            "[CrossChainReentrancy] Re-entrant deposit during relay: \
             pending before={} during={} relay_still_pending={}",
            pending_before, pending_during, relay_still_pending
        );
        return vec![CROSS_CHAIN_REENTRANCY_BUG_IDX];
    }
    vec![]
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reentrancy_detected_when_queue_grows_mid_relay() {
        // pending grew from 1 to 2 while relay message still pending
        let bugs = inspect_reentrancy(1, 2, true);
        assert!(bugs.contains(&CROSS_CHAIN_REENTRANCY_BUG_IDX));
    }

    #[test]
    fn test_no_reentrancy_when_relay_already_processed() {
        // relay message already marked processed before queue grew
        let bugs = inspect_reentrancy(1, 2, false);
        assert!(bugs.is_empty());
    }

    #[test]
    fn test_no_reentrancy_when_queue_stable() {
        // queue did not grow during relay
        let bugs = inspect_reentrancy(1, 1, true);
        assert!(bugs.is_empty());
    }
}
