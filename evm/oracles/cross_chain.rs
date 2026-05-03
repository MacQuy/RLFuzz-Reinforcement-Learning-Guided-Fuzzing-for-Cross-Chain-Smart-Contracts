/// oracles/cross_chain.rs — Phase 4: CrossChainOracle
///
/// Inspects DualChainState post-execution and reports triggered bug invariants.
/// Called directly as CrossChainOracle::inspect() — no Oracle trait dispatch needed.

use tracing::warn;

use crate::evm::{
    cross_chain::DualChainState,
    types::{EVMAddress, EVMU256},
};

pub const CROSS_CHAIN_MINT_IDX: u64 = 12;
pub const CROSS_CHAIN_FAKE_MSG_IDX: u64 = 13;
pub const CROSS_CHAIN_REPLAY_IDX: u64 = 14;
pub const CROSS_CHAIN_DRAIN_IDX: u64 = 15;
pub const CROSS_CHAIN_DESYNC_IDX: u64 = 16;
pub const CROSS_CHAIN_QUEUE_IDX: u64 = 17;
pub const CROSS_CHAIN_ATOMICITY_IDX: u64 = 18;

pub struct CrossChainOracle;

impl CrossChainOracle {
    pub fn new() -> Self {
        Self
    }

    /// Inspect a DualChainState snapshot and return all triggered bug indices.
    pub fn inspect(state: &DualChainState) -> Vec<u64> {
        let mut bugs = vec![];

        // I1 — Mint exceeds Lock
        for (token, locked) in &state.locked_a {
            let minted = state.minted_b.get(token).copied().unwrap_or(EVMU256::ZERO);
            if minted > *locked {
                warn!("[CrossChainOracle] I1: minted > locked for token {:?}", token);
                bugs.push(CROSS_CHAIN_MINT_IDX);
                break;
            }
        }

        // I2 — Fake message accepted
        if state.fake_message_accepted {
            warn!("[CrossChainOracle] I2: fake_message_accepted");
            bugs.push(CROSS_CHAIN_FAKE_MSG_IDX);
        }

        // I3 — Replay attack
        if state.replay_detected {
            warn!("[CrossChainOracle] I3: replay_detected");
            bugs.push(CROSS_CHAIN_REPLAY_IDX);
        }

        // I4 — State desynchronization
        if state.state_desync_detected {
            warn!("[CrossChainOracle] I4: state_desync_detected");
            bugs.push(CROSS_CHAIN_DESYNC_IDX);
        }

        // I5 — Queue consistency
        if state.queue_consistency_violated {
            warn!("[CrossChainOracle] I5: queue_consistency_violated");
            bugs.push(CROSS_CHAIN_QUEUE_IDX);
        }

        // I6 — Atomicity violation
        if state.atomicity_violated {
            warn!("[CrossChainOracle] I6: atomicity_violated");
            bugs.push(CROSS_CHAIN_ATOMICITY_IDX);
        }

        // I7 — Fund drain
        if state.drain_detected {
            warn!("[CrossChainOracle] I7: drain_detected");
            bugs.push(CROSS_CHAIN_DRAIN_IDX);
        }

        bugs
    }
}

impl Default for CrossChainOracle {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// Unit Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::{
        cross_chain::DualChainState,
        types::{EVMAddress, EVMU256},
    };

    #[test]
    fn test_clean_state_no_bugs() {
        assert!(CrossChainOracle::inspect(&DualChainState::new()).is_empty());
    }

    #[test]
    fn test_fake_msg_returns_index_13() {
        let mut s = DualChainState::new();
        s.fake_message_accepted = true;
        assert!(CrossChainOracle::inspect(&s).contains(&CROSS_CHAIN_FAKE_MSG_IDX));
    }

    #[test]
    fn test_mint_exceeds_lock_returns_index_12() {
        let mut s = DualChainState::new();
        let token = EVMAddress::default();
        s.locked_a.insert(token, EVMU256::from(100u64));
        s.minted_b.insert(token, EVMU256::from(999u64));
        assert!(CrossChainOracle::inspect(&s).contains(&CROSS_CHAIN_MINT_IDX));
    }

    #[test]
    fn test_desync_returns_index_16() {
        let mut s = DualChainState::new();
        s.state_desync_detected = true;
        assert!(CrossChainOracle::inspect(&s).contains(&CROSS_CHAIN_DESYNC_IDX));
    }

    #[test]
    fn test_atomicity_returns_index_18() {
        let mut s = DualChainState::new();
        s.atomicity_violated = true;
        assert!(CrossChainOracle::inspect(&s).contains(&CROSS_CHAIN_ATOMICITY_IDX));
    }
}
