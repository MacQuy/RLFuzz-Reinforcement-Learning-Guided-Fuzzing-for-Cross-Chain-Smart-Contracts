/// oracles/access_control.rs — Access control oracle
///
/// Detects two classes of missing access control bugs found in both
/// DeFiHackLabs and Web3Bugs (SC4):
///
///   1. Privileged state-change accepted from an unprivileged caller
///      — we fuzz with a randomly generated "attacker" address and check
///        whether any critical storage slot changed.
///
///   2. Self-destruct reachable from an arbitrary caller
///      — re-uses the existing SELFDESTRUCT_BUG_IDX oracle signal.
///
/// Strategy: we maintain a set of "owner-equivalent" addresses seen during
/// deployment. After each execution, if a privileged write was accepted from
/// an address NOT in that set, the bug fires.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::evm::{
    cross_chain::DualChainState,
    types::{EVMAddress, EVMU256},
};

pub const ACCESS_CONTROL_BUG_IDX: u64 = 19;

// ============================================================
// AccessControlState — tracks privileged addresses and writes
// ============================================================

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccessControlState {
    /// Addresses seen as deployer / initial owner during setup
    pub privileged_addrs: HashSet<EVMAddress>,
    /// Storage slots considered "admin" (e.g. slot 0 = owner in OZ layout)
    pub sensitive_slots: HashSet<EVMU256>,
}

impl AccessControlState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_privileged(&mut self, addr: EVMAddress) {
        self.privileged_addrs.insert(addr);
    }

    pub fn add_sensitive_slot(&mut self, slot: EVMU256) {
        self.sensitive_slots.insert(slot);
    }
}

// ============================================================
// AccessControlOracle
// ============================================================

pub struct AccessControlOracle {
    pub ac_state: AccessControlState,
}

impl AccessControlOracle {
    pub fn new(ac_state: AccessControlState) -> Self {
        Self { ac_state }
    }

    /// Check whether a privileged write was accepted from `caller`.
    ///
    /// Returns ACCESS_CONTROL_BUG_IDX if:
    ///   - caller is NOT in privileged_addrs
    ///   - AND a sensitive slot changed value in chain_state_b
    pub fn inspect(
        &self,
        caller: EVMAddress,
        slot_before: &std::collections::HashMap<EVMU256, EVMU256>,
        slot_after: &std::collections::HashMap<EVMU256, EVMU256>,
    ) -> Vec<u64> {
        let mut bugs = vec![];

        // If caller IS privileged, no bug
        if self.ac_state.privileged_addrs.contains(&caller) {
            return bugs;
        }

        // Check if any sensitive slot changed
        for slot in &self.ac_state.sensitive_slots {
            let before = slot_before.get(slot).copied().unwrap_or(EVMU256::ZERO);
            let after  = slot_after.get(slot).copied().unwrap_or(EVMU256::ZERO);
            if before != after {
                warn!(
                    "[AccessControlOracle] Privileged write from unprivileged caller={:?} slot={:?}",
                    caller, slot
                );
                bugs.push(ACCESS_CONTROL_BUG_IDX);
                break;
            }
        }

        bugs
    }

    /// Simpler variant used in cross-chain context:
    /// Check if a relay was accepted from a caller not in privileged_addrs
    /// and the queue grew (i.e. state changed).
    pub fn inspect_relay(
        &self,
        caller: EVMAddress,
        queue_grew: bool,
    ) -> Vec<u64> {
        let mut bugs = vec![];
        if queue_grew && !self.ac_state.privileged_addrs.contains(&caller) {
            warn!("[AccessControlOracle] Relay accepted from unprivileged caller={:?}", caller);
            bugs.push(ACCESS_CONTROL_BUG_IDX);
        }
        bugs
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::evm::types::{EVMAddress, EVMU256};

    fn make_oracle() -> AccessControlOracle {
        let mut ac = AccessControlState::new();
        let owner = EVMAddress::from([0x01u8; 20]);
        ac.add_privileged(owner);
        ac.add_sensitive_slot(EVMU256::from(0u64));
        AccessControlOracle::new(ac)
    }

    #[test]
    fn test_privileged_caller_no_bug() {
        let oracle = make_oracle();
        let owner = EVMAddress::from([0x01u8; 20]);
        let mut before = HashMap::new();
        let mut after  = HashMap::new();
        before.insert(EVMU256::ZERO, EVMU256::from(1u64));
        after.insert(EVMU256::ZERO,  EVMU256::from(2u64));
        // owner writes sensitive slot → no bug
        assert!(oracle.inspect(owner, &before, &after).is_empty());
    }

    #[test]
    fn test_unprivileged_caller_sensitive_write_fires() {
        let oracle = make_oracle();
        let attacker = EVMAddress::from([0xdeu8; 20]);
        let mut before = HashMap::new();
        let mut after  = HashMap::new();
        before.insert(EVMU256::ZERO, EVMU256::from(1u64));
        after.insert(EVMU256::ZERO,  EVMU256::from(99u64));
        let bugs = oracle.inspect(attacker, &before, &after);
        assert!(bugs.contains(&ACCESS_CONTROL_BUG_IDX));
    }

    #[test]
    fn test_no_slot_change_no_bug() {
        let oracle = make_oracle();
        let attacker = EVMAddress::from([0xdeu8; 20]);
        let mut slots = HashMap::new();
        slots.insert(EVMU256::ZERO, EVMU256::from(42u64));
        // before == after → no write → no bug
        assert!(oracle.inspect(attacker, &slots, &slots).is_empty());
    }

    #[test]
    fn test_inspect_relay_unprivileged() {
        let oracle = make_oracle();
        let attacker = EVMAddress::from([0xdeu8; 20]);
        let bugs = oracle.inspect_relay(attacker, true);
        assert!(bugs.contains(&ACCESS_CONTROL_BUG_IDX));
    }
}
