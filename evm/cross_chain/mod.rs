/// cross_chain/mod.rs — Phase 1: DualChainState, CrossChainMessage, CrossChainMessageQueue
///
/// Provides the core data model for dual-chain fuzzing. Chain A is the source
/// (lock/deposit side); Chain B is the destination (mint/relay side).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::evm::{
    types::{EVMAddress, EVMU256},
    vm::EVMState,
};

pub mod executor;
pub mod exploit_path;

// ============================================================
// Message Status
// ============================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    Pending,
    Processed,
    Dropped,
}

impl Default for MessageStatus {
    fn default() -> Self {
        MessageStatus::Pending
    }
}

// ============================================================
// CrossChainMessage
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossChainMessage {
    /// Unique identifier assigned by the queue
    pub id: u64,
    /// Nonce (used for replay detection)
    pub nonce: u64,
    /// Sender address on Chain A
    pub sender: EVMAddress,
    /// Recipient address on Chain B
    pub recipient: EVMAddress,
    /// Raw payload bytes
    pub payload: Vec<u8>,
    /// Token value being bridged
    pub value: EVMU256,
    /// Merkle root (32 bytes); all-zeros triggers Nomad bypass
    pub merkle_root: [u8; 32],
    /// Current delivery status
    pub status: MessageStatus,
    /// If true, this message was injected by the fuzzer as a fake
    pub is_fake: bool,
}

impl CrossChainMessage {
    /// Construct a new message (id assigned later by queue)
    pub fn new(
        nonce: u64,
        sender: EVMAddress,
        recipient: EVMAddress,
        payload: Vec<u8>,
        value: EVMU256,
        merkle_root: [u8; 32],
        is_fake: bool,
    ) -> Self {
        Self {
            id: 0, // assigned by push()
            nonce,
            sender,
            recipient,
            payload,
            value,
            merkle_root,
            status: MessageStatus::Pending,
            is_fake,
        }
    }
}

// ============================================================
// CrossChainMessageQueue
// ============================================================

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrossChainMessageQueue {
    /// All messages, in insertion order
    pub messages: Vec<CrossChainMessage>,
    /// Monotonically-increasing id counter
    pub next_id: u64,
    /// Set of nonces that have been processed (for replay detection)
    pub processed_nonces: HashSet<u64>,
}

impl CrossChainMessageQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Assign an id to the message, append it to the queue, and return its id.
    pub fn push(&mut self, mut msg: CrossChainMessage) -> u64 {
        let id = self.next_id;
        msg.id = id;
        self.next_id += 1;
        self.messages.push(msg);
        id
    }

    /// Return references to all Pending messages.
    pub fn pending(&self) -> Vec<&CrossChainMessage> {
        self.messages
            .iter()
            .filter(|m| m.status == MessageStatus::Pending)
            .collect()
    }

    /// Mark the message with `id` as Processed and record its nonce.
    pub fn mark_processed(&mut self, id: u64) {
        if let Some(msg) = self.messages.iter_mut().find(|m| m.id == id) {
            self.processed_nonces.insert(msg.nonce);
            msg.status = MessageStatus::Processed;
        }
    }

    /// Mark the message with `id` as Dropped (silently rejected).
    pub fn mark_dropped(&mut self, id: u64) {
        if let Some(msg) = self.messages.iter_mut().find(|m| m.id == id) {
            msg.status = MessageStatus::Dropped;
        }
    }

    /// Returns true if `nonce` has already been processed.
    pub fn is_nonce_replayed(&self, nonce: u64) -> bool {
        self.processed_nonces.contains(&nonce)
    }

    /// Counts for invariant checking.
    pub fn pending_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| m.status == MessageStatus::Pending)
            .count()
    }

    pub fn processed_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| m.status == MessageStatus::Processed)
            .count()
    }

    pub fn dropped_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| m.status == MessageStatus::Dropped)
            .count()
    }

    pub fn total_count(&self) -> usize {
        self.messages.len()
    }
}

// ============================================================
// DualChainState
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DualChainState {
    /// EVM state of Chain A (source / lock side)
    pub state_a: EVMState,
    /// EVM state of Chain B (destination / mint side)
    pub state_b: EVMState,
    /// Message queue shared between the two chains
    pub queue: CrossChainMessageQueue,

    /// Per-token locked amounts on Chain A: token_address -> total_locked
    pub locked_a: HashMap<EVMAddress, EVMU256>,
    /// Per-token minted amounts on Chain B: token_address -> total_minted
    pub minted_b: HashMap<EVMAddress, EVMU256>,

    // --- Bug flags ---
    /// A message with is_fake=true was accepted and executed without revert
    pub fake_message_accepted: bool,
    /// A replayed nonce was detected during relay
    pub replay_detected: bool,
    /// Chain B state diverged from Chain A (minted > locked)
    pub state_desync_detected: bool,
    /// pending + processed + dropped ≠ total message count
    pub queue_consistency_violated: bool,
    /// Phase 4: atomicity violation (partial state update on revert)
    pub atomicity_violated: bool,
    /// Phase 6 placeholder: bridge balance drained
    pub drain_detected: bool,
    /// Cross-chain re-entrant deposit detected during relay
    pub reentrancy_detected: bool,
}

impl Default for DualChainState {
    fn default() -> Self {
        Self {
            state_a: EVMState::default(),
            state_b: EVMState::default(),
            queue: CrossChainMessageQueue::new(),
            locked_a: HashMap::new(),
            minted_b: HashMap::new(),
            fake_message_accepted: false,
            replay_detected: false,
            state_desync_detected: false,
            queue_consistency_violated: false,
            atomicity_violated: false,
            drain_detected: false,
            reentrancy_detected: false,
        }
    }
}

impl DualChainState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute a combined state hash from both chain states and the queue.
    /// Used to detect state changes (e.g., in unit tests).
    pub fn state_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut h = DefaultHasher::new();

        // Hash state_a storage
        let mut a_entries: Vec<_> = self.state_a.state.iter().collect();
        a_entries.sort_by_key(|(k, _)| *k);
        for (addr, slots) in &a_entries {
            addr.hash(&mut h);
            let mut slot_entries: Vec<_> = slots.iter().collect();
            slot_entries.sort_by_key(|(k, _)| *k);
            for (slot, val) in slot_entries {
                slot.hash(&mut h);
                val.hash(&mut h);
            }
        }

        // Hash state_b storage
        let mut b_entries: Vec<_> = self.state_b.state.iter().collect();
        b_entries.sort_by_key(|(k, _)| *k);
        for (addr, slots) in &b_entries {
            addr.hash(&mut h);
            let mut slot_entries: Vec<_> = slots.iter().collect();
            slot_entries.sort_by_key(|(k, _)| *k);
            for (slot, val) in slot_entries {
                slot.hash(&mut h);
                val.hash(&mut h);
            }
        }

        // Hash queue id+status pairs
        for msg in &self.queue.messages {
            msg.id.hash(&mut h);
            (msg.status == MessageStatus::Pending).hash(&mut h);
            (msg.status == MessageStatus::Processed).hash(&mut h);
            (msg.status == MessageStatus::Dropped).hash(&mut h);
        }

        h.finish()
    }

    /// Lock `amount` of `token` on Chain A.
    pub fn lock_a(&mut self, token: EVMAddress, amount: EVMU256) {
        let entry = self.locked_a.entry(token).or_insert(EVMU256::ZERO);
        *entry = entry.saturating_add(amount);
    }

    /// Mint `amount` of `token` on Chain B.
    pub fn mint_b(&mut self, token: EVMAddress, amount: EVMU256) {
        let entry = self.minted_b.entry(token).or_insert(EVMU256::ZERO);
        *entry = entry.saturating_add(amount);
    }
}

// ============================================================
// Unit Tests — Phase 1
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test 1: state hash changes after a message is pushed.
    #[test]
    fn test_hash_changes_on_mutation() {
        let mut state_a = DualChainState::new();
        let state_b = DualChainState::new();

        let hash_before = state_a.state_hash();
        let hash_before_b = state_b.state_hash();

        // Two fresh states should be equal
        assert_eq!(hash_before, hash_before_b);

        // Push a message to state_a
        let msg = CrossChainMessage::new(
            42,
            EVMAddress::default(),
            EVMAddress::default(),
            vec![0xde, 0xad],
            EVMU256::from(1000u64),
            [0u8; 32],
            false,
        );
        state_a.queue.push(msg);

        let hash_after = state_a.state_hash();
        assert_ne!(hash_before, hash_after, "Hash must change after message push");
    }

    /// Test 2: replay detection via processed_nonces.
    #[test]
    fn test_replay_detection() {
        let mut state = DualChainState::new();
        let msg = CrossChainMessage::new(
            42,
            EVMAddress::default(),
            EVMAddress::default(),
            vec![],
            EVMU256::ZERO,
            [0u8; 32],
            false,
        );
        let id = state.queue.push(msg);

        assert!(!state.queue.is_nonce_replayed(42), "Nonce not yet processed");
        state.queue.mark_processed(id);
        assert!(state.queue.is_nonce_replayed(42), "Nonce must be replayed after processing");
    }
}
