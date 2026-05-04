/// cross_chain/executor.rs — Phase 3: DualChainExecutor

use std::{collections::HashSet, fs::OpenOptions, io::Write};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::{CrossChainMessage, DualChainState, MessageStatus};
use crate::evm::oracles::reentrancy_crosschain::inspect_reentrancy;
use super::exploit_path::{ExploitPath, ExploitStep};
use crate::evm::{
    middlewares::cross_chain_interceptor::{
        verify_message, BypassReason, MockVerificationConfig, VerificationResult,
    },
    types::{EVMAddress, EVMU256},
};

// ============================================================
// Message ordering
// ============================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageOrdering {
    Fifo,
    Random,
    Shuffled,
}

// ============================================================
// Trace record
// ============================================================

#[derive(Serialize)]
struct TraceRecord {
    run_id: u64,
    iteration: u64,
    input_type: String,
    message_id_selected: Option<u64>,
    ordering_mode: String,
    verification_result: String,
    bugs_triggered: Vec<String>,
}

// ============================================================
// xorshift64
// ============================================================

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

// ============================================================
// CrossChainMutationMeta
// ============================================================

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrossChainMutationMeta {
    pub force_zero_merkle_root: bool,
    pub force_replay_nonce: bool,
    pub force_inflate_value: bool,
}

// ============================================================
// DualChainExecutor
// ============================================================

pub struct DualChainExecutor {
    pub state: DualChainState,
    rng_state: u64,
    pub fixed_seed: Option<u64>,
    pub trace_log_path: Option<String>,
    pub verify_config: MockVerificationConfig,
    iteration: u64,
    pub run_id: u64,
    /// Running exploit path — steps are appended on every deposit/relay
    pub exploit_path: ExploitPath,
}

impl DualChainExecutor {
    pub fn new(state: DualChainState, seed: Option<u64>, verify_config: MockVerificationConfig) -> Self {
        Self {
            state,
            rng_state: seed.unwrap_or(0xdeadbeef_cafebabe),
            fixed_seed: seed,
            trace_log_path: None,
            verify_config,
            iteration: 0,
            run_id: 0,
            exploit_path: ExploitPath::new(),
        }
    }

    pub fn set_trace_log(&mut self, path: String) {
        self.trace_log_path = Some(path);
    }

    fn next_rand(&mut self) -> u64 {
        xorshift64(&mut self.rng_state)
    }

    fn pick_ordering(&mut self) -> MessageOrdering {
        match self.next_rand() % 3 {
            0 => MessageOrdering::Fifo,
            1 => MessageOrdering::Random,
            _ => MessageOrdering::Shuffled,
        }
    }

    fn select_pending_id(&mut self) -> Option<u64> {
        let pending_ids: Vec<u64> = self.state.queue.messages.iter()
            .filter(|m| m.status == MessageStatus::Pending)
            .map(|m| m.id)
            .collect();

        if pending_ids.is_empty() { return None; }

        let chosen = match self.pick_ordering() {
            MessageOrdering::Fifo => pending_ids[0],
            MessageOrdering::Random => {
                pending_ids[(self.next_rand() as usize) % pending_ids.len()]
            }
            MessageOrdering::Shuffled => {
                let mut ids = pending_ids.clone();
                for i in (1..ids.len()).rev() {
                    let j = (self.next_rand() as usize) % (i + 1);
                    ids.swap(i, j);
                }
                ids[0]
            }
        };
        Some(chosen)
    }

    pub fn check_invariants(&mut self) {
        // I4: minted > locked
        let tokens: Vec<EVMAddress> = self.state.locked_a.keys()
            .chain(self.state.minted_b.keys())
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        for token in tokens {
            let locked = *self.state.locked_a.get(&token).unwrap_or(&EVMU256::ZERO);
            let minted = *self.state.minted_b.get(&token).unwrap_or(&EVMU256::ZERO);
            if minted > locked {
                self.state.state_desync_detected = true;
                warn!("[Executor] I4: desync minted > locked token={:?}", token);
            }
        }

        // I5: queue count consistency
        let total = self.state.queue.total_count();
        let accounted = self.state.queue.pending_count()
            + self.state.queue.processed_count()
            + self.state.queue.dropped_count();
        if accounted != total {
            self.state.queue_consistency_violated = true;
            warn!("[Executor] I5: queue inconsistency {} != {}", accounted, total);
        }
    }

    fn write_trace(&self, record: &TraceRecord) {
        if let Some(path) = &self.trace_log_path {
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
                if let Ok(line) = serde_json::to_string(record) {
                    let _ = writeln!(f, "{}", line);
                }
            }
        }
    }

    fn collect_bug_flags(&self) -> Vec<String> {
        let mut flags = vec![];
        if self.state.fake_message_accepted { flags.push("FAKE_MSG".into()); }
        if self.state.replay_detected       { flags.push("REPLAY".into()); }
        if self.state.state_desync_detected { flags.push("DESYNC".into()); }
        if self.state.queue_consistency_violated { flags.push("QUEUE".into()); }
        if self.state.atomicity_violated    { flags.push("ATOMICITY".into()); }
        if self.state.drain_detected        { flags.push("DRAIN".into()); }
        flags
    }

    // --------------------------------------------------------
    // Deposit
    // --------------------------------------------------------

    pub fn execute_deposit(
        &mut self,
        token: EVMAddress,
        interceptor_captured: Vec<CrossChainMessage>,
        sig_count: u32,
        meta: Option<&CrossChainMutationMeta>,
    ) {
        self.iteration += 1;
        let mut enqueued_ids = vec![];
        let processed_nonces = self.state.queue.processed_nonces.clone();

        for mut msg in interceptor_captured {
            if let Some(m) = meta {
                if m.force_zero_merkle_root { msg.merkle_root = [0u8; 32]; }
                if m.force_inflate_value    { msg.value = EVMU256::MAX; }
            }

            let mut replay_flag = false;
            let vr = verify_message(&self.verify_config, &msg, &processed_nonces, sig_count, &mut replay_flag);
            if replay_flag { self.state.replay_detected = true; }

            match vr {
                VerificationResult::Rejected => {
                    debug!("[Executor] Deposit rejected nonce={}", msg.nonce);
                }
                _ => {
                    let value = msg.value;
                    // Record step before push (so msg is still owned)
                    let step = ExploitStep::deposit(
                        &msg,
                        token,
                        sig_count,
                        meta.cloned().unwrap_or_default(),
                    );
                    let id = self.state.queue.push(msg);
                    self.state.lock_a(token, value);
                    self.exploit_path.push(step);
                    enqueued_ids.push(id);
                }
            }
        }

        self.write_trace(&TraceRecord {
            run_id: self.run_id,
            iteration: self.iteration,
            input_type: "Deposit".into(),
            message_id_selected: enqueued_ids.first().copied(),
            ordering_mode: "N/A".into(),
            verification_result: format!("{} enqueued", enqueued_ids.len()),
            bugs_triggered: self.collect_bug_flags(),
        });
    }

    // --------------------------------------------------------
    // Relay
    // --------------------------------------------------------

    pub fn execute_relay(
        &mut self,
        token: EVMAddress,
        sig_count: u32,
        meta: Option<&CrossChainMutationMeta>,
    ) -> bool {
        self.iteration += 1;
        let pending_before_relay = self.state.queue.pending_count();

        let Some(msg_id) = self.select_pending_id() else {
            self.write_trace(&TraceRecord {
                run_id: self.run_id,
                iteration: self.iteration,
                input_type: "Relay".into(),
                message_id_selected: None,
                ordering_mode: "N/A".into(),
                verification_result: "NoPending".into(),
                bugs_triggered: self.collect_bug_flags(),
            });
            return false;
        };

        let mut msg = self.state.queue.messages.iter()
            .find(|m| m.id == msg_id)
            .cloned()
            .unwrap();

        if let Some(m) = meta {
            if m.force_zero_merkle_root { msg.merkle_root = [0u8; 32]; }
            if m.force_replay_nonce {
                if let Some(&n) = self.state.queue.processed_nonces.iter().next() {
                    msg.nonce = n;
                }
            }
            if m.force_inflate_value { msg.value = EVMU256::MAX; }
        }

        let processed_nonces = self.state.queue.processed_nonces.clone();
        let mut replay_flag = false;
        let vr = verify_message(&self.verify_config, &msg, &processed_nonces, sig_count, &mut replay_flag);
        if replay_flag { self.state.replay_detected = true; }

        let ordering_label = format!("{:?}", self.pick_ordering());

        match vr {
            VerificationResult::Rejected => {
                self.state.queue.mark_dropped(msg_id);
                self.write_trace(&TraceRecord {
                    run_id: self.run_id,
                    iteration: self.iteration,
                    input_type: "Relay".into(),
                    message_id_selected: Some(msg_id),
                    ordering_mode: ordering_label,
                    verification_result: "Rejected".into(),
                    bugs_triggered: self.collect_bug_flags(),
                });
                false
            }
            _ => {
                let simulated_revert = self.simulate_chain_b_execution(&msg);

                // Record relay step
                let step = ExploitStep::relay(
                    &msg,
                    token,
                    sig_count,
                    meta.cloned().unwrap_or_default(),
                );
                self.exploit_path.push(step);

                if simulated_revert {
                    self.state.atomicity_violated = true;
                    warn!("[Executor] Chain B revert msg={}", msg_id);
                } else {
                    let value = msg.value;
                    self.state.mint_b(token, value);
                    if msg.is_fake {
                        self.state.fake_message_accepted = true;
                        warn!("[Executor] I2: fake_message_accepted msg={}", msg_id);
                    }
                }

                // Cross-chain reentrancy check:
                // If pending count grew while the relay message was still Pending,
                // a re-entrant deposit occurred before relay completed.
                let pending_during = self.state.queue.pending_count();
                let reentrancy_bugs = inspect_reentrancy(
                    pending_before_relay,
                    pending_during,
                    true, // relay message still Pending at this point
                );
                if !reentrancy_bugs.is_empty() {
                    self.state.reentrancy_detected = true;
                }

                self.state.queue.mark_processed(msg_id);
                self.check_invariants();

                self.write_trace(&TraceRecord {
                    run_id: self.run_id,
                    iteration: self.iteration,
                    input_type: "Relay".into(),
                    message_id_selected: Some(msg_id),
                    ordering_mode: ordering_label,
                    verification_result: if simulated_revert { "Revert" } else { "Success" }.into(),
                    bugs_triggered: self.collect_bug_flags(),
                });
                true
            }
        }
    }

    fn simulate_chain_b_execution(&mut self, msg: &CrossChainMessage) -> bool {
        if msg.is_fake {
            return (self.next_rand() % 10) < 7;
        }
        false
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::{
        cross_chain::{CrossChainMessage, DualChainState},
        middlewares::cross_chain_interceptor::MockVerificationConfig,
        types::{EVMAddress, EVMU256},
    };

    fn exec(seed: u64) -> DualChainExecutor {
        DualChainExecutor::new(DualChainState::new(), Some(seed), MockVerificationConfig::default())
    }

    fn real_msg(nonce: u64, value: u64) -> CrossChainMessage {
        CrossChainMessage::new(nonce, EVMAddress::default(), EVMAddress::default(),
            vec![0xab; 32], EVMU256::from(value), [1u8; 32], false)
    }

    #[test]
    fn test_relay_no_pending_returns_false() {
        assert!(!exec(0).execute_relay(EVMAddress::default(), 5, None));
    }

    #[test]
    fn test_deposit_then_relay_processes_message() {
        let mut e = exec(42);
        let token = EVMAddress::default();
        e.execute_deposit(token, vec![real_msg(1, 100)], 5, None);
        assert_eq!(e.state.queue.pending_count(), 1);
        assert!(e.execute_relay(token, 5, None));
        assert_eq!(e.state.queue.pending_count(), 0);
        assert_eq!(e.state.queue.processed_count(), 1);
    }

    #[test]
    fn test_desync_detected() {
        let mut e = exec(99);
        let token = EVMAddress::default();
        e.execute_deposit(token, vec![real_msg(1, 100)], 5, None);
        e.state.mint_b(token, EVMU256::from(9999u64));
        e.check_invariants();
        assert!(e.state.state_desync_detected);
    }

    #[test]
    fn test_queue_consistency_after_clean_run() {
        let mut e = exec(7);
        let token = EVMAddress::default();
        e.execute_deposit(token, vec![real_msg(1, 50), real_msg(2, 50)], 5, None);
        e.execute_relay(token, 5, None);
        e.execute_relay(token, 5, None);
        assert!(!e.state.queue_consistency_violated);
    }
}
