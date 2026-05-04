/// fuzzers/cross_chain_fuzzer.rs — Phase 6: Cross-Chain Fuzzer Entry Point

use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::{
    evm::{
        cross_chain::{
            executor::{CrossChainMutationMeta, DualChainExecutor},
            exploit_path::{bug_name, ExploitPath},
            CrossChainMessage, DualChainState,
        },
        middlewares::cross_chain_interceptor::MockVerificationConfig,
        mutator::CrossChainMutator,
        oracles::cross_chain::CrossChainOracle,
        types::{EVMAddress, EVMU256},
    },
    rl_scheduler::build_cross_chain_signal,
};

// ============================================================
// FuzzerConfig
// ============================================================

pub struct CrossChainFuzzerConfig {
    pub seed: Option<u64>,
    pub time_budget_secs: Option<u64>,
    pub max_iterations: Option<u64>,
    pub trace_log_path: Option<String>,
    pub deterministic: bool,
    pub verify_config: MockVerificationConfig,
    pub token: EVMAddress,
}

impl Default for CrossChainFuzzerConfig {
    fn default() -> Self {
        Self {
            seed: None,
            time_budget_secs: Some(1800),
            max_iterations: None,
            trace_log_path: None,
            deterministic: false,
            verify_config: MockVerificationConfig::default(),
            token: EVMAddress::default(),
        }
    }
}

// ============================================================
// RunResult
// ============================================================

pub struct RunResult {
    pub iterations: u64,
    pub bugs_found: Vec<u64>,
    pub time_to_first_bug_secs: Option<f64>,
    pub total_reward: f64,
    /// Confirmed exploit paths, one per unique bug index first discovered
    pub exploit_paths: Vec<ExploitPath>,
}

// ============================================================
// CrossChainFuzzer
// ============================================================

pub struct CrossChainFuzzer {
    pub config: CrossChainFuzzerConfig,
    executor: DualChainExecutor,
    mutator: CrossChainMutator,
}

impl CrossChainFuzzer {
    pub fn new(config: CrossChainFuzzerConfig) -> Self {
        let seed = config.seed;
        let verify_config = config.verify_config.clone();

        let mut executor = DualChainExecutor::new(DualChainState::new(), seed, verify_config);
        if let Some(ref path) = config.trace_log_path {
            executor.set_trace_log(path.clone());
        }

        let mut mutator = CrossChainMutator::new(seed.unwrap_or(0xdeadbeef));
        mutator.add_seed(vec![0u8; 64]);
        mutator.add_seed(vec![0xff; 64]);
        mutator.add_seed({
            let mut v = vec![0u8; 64];
            v[0..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
            v
        });

        Self { config, executor, mutator }
    }

    pub fn run(&mut self) -> RunResult {
        let start = Instant::now();
        let deadline = self.config.time_budget_secs.map(|s| start + Duration::from_secs(s));
        let max_iter = self.config.max_iterations.unwrap_or(u64::MAX);

        let mut iteration: u64 = 0;
        let mut all_bugs: Vec<u64> = vec![];
        let mut first_bug_time: Option<f64> = None;
        let mut total_reward: f64 = 0.0;
        let mut exploit_paths: Vec<ExploitPath> = vec![];

        info!("[CrossChainFuzzer] Starting (seed={:?})", self.config.seed);

        while iteration < max_iter {
            if !self.config.deterministic {
                if let Some(dl) = deadline {
                    if Instant::now() >= dl {
                        break;
                    }
                }
            }

            iteration += 1;

            let corpus_idx = self.mutator.select_next().unwrap_or(0);

            let prev_pending = self.executor.state.queue.pending_count();
            let prev_processed = self.executor.state.queue.processed_count();

            // Deposit phase
            let deposit_meta = {
                let mut data = self.mutator.corpus.get(corpus_idx)
                    .map(|(d, _)| d.clone())
                    .unwrap_or_else(|| vec![0u8; 64]);
                let m = self.mutator.mutate_deposit(&mut data);
                if let Some((ref mut d, _)) = self.mutator.corpus.get_mut(corpus_idx) {
                    *d = data;
                }
                m
            };

            let deposit_msg = self.synthesize_deposit_message(iteration, &deposit_meta);
            let sig_count = self.fuzz_sig_count(iteration);
            self.executor.execute_deposit(self.config.token, vec![deposit_msg], sig_count, Some(&deposit_meta));

            // Relay phase
            let relay_meta = {
                let mut data = self.mutator.corpus.get(corpus_idx)
                    .map(|(d, _)| d.clone())
                    .unwrap_or_else(|| vec![0u8; 64]);
                self.mutator.mutate_relay(&mut data)
            };
            self.executor.execute_relay(self.config.token, self.fuzz_sig_count(iteration + 1), Some(&relay_meta));

            // Oracle
            let bugs = CrossChainOracle::inspect(&self.executor.state);

            // RL reward
            let signal = build_cross_chain_signal(
                prev_pending, prev_processed,
                self.executor.state.queue.pending_count(),
                self.executor.state.queue.processed_count(),
                &self.executor.state,
            );
            let reward = signal.compute_reward();
            total_reward += reward;

            // Corpus energy update
            let new_signal = !bugs.is_empty() || self.executor.state.queue.processed_count() > prev_processed;
            if new_signal {
                self.mutator.notify_new_signal(corpus_idx);
            } else {
                self.mutator.notify_no_signal(corpus_idx);
            }

            // Record bugs — confirm and print exploit path on first discovery
            for bug_idx in bugs {
                if !all_bugs.contains(&bug_idx) {
                    all_bugs.push(bug_idx);
                    if first_bug_time.is_none() {
                        first_bug_time = Some(start.elapsed().as_secs_f64());
                    }

                    // Snapshot the current exploit path and confirm the bug
                    let mut candidate = self.executor.exploit_path.clone();
                    let confirmed = candidate.reproduce(
                        self.config.verify_config.clone(),
                        &[bug_idx],
                    );

                    // Pretty-print like ItyFuzz
                    let report = candidate.pretty_print();
                    warn!(
                        "[CrossChainFuzzer] New bug iter={} t={:.2}s idx={} ({})\n{}",
                        iteration,
                        first_bug_time.unwrap(),
                        bug_idx,
                        bug_name(bug_idx),
                        report
                    );

                    // Optionally write replay file
                    if let Some(ref log_path) = self.config.trace_log_path {
                        let replay_path = format!("{}.exploit_{}.json", log_path, bug_idx);
                        let _ = candidate.to_replay_file(&replay_path);
                    }

                    exploit_paths.push(candidate);
                }
            }

            if iteration % 1000 == 0 {
                info!("[CrossChainFuzzer] iter={} bugs={} reward={:.2}", iteration, all_bugs.len(), total_reward);
            }
        }

        RunResult { iterations: iteration, bugs_found: all_bugs, time_to_first_bug_secs: first_bug_time, total_reward, exploit_paths }
    }

    fn synthesize_deposit_message(&self, nonce: u64, meta: &CrossChainMutationMeta) -> CrossChainMessage {
        CrossChainMessage::new(
            nonce,
            EVMAddress::default(),
            EVMAddress::default(),
            vec![0xab; 32],
            if meta.force_inflate_value { EVMU256::MAX } else { EVMU256::from(1000u64) },
            if meta.force_zero_merkle_root { [0u8; 32] } else { [1u8; 32] },
            false,
        )
    }

    fn fuzz_sig_count(&self, iteration: u64) -> u32 {
        if iteration % 7 == 0 { 1 } else { 5 }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fuzzer(seed: u64, max_iter: u64) -> CrossChainFuzzer {
        CrossChainFuzzer::new(CrossChainFuzzerConfig {
            seed: Some(seed),
            time_budget_secs: None,
            max_iterations: Some(max_iter),
            deterministic: true,
            ..Default::default()
        })
    }

    #[test]
    fn test_fuzzer_runs_without_panic() {
        let mut f = make_fuzzer(42, 100);
        let result = f.run();
        assert_eq!(result.iterations, 100);
    }

    #[test]
    fn test_deterministic_same_seed_same_result() {
        let r1 = make_fuzzer(99, 50).run();
        let r2 = make_fuzzer(99, 50).run();
        assert_eq!(r1.iterations, r2.iterations);
        assert_eq!(r1.bugs_found.len(), r2.bugs_found.len());
    }
}

// ============================================================
// Extended oracle runner — calls all gap-coverage oracles
// ============================================================

use crate::evm::oracles::{
    access_control::{AccessControlOracle, AccessControlState},
    integer_overflow::IntegerOverflowOracle,
    price_oracle_manip::{PoolState, PriceOracleOracle},
};

/// Run the three dataset-gap oracles on a snapshot diff and return all
/// triggered bug indices. Called from the fuzzer after each relay step.
pub fn run_gap_oracles(
    caller: EVMAddress,
    slot_changes: &[(EVMU256, EVMU256, EVMU256)],
    pre_pools: &[PoolState],
    post_pools: &[PoolState],
    ac_oracle: &AccessControlOracle,
    price_oracle: &PriceOracleOracle,
) -> Vec<u64> {
    let mut bugs = vec![];

    // 1. Access control
    let slot_before: std::collections::HashMap<EVMU256, EVMU256> = slot_changes
        .iter().map(|(s, pre, _)| (*s, *pre)).collect();
    let slot_after: std::collections::HashMap<EVMU256, EVMU256> = slot_changes
        .iter().map(|(s, _, post)| (*s, *post)).collect();
    bugs.extend(ac_oracle.inspect(caller, &slot_before, &slot_after));

    // 2. Integer overflow
    bugs.extend(IntegerOverflowOracle::inspect(slot_changes));

    // 3. Price oracle manipulation
    bugs.extend(price_oracle.inspect(post_pools));

    bugs
}
