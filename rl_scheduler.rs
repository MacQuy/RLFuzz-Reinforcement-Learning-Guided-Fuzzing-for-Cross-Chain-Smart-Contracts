/// RL-guided Scheduler for ItyFuzz

use std::{collections::HashMap, fmt::Debug};

use libafl::{
    corpus::{Corpus, Testcase},
    prelude::{CorpusId, HasMetadata, HasRand, HasTestcase, UsesInput},
    schedulers::{RemovableScheduler, Scheduler},
    state::{HasCorpus, State, UsesState},
    Error,
};
use libafl_bolts::{impl_serdeany, prelude::Rand};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    r#const::{CORPUS_INITIAL_VOTES, DROP_THRESHOLD, PRUNE_AMT,
        RL_INIT_Q, RL_PRUNE_Q_THRESHOLD,
        RL_REWARD_BUG_FOUND, RL_REWARD_CMP_IMPROVE, RL_REWARD_COV_NEW, RL_REWARD_STEP,
        UCB_C, UCB_EPSILON_INIT, UCB_EPSILON_MIN},
    scheduler::{DependencyTree, HasVote, VoteData},
    state::HasParent,
};

// ============================================================
// RLMetadata — lưu Q-table và last_selected vào LibAFL state
// ============================================================

/// Lưu trữ toàn bộ trạng thái của RL agent.
/// Được attach vào LibAFL state qua metadata_map.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RLMetadata {
    /// UCB: mean reward của mỗi arm (corpus entry)
    pub mean_reward: HashMap<usize, f64>,

    /// UCB: số lần mỗi arm được chọn
    pub visit_count: HashMap<usize, u64>,

    /// Tổng số lần select — dùng để tính UCB score
    pub total_visits: u64,

    /// Index của corpus entry được chọn lần trước
    pub last_selected: Option<usize>,

    /// Epsilon hiện tại (giảm dần theo thời gian)
    pub epsilon: f64,

    /// Tổng reward tích lũy — dùng để log/debug
    pub total_reward: f64,

    /// Số lần exploit vs explore
    pub exploit_count: usize,
    pub explore_count: usize,

    /// Dependency tree — giữ nguyên từ SortedDroppingScheduler
    pub deps: DependencyTree,

    /// Danh sách index cần remove (dùng bởi evm_fuzzer.rs)
    pub to_remove: Vec<usize>,
}

impl RLMetadata {
    pub fn new() -> Self {
        Self {
            mean_reward: HashMap::new(),
            visit_count: HashMap::new(),
            total_visits: 1, // bắt đầu từ 1 để tránh ln(0)
            last_selected: None,
            epsilon: UCB_EPSILON_INIT,
            total_reward: 0.0,
            exploit_count: 0,
            explore_count: 0,
            deps: DependencyTree::new(),
            to_remove: vec![],
        }
    }

    /// Lấy mean reward của một arm, mặc định là RL_INIT_Q (optimistic)
    pub fn get_mean(&self, idx: usize) -> f64 {
        *self.mean_reward.get(&idx).unwrap_or(&RL_INIT_Q)
    }

    /// Tính UCB1 score cho một arm:
    /// UCB(i) = mean_reward(i) + C * sqrt(ln(total_visits) / visit_count(i))
    pub fn ucb_score(&self, idx: usize) -> f64 {
        let mean = self.get_mean(idx);
        let visits = *self.visit_count.get(&idx).unwrap_or(&1) as f64;
        let bonus = UCB_C * ((self.total_visits as f64).ln() / visits).sqrt();
        mean + bonus
    }

    /// Update mean reward theo incremental mean:
    /// mean_new = mean_old + (reward - mean_old) / visit_count
    /// Không cần lưu toàn bộ history, O(1) memory.
    pub fn update(&mut self, idx: usize, reward: f64) {
        let visits = self.visit_count.entry(idx).or_insert(0);
        *visits += 1;
        let n = *visits as f64;
        let mean = self.mean_reward.entry(idx).or_insert(RL_INIT_Q);
        *mean += (reward - *mean) / n; // incremental mean
        self.total_visits += 1;
        self.total_reward += reward;
    }

    /// Decay epsilon: giảm dần sau mỗi lần select
    /// epsilon_new = max(UCB_EPSILON_MIN, epsilon * 0.9995)
    pub fn decay_epsilon(&mut self) {
        self.epsilon = (self.epsilon * 0.9995_f64).max(UCB_EPSILON_MIN);
    }

    /// Chọn arm theo UCB1 + epsilon-greedy decay:
    /// - Với xác suất epsilon (giảm dần): explore ngẫu nhiên
    /// - Ngược lại: chọn arm có UCB score cao nhất
    pub fn select(&mut self, indices: &[usize], rand_val: f64) -> usize {
        if indices.is_empty() {
            panic!("RLScheduler: corpus rỗng, không thể select");
        }

        self.decay_epsilon();

        if rand_val < self.epsilon {
            // EXPLORE: chọn ngẫu nhiên
            self.explore_count += 1;
            let i = (rand_val / self.epsilon * indices.len() as f64) as usize;
            indices[i.min(indices.len() - 1)]
        } else {
            // EXPLOIT: chọn UCB score cao nhất
            self.exploit_count += 1;
            *indices
                .iter()
                .max_by(|a, b| {
                    self.ucb_score(**a)
                        .partial_cmp(&self.ucb_score(**b))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .unwrap()
        }
    }
}

impl Default for RLMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl_serdeany!(RLMetadata);

// ============================================================
// RewardSignal — struct truyền reward từ feedback vào scheduler
// ============================================================

/// Gắn vào LibAFL state sau mỗi execution để scheduler đọc reward
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RewardSignal {
    /// Distance delta từ CmpFeedback (dương = tiến gần hơn đến branch)
    pub cmp_improvement: f64,
    /// Coverage mới được tìm thấy
    pub new_coverage: bool,
    /// Bug được tìm thấy
    pub bug_found: bool,
}

impl RewardSignal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Tính tổng reward từ các signal
    pub fn compute_reward(&self) -> f64 {
        let mut r = RL_REWARD_STEP; // base cost mỗi bước
        if self.bug_found {
            r += RL_REWARD_BUG_FOUND;
        }
        if self.cmp_improvement > 0.0 {
            r += RL_REWARD_CMP_IMPROVE * self.cmp_improvement.ln_1p();
        }
        if self.new_coverage {
            r += RL_REWARD_COV_NEW;
        }
        r
    }
}

impl_serdeany!(RewardSignal);

// ============================================================
// RLScheduler — implement Scheduler trait
// ============================================================

/// RL-guided scheduler thay thế SortedDroppingScheduler.
/// Dùng epsilon-greedy Q-learning để chọn corpus entry.
/// Smart pruning: không prune entry có Q-value cao.
#[derive(Debug, Clone)]
pub struct RLScheduler<S> {
    phantom: std::marker::PhantomData<S>,
}

impl<S> Default for RLScheduler<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> RLScheduler<S> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}

impl<S> UsesState for RLScheduler<S>
where
    S: UsesInput + State,
{
    type State = S;
}

// Implement HasVote để CmpFeedback có thể vote — ta map vote thành Q-update
impl<S> HasVote<S> for RLScheduler<S>
where
    S: HasCorpus + HasRand + HasMetadata,
{
    fn vote(&self, state: &mut S, idx: usize, _increment: usize) {
        // Khi CmpFeedback vote, ta interpret đó là reward signal nhỏ
        if !state.has_metadata::<RLMetadata>() {
            state.metadata_map_mut().insert(RLMetadata::new());
        }
        let meta = state.metadata_map_mut().get_mut::<RLMetadata>().unwrap();
        // Vote từ feedback = cmp improvement reward nhỏ
        meta.update(idx, RL_REWARD_CMP_IMPROVE);
    }
}

impl<S> Scheduler for RLScheduler<S>
where
    S: HasCorpus + HasTestcase + HasRand + HasMetadata + HasParent + State,
{
    fn on_add(&mut self, state: &mut Self::State, idx: CorpusId) -> Result<(), Error> {
        let idx_usize = usize::from(idx);

        // Khởi tạo metadata nếu chưa có
        if !state.has_metadata::<RLMetadata>() {
            state.metadata_map_mut().insert(RLMetadata::new());
        }
        // Khởi tạo VoteData (legacy, giữ để tương thích với phần còn lại)
        if !state.has_metadata::<VoteData>() {
            state.metadata_map_mut().insert(VoteData {
                votes_and_visits: HashMap::new(),
                sorted_votes: vec![],
                visits_total: 1,
                votes_total: 1,
                deps: DependencyTree::new(),
                to_remove: vec![],
            });
        }

        {
            let parent_idx = state.get_parent_idx();
            let rl_meta = state.metadata_map_mut().get_mut::<RLMetadata>().unwrap();

            // Entry mới: optimistic init (visit_count=1, mean=RL_INIT_Q)
            rl_meta.mean_reward.entry(idx_usize).or_insert(RL_INIT_Q);
            rl_meta.visit_count.entry(idx_usize).or_insert(1);

            #[cfg(feature = "full_trace")]
            rl_meta.deps.add_node(idx_usize, parent_idx);
        }

        // ===== SMART PRUNING =====
        // Giống SortedDroppingScheduler nhưng bảo vệ entry có Q-value cao
        let corpus_size = state.corpus().count();
        if corpus_size > DROP_THRESHOLD {
            let mut to_remove: Vec<usize> = vec![];

            {
                let rl_meta = state.metadata_map().get::<RLMetadata>().unwrap();

                // Sắp xếp theo Q-value tăng dần (Q thấp = ứng viên bị prune trước)
                let mut candidates: Vec<(usize, f64)> = rl_meta
                    .mean_reward
                    .iter()
                    .map(|(k, v)| (*k, *v))
                    .collect();
                candidates.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

                for (candidate_idx, q_val) in candidates.iter().take(PRUNE_AMT) {
                    // Bảo vệ: không prune nếu Q-value cao, là entry hiện tại, hoặc là artifact
                    if *candidate_idx < 3 || *candidate_idx == idx_usize {
                        continue;
                    }
                    // KEY IMPROVEMENT: chỉ prune nếu Q-value thực sự thấp
                    if *q_val <= RL_PRUNE_Q_THRESHOLD {
                        to_remove.push(*candidate_idx);
                    }
                }
            }

            // Log để quan sát hiệu quả (dùng khi debug)
            if !to_remove.is_empty() {
                info!(
                    "RLScheduler: pruning {} entries (protected {} high-Q entries)",
                    to_remove.len(),
                    PRUNE_AMT - to_remove.len()
                );
            }

            // Thực hiện remove
            for x in &to_remove {
                let _ = self.on_remove(state, (*x).into(), &None);
                #[cfg(not(feature = "full_trace"))]
                {
                    state.corpus_mut().remove((*x).into()).expect("failed to remove");
                }
            }

            state
                .metadata_map_mut()
                .get_mut::<RLMetadata>()
                .unwrap()
                .to_remove = to_remove;
        }

        Ok(())
    }

    /// Chọn corpus entry tiếp theo theo epsilon-greedy
    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        if !state.has_metadata::<RLMetadata>() {
            state.metadata_map_mut().insert(RLMetadata::new());
        }

        // Đọc reward từ lần execute trước và update Q
        let reward_opt = state
            .metadata_map()
            .get::<RewardSignal>()
            .map(|r| r.compute_reward());

        {
            let rl_meta = state.metadata_map_mut().get_mut::<RLMetadata>().unwrap();
            if let (Some(last_idx), Some(reward)) = (rl_meta.last_selected, reward_opt) {
                rl_meta.update(last_idx, reward);
            }
        }

        // Lấy danh sách tất cả indices còn trong corpus
        let indices: Vec<usize> = {
            let rl_meta = state.metadata_map().get::<RLMetadata>().unwrap();
            rl_meta.mean_reward.keys().cloned().collect()
        };

        if indices.is_empty() {
            return Err(Error::empty("corpus rỗng"));
        }

        // Epsilon-greedy selection
        let rand_val = state.rand_mut().below(10000) as f64 / 10000.0;
        let selected = {
            let rl_meta = state.metadata_map_mut().get_mut::<RLMetadata>().unwrap();
            rl_meta.select(&indices, rand_val)
        };

        // Lưu lại để update Q sau lần execute tiếp theo
        state
            .metadata_map_mut()
            .get_mut::<RLMetadata>()
            .unwrap()
            .last_selected = Some(selected);

        // Log stats định kỳ
        #[cfg(feature = "print_infant_corpus")]
        {
            let rl_meta = state.metadata_map().get::<RLMetadata>().unwrap();
            if state.rand_mut().below(8000) == 0 {
                let exploit = rl_meta.exploit_count;
                let explore = rl_meta.explore_count;
                let total = exploit + explore;
                info!(
                    "RLScheduler: selected={} | exploit={:.1}% explore={:.1}% | total_reward={:.2}",
                    selected,
                    if total > 0 { exploit as f64 / total as f64 * 100.0 } else { 0.0 },
                    if total > 0 { explore as f64 / total as f64 * 100.0 } else { 0.0 },
                    rl_meta.total_reward
                );
            }
        }

        Ok(selected.into())
    }
}

impl<S> RemovableScheduler for RLScheduler<S>
where
    S: HasCorpus + HasTestcase + HasRand + HasMetadata + HasParent + State,
{
    fn on_remove(
        &mut self,
        state: &mut Self::State,
        idx: CorpusId,
        _testcase: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        let idx_usize = usize::from(idx);
        if let Some(meta) = state.metadata_map_mut().get_mut::<RLMetadata>() {
            meta.mean_reward.remove(&idx_usize);
            meta.visit_count.remove(&idx_usize);
            if meta.last_selected == Some(idx_usize) {
                meta.last_selected = None;
            }
        }
        // Giữ VoteData cleanup cho tương thích
        if let Some(data) = state.metadata_map_mut().get_mut::<VoteData>() {
            data.votes_and_visits.remove(&idx_usize);
            data.sorted_votes.retain(|x| *x != idx_usize);
        }
        Ok(())
    }
}

// ============================================================
// HasReportCorpus — tương thích với evm_fuzzer.rs
// ============================================================

use crate::scheduler::HasReportCorpus;

impl<S> HasReportCorpus<S> for RLScheduler<S>
where
    S: HasCorpus + HasRand + HasMetadata + HasParent,
{
    fn report_corpus(&self, state: &mut S, state_idx: usize) {
        // Khi một state được confirm là interesting, boost Q-value
        if !state.has_metadata::<RLMetadata>() {
            state.metadata_map_mut().insert(RLMetadata::new());
        }
        let meta = state.metadata_map_mut().get_mut::<RLMetadata>().unwrap();
        meta.update(state_idx, RL_REWARD_COV_NEW * 2.0);

        #[cfg(feature = "full_trace")]
        meta.deps.mark_never_delete(state_idx);
    }

    fn sponsor_state(&self, state: &mut S, state_idx: usize, _amt: usize) {
        if !state.has_metadata::<RLMetadata>() {
            state.metadata_map_mut().insert(RLMetadata::new());
        }
        let meta = state.metadata_map_mut().get_mut::<RLMetadata>().unwrap();
        meta.update(state_idx, RL_REWARD_CMP_IMPROVE);
    }
}

// ============================================================
// Helper: set reward signal từ feedback
// ============================================================

/// Gọi hàm này từ CmpFeedback::is_interesting() và OracleFeedback::is_interesting()
/// để truyền reward signal vào state trước khi scheduler đọc
pub fn set_reward_signal<S: HasMetadata>(
    state: &mut S,
    cmp_improvement: f64,
    new_coverage: bool,
    bug_found: bool,
) {
    let signal = RewardSignal {
        cmp_improvement,
        new_coverage,
        bug_found,
    };
    if state.has_metadata::<RewardSignal>() {
        *state.metadata_map_mut().get_mut::<RewardSignal>().unwrap() = signal;
    } else {
        state.metadata_map_mut().insert(signal);
    }
}