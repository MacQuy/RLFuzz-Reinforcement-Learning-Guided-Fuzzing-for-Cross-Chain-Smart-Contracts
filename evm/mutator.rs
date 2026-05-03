use std::fmt::Debug;

use libafl::{
    inputs::Input,
    mutators::MutationResult,
    prelude::{HasMaxSize, HasRand, Mutator, State},
    schedulers::Scheduler,
    state::HasMetadata,
    Error,
};
use libafl_bolts::{prelude::Rand, Named};
use revm_interpreter::Interpreter;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::onchain::flashloan::CAN_LIQUIDATE;
/// Mutator for EVM inputs
use crate::evm::input::EVMInputT;
use crate::{
    evm::{
        abi::ABIAddressToInstanceMap,
        input::EVMInputTy::Borrow,
        types::{convert_u256_to_h160, EVMAddress, EVMU256},
        vm::{Constraint, EVMStateT},
    },
    generic_vm::vm_state::VMStateT,
    input::{ConciseSerde, VMInputT},
    r#const::{
        ABI_MUTATE_CHOICE,
        EXPLOIT_PRESET_CHOICE,
        HAVOC_CHOICE,
        HAVOC_MAX_ITERS,
        LIQUIDATE_CHOICE,
        LIQ_PERCENT,
        LIQ_PERCENT_CHOICE,
        MUTATE_CALLER_CHOICE,
        MUTATION_RETRIES,
        MUTATOR_SAMPLE_MAX,
        RANDOMNESS_CHOICE,
        RANDOMNESS_CHOICE_2,
        TURN_TO_STEP_CHOICE,
    },
    state::{HasCaller, HasItyState, HasPresets, InfantStateState},
};

/// [`AccessPattern`] records the access pattern of the input during execution.
/// This helps to determine what is needed to be fuzzed. For instance, we don't
/// need to mutate caller if the execution never uses it.
///
/// Each mutant should report to its parent's access pattern
/// if a new corpus item is added, it should inherit the access pattern of its
/// source
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AccessPattern {
    pub caller: bool,             // or origin
    pub balance: Vec<EVMAddress>, // balance queried for accounts
    pub call_value: bool,
    pub gas_price: bool,
    pub number: bool,
    pub coinbase: bool,
    pub timestamp: bool,
    pub prevrandao: bool,
    pub gas_limit: bool,
    pub chain_id: bool,
    pub basefee: bool,
}

impl AccessPattern {
    /// Create a new access pattern with all fields set to false
    pub fn new() -> Self {
        Self {
            balance: vec![],
            caller: false,
            call_value: false,
            gas_price: false,
            number: false,
            coinbase: false,
            timestamp: false,
            prevrandao: false,
            gas_limit: false,
            chain_id: false,
            basefee: false,
        }
    }

    /// Record access pattern of current opcode executed by the interpreter
    pub fn decode_instruction(&mut self, interp: &Interpreter) {
        match unsafe { *interp.instruction_pointer } {
            0x31 => self.balance.push(convert_u256_to_h160(interp.stack.peek(0).unwrap())),
            0x33 => self.caller = true,
            0x3a => self.gas_price = true,
            0x43 => self.number = true,
            0x41 => self.coinbase = true,
            0x42 => self.timestamp = true,
            0x44 => self.prevrandao = true,
            0x45 => self.gas_limit = true,
            0x46 => self.chain_id = true,
            0x48 => self.basefee = true,
            0x34 => self.call_value = true,
            _ => {}
        }
    }
}

/// [`FuzzMutator`] is a mutator that mutates the input based on the ABI and
/// access pattern
pub struct FuzzMutator<VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Scheduler for selecting the next VM state to use if we decide to mutate
    /// the VM state of the input
    pub infant_scheduler: SC,
    pub phantom: std::marker::PhantomData<(VS, Loc, Addr, CI)>,
}

impl<VS, Loc, Addr, SC, CI> FuzzMutator<VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new [`FuzzMutator`] with the given scheduler
    pub fn new(infant_scheduler: SC) -> Self {
        Self {
            infant_scheduler,
            phantom: Default::default(),
        }
    }

    fn ensures_constraint<I, S>(input: &mut I, state: &mut S, new_vm_state: &VS, constraints: Vec<Constraint>) -> bool
    where
        I: VMInputT<VS, Loc, Addr, CI> + Input + EVMInputT,
        S: State + HasRand + HasMaxSize + HasItyState<Loc, Addr, VS, CI> + HasCaller<Addr> + HasMetadata,
    {
        // precheck
        for constraint in &constraints {
            match constraint {
                Constraint::MustStepNow => {
                    if input.get_input_type() == Borrow {
                        return false;
                    }
                }
                Constraint::Contract(_) => {
                    if input.get_input_type() == Borrow {
                        return false;
                    }
                }
                _ => {}
            }
        }

        for constraint in constraints {
            match constraint {
                Constraint::Caller(caller) => {
                    input.set_caller_evm(caller);
                }
                Constraint::Value(value) => {
                    input.set_txn_value(value);
                }
                Constraint::Contract(target) => {
                    let rand_int = state.rand_mut().next();
                    let always_none = state.rand_mut().below(MUTATOR_SAMPLE_MAX);
                    let abis = state
                        .metadata_map()
                        .get::<ABIAddressToInstanceMap>()
                        .expect("ABIAddressToInstanceMap not found");
                    let abi = match abis.map.get(&target) {
                        Some(abi) => {
                            if !abi.is_empty() {
                                match always_none {
                                    0..=ABI_MUTATE_CHOICE => {
                                        // we return a random abi
                                        Some((*abi)[rand_int as usize % abi.len()].clone())
                                    }
                                    _ => None,
                                }
                            } else {
                                None
                            }
                        }
                        None => None,
                    };
                    input.set_contract_and_abi(target, abi);
                }
                Constraint::NoLiquidation => {
                    input.set_liquidation_percent(0);
                }
                Constraint::MustStepNow => {
                    input.set_step(true);
                    // todo(@shou): move args into
                    // debug!("vm state: {:?}", input.get_state());
                    input.set_as_post_exec(new_vm_state.get_post_execution_needed_len());
                    input.mutate(state);
                }
            }
        }
        true
    }
}

impl<VS, Loc, Addr, SC, CI> Named for FuzzMutator<VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn name(&self) -> &str {
        "FuzzMutator"
    }
}

impl<VS, Loc, Addr, I, S, SC, CI> Mutator<I, S> for FuzzMutator<VS, Loc, Addr, SC, CI>
where
    I: VMInputT<VS, Loc, Addr, CI> + Input + EVMInputT,
    S: State + HasRand + HasMaxSize + HasItyState<Loc, Addr, VS, CI> + HasCaller<Addr> + HasMetadata + HasPresets,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    VS: Default + VMStateT + EVMStateT,
    Addr: PartialEq + Debug + Serialize + DeserializeOwned + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Mutate the input
    #[allow(unused_assignments)]
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        // if the VM state of the input is not initialized, swap it with a state
        // initialized
        if !input.get_staged_state().initialized {
            let concrete = state.get_infant_state(&mut self.infant_scheduler).unwrap();
            input.set_staged_state(concrete.1, concrete.0);
        }

        // use exploit template
        if state.has_preset() && state.rand_mut().below(MUTATOR_SAMPLE_MAX) < EXPLOIT_PRESET_CHOICE {
            // if flashloan_v2, we don't mutate if it's a borrow
            if input.get_input_type() != Borrow {
                match state.get_next_call() {
                    Some((addr, abi)) => {
                        input.set_contract_and_abi(addr, Some(abi));
                        input.mutate(state);
                        return Ok(MutationResult::Mutated);
                    }
                    None => {
                        // debug!("cannot find next call");
                    }
                }
            }
        }
        // determine whether we should conduct havoc
        // (a sequence of mutations in batch vs single mutation)
        // let mut amount_of_args = input.get_data_abi().map(|abi|
        // abi.b.get_size()).unwrap_or(0) / 32 + 1; if amount_of_args > 6 {
        //     amount_of_args = 6;
        // }
        let should_havoc = state.rand_mut().below(MUTATOR_SAMPLE_MAX) < HAVOC_CHOICE;

        // determine how many times we should mutate the input
        let havoc_times = if should_havoc {
            state.rand_mut().below(HAVOC_MAX_ITERS) + 1 // (amount_of_args *
                                                        // HAVOC_MAX_ITERS) as
                                                        // u64;
        } else {
            1
        };

        let mut mutated = false;

        {
            if !input.is_step() && state.rand_mut().below(MUTATOR_SAMPLE_MAX) < MUTATE_CALLER_CHOICE {
                let old_idx = input.get_state_idx();
                let (idx, new_state) = state.get_infant_state(&mut self.infant_scheduler).unwrap();
                if idx != old_idx {
                    if !state.has_caller(&input.get_caller()) {
                        input.set_caller(state.get_rand_caller());
                    }

                    if Self::ensures_constraint(input, state, &new_state.state, new_state.state.get_constraints()) {
                        mutated = true;
                        input.set_staged_state(new_state, idx);
                    }
                }
            }

            if input.get_staged_state().state.has_post_execution() &&
                !input.is_step() &&
                state.rand_mut().below(MUTATOR_SAMPLE_MAX) < TURN_TO_STEP_CHOICE
            {
                macro_rules! turn_to_step {
                    () => {
                        input.set_step(true);
                        // todo(@shou): move args into
                        input.set_as_post_exec(input.get_state().get_post_execution_needed_len());
                        for _ in 0..havoc_times - 1 {
                            input.mutate(state);
                        }
                        mutated = true;
                    };
                }
                if input.get_input_type() != Borrow {
                    turn_to_step!();
                }

                return Ok(MutationResult::Mutated);
            }
        }

        // mutate the input once
        let mut mutator = || -> MutationResult {
            // if the input is a step input (resume execution from a control leak)
            // we should not mutate the VM state, but only mutate the bytes
            if input.is_step() {
                let res = match state.rand_mut().below(MUTATOR_SAMPLE_MAX) {
                    0..=LIQUIDATE_CHOICE => {
                        // only when there are more than one liquidation path, we attempt to liquidate
                        if unsafe { CAN_LIQUIDATE } {
                            let prev_percent = input.get_liquidation_percent();
                            input.set_liquidation_percent(if state.rand_mut().below(MUTATOR_SAMPLE_MAX) <
                                LIQ_PERCENT_CHOICE
                            {
                                LIQ_PERCENT
                            } else {
                                0
                            } as u8);
                            if prev_percent != input.get_liquidation_percent() {
                                MutationResult::Mutated
                            } else {
                                MutationResult::Skipped
                            }
                        } else {
                            MutationResult::Skipped
                        }
                    }
                    _ => input.mutate(state),
                };
                input.set_txn_value(EVMU256::ZERO);
                return res;
            }

            // if the input is to borrow token, we should mutate the randomness
            // (use to select the paths to buy token), VM state, and bytes
            if input.get_input_type() == Borrow {
                let rand_u8 = state.rand_mut().below(256) as u8;
                return match state.rand_mut().below(MUTATOR_SAMPLE_MAX) {
                    0..=RANDOMNESS_CHOICE => {
                        // mutate the randomness
                        input.set_randomness(vec![rand_u8; 1]);
                        MutationResult::Mutated
                    }
                    // mutate the bytes
                    _ => input.mutate(state),
                };
            }

            // mutate the bytes or VM state or liquidation percent (percentage of token to
            // liquidate) by default
            match state.rand_mut().below(MUTATOR_SAMPLE_MAX) {
                0..=LIQUIDATE_CHOICE => {
                    let prev_percent = input.get_liquidation_percent();
                    input.set_liquidation_percent(if state.rand_mut().below(MUTATOR_SAMPLE_MAX) < LIQ_PERCENT_CHOICE {
                        LIQ_PERCENT
                    } else {
                        0
                    } as u8);
                    if prev_percent != input.get_liquidation_percent() {
                        MutationResult::Mutated
                    } else {
                        MutationResult::Skipped
                    }
                }
                LIQUIDATE_CHOICE..=RANDOMNESS_CHOICE_2 => {
                    let rand_u8 = state.rand_mut().below(256) as u8;
                    input.set_randomness(vec![rand_u8; 1]);
                    MutationResult::Mutated
                }
                _ => input.mutate(state),
            }
        };

        let mut res = if mutated {
            MutationResult::Mutated
        } else {
            MutationResult::Skipped
        };
        let mut tries = 0;

        // try to mutate the input for [`havoc_times`] times with MUTATION_RETRIES
        // retries if the input is not mutated
        while res != MutationResult::Mutated && tries < MUTATION_RETRIES {
            for i in 0..havoc_times {
                if mutator() == MutationResult::Mutated {
                    res = MutationResult::Mutated;
                }
            }
            tries += 1;
        }
        Ok(res)
    }
}

// ============================================================
// Phase 4 — CrossChain Generic Mutation Strategy
// ============================================================

use crate::evm::cross_chain::executor::CrossChainMutationMeta;

/// Four strategy types for cross-chain mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrossChainMutationStrategy {
    /// Flip 1–8 random bits in a random calldata byte
    BitFlip,
    /// Mutate a single ABI-encoded field (Zero / Max / Increment / Decrement / Random)
    AbiFieldMutate,
    /// Use queue state to set intent flags for the executor
    StateAwareMutate,
    /// Set a numeric field to a boundary value
    BoundaryValue,
}

/// Sub-types for AbiFieldMutate
#[derive(Clone, Debug)]
pub enum AbiMutateSubtype {
    Zero,
    Max,
    Increment,
    Decrement,
    RandomBytes,
}

/// Corpus energy entry — tracks per-input exploration weight
#[derive(Clone, Debug)]
pub struct CorpusEnergyEntry {
    pub energy: f64,
    pub last_strategy: Option<CrossChainMutationStrategy>,
}

impl Default for CorpusEnergyEntry {
    fn default() -> Self {
        Self { energy: 1.0, last_strategy: None }
    }
}

impl CorpusEnergyEntry {
    pub const MAX_ENERGY: f64 = 10.0;
    pub const MIN_ENERGY: f64 = 0.1;

    /// Reward: new coverage edge or new invariant flag triggered
    pub fn reward(&mut self) {
        self.energy = (self.energy * 1.5).min(Self::MAX_ENERGY);
    }

    /// Decay: no new signal
    pub fn decay(&mut self) {
        self.energy = (self.energy * 0.9).max(Self::MIN_ENERGY);
    }
}

/// Cross-chain mutator operating on raw calldata bytes.
pub struct CrossChainMutator {
    pub corpus: Vec<(Vec<u8>, CorpusEnergyEntry)>,
    /// xorshift64 state
    rng: u64,
    /// ABI available? If so, field-aware mutation is possible
    pub abi_available: bool,
}

impl CrossChainMutator {
    pub fn new(seed: u64) -> Self {
        Self {
            corpus: Vec::new(),
            rng: if seed == 0 { 0xdeadbeef } else { seed },
            abi_available: false,
        }
    }

    fn next_rand(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    /// Add a new seed to the corpus with default energy.
    pub fn add_seed(&mut self, data: Vec<u8>) {
        self.corpus.push((data, CorpusEnergyEntry::default()));
    }

    /// Select the next corpus entry using weighted random selection (proportional to energy).
    pub fn select_next(&mut self) -> Option<usize> {
        if self.corpus.is_empty() {
            return None;
        }
        let total: f64 = self.corpus.iter().map(|(_, e)| e.energy).sum();
        let mut pick = (self.next_rand() as f64 / u64::MAX as f64) * total;
        for (i, (_, entry)) in self.corpus.iter().enumerate() {
            pick -= entry.energy;
            if pick <= 0.0 {
                return Some(i);
            }
        }
        Some(self.corpus.len() - 1)
    }

    /// Notify the corpus that the execution at `idx` produced a new signal.
    pub fn notify_new_signal(&mut self, idx: usize) {
        if let Some((_, entry)) = self.corpus.get_mut(idx) {
            entry.reward();
        }
    }

    /// Notify the corpus that the execution at `idx` produced no new signal.
    pub fn notify_no_signal(&mut self, idx: usize) {
        if let Some((_, entry)) = self.corpus.get_mut(idx) {
            entry.decay();
        }
    }

    // --------------------------------------------------------
    // Strategy selection (70% explore / 30% exploit)
    // --------------------------------------------------------

    fn pick_strategy(&mut self, last_strategy: Option<&CrossChainMutationStrategy>) -> CrossChainMutationStrategy {
        let explore = (self.next_rand() % 100) < 70; // MUTATION_EXPLORE_RATIO = 0.7
        if explore || last_strategy.is_none() {
            match self.next_rand() % 4 {
                0 => CrossChainMutationStrategy::BitFlip,
                1 => CrossChainMutationStrategy::AbiFieldMutate,
                2 => CrossChainMutationStrategy::StateAwareMutate,
                _ => CrossChainMutationStrategy::BoundaryValue,
            }
        } else {
            // Exploit: repeat last successful strategy
            last_strategy.unwrap().clone()
        }
    }

    // --------------------------------------------------------
    // Deposit mutation
    // --------------------------------------------------------

    /// Mutate calldata for a deposit (lock) transaction.
    pub fn mutate_deposit(&mut self, data: &mut Vec<u8>) -> CrossChainMutationMeta {
        let roll = self.next_rand() % 4;
        match roll {
            0 | 1 => self.apply_boundary_value(data, 4), // 50%: BoundaryValue on amount
            2 => self.apply_bit_flip(data),               // 25%: BitFlip
            _ => self.apply_abi_field_mutate(data),        // 25%: AbiFieldMutate
        };
        CrossChainMutationMeta::default()
    }

    // --------------------------------------------------------
    // Relay mutation
    // --------------------------------------------------------

    /// Mutate calldata for a relay transaction. Returns the meta intent flags.
    pub fn mutate_relay(&mut self, data: &mut Vec<u8>) -> CrossChainMutationMeta {
        let mut meta = CrossChainMutationMeta::default();
        match self.next_rand() % 5 {
            0 | 1 => {
                // 40%: StateAwareMutate
                meta.force_zero_merkle_root = self.next_rand() % 2 == 0;
                meta.force_replay_nonce = self.next_rand() % 2 == 0;
                meta.force_inflate_value = self.next_rand() % 2 == 0;
            }
            2 => {
                // 20%: AbiFieldMutate Zero on random field
                self.apply_abi_field_zero(data);
            }
            3 => {
                // 20%: BitFlip in first 64 bytes
                if !data.is_empty() {
                    let range = data.len().min(64);
                    let byte_idx = (self.next_rand() as usize) % range;
                    let mask = 1u8 << (self.next_rand() % 8);
                    data[byte_idx] ^= mask;
                }
            }
            _ => {
                // 20%: BoundaryValue Max on value field
                self.apply_boundary_max(data, 4);
                meta.force_inflate_value = true;
            }
        }
        meta
    }

    // --------------------------------------------------------
    // Primitive mutations
    // --------------------------------------------------------

    fn apply_bit_flip(&mut self, data: &mut Vec<u8>) {
        if data.is_empty() { return; }
        let byte_idx = (self.next_rand() as usize) % data.len();
        let bits = (self.next_rand() % 8) + 1;
        let mask: u8 = ((1u16 << bits) - 1) as u8;
        data[byte_idx] ^= mask;
    }

    fn apply_abi_field_mutate(&mut self, data: &mut Vec<u8>) {
        // Each ABI field is 32 bytes; skip 4-byte selector
        if data.len() < 36 { return; }
        let fields = (data.len() - 4) / 32;
        if fields == 0 { return; }
        let field_idx = (self.next_rand() as usize) % fields;
        let start = 4 + field_idx * 32;
        let end = start + 32;
        if end > data.len() { return; }

        match self.next_rand() % 5 {
            0 => { data[start..end].fill(0); }  // Zero
            1 => { data[start..end].fill(0xff); } // Max
            2 => {
                // Increment last byte
                let last = end - 1;
                data[last] = data[last].wrapping_add(1);
            }
            3 => {
                let last = end - 1;
                data[last] = data[last].wrapping_sub(1);
            }
            _ => {
                // RandomBytes
                for b in data[start..end].iter_mut() {
                    *b = (self.next_rand() & 0xff) as u8;
                }
            }
        }
    }

    fn apply_abi_field_zero(&mut self, data: &mut Vec<u8>) {
        if data.len() < 36 { return; }
        let fields = (data.len() - 4) / 32;
        if fields == 0 { return; }
        let field_idx = (self.next_rand() as usize) % fields;
        let start = 4 + field_idx * 32;
        let end = (start + 32).min(data.len());
        data[start..end].fill(0);
    }

    fn apply_boundary_value(&mut self, data: &mut Vec<u8>, field_offset: usize) {
        const BOUNDARIES: [u64; 5] = [0, u64::MAX, (1u64 << 96) - 1, (1u64 << 32) - 1, 1];
        let val = BOUNDARIES[(self.next_rand() as usize) % BOUNDARIES.len()];
        let end = (field_offset + 32).min(data.len());
        if end <= field_offset { return; }
        let bytes = val.to_be_bytes();
        // Write into the last 8 bytes of the 32-byte slot
        let slot_end = end;
        let write_start = slot_end.saturating_sub(8);
        let avail = slot_end - write_start;
        data[write_start..slot_end].copy_from_slice(&bytes[8 - avail..]);
    }

    fn apply_boundary_max(&mut self, data: &mut Vec<u8>, field_offset: usize) {
        let end = (field_offset + 32).min(data.len());
        if end <= field_offset { return; }
        data[field_offset..end].fill(0xff);
    }
}
