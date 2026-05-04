use super::types::EVMU512;

pub mod arb_call;
pub mod access_control;
pub mod cross_chain;
pub mod echidna;
pub mod erc20;
pub mod function;
pub mod integer_overflow;
pub mod invariant;
pub mod price_oracle_manip;
pub mod reentrancy;
pub mod reentrancy_crosschain;
pub mod selfdestruct;
pub mod state_comp;
pub mod typed_bug;
pub mod v2_pair;

// ItyFuzz original indices
pub static ERC20_BUG_IDX: u64 = 0;
pub static FUNCTION_BUG_IDX: u64 = 1;
pub static V2_PAIR_BUG_IDX: u64 = 2;
pub static TYPED_BUG_BUG_IDX: u64 = 4;
pub static SELFDESTRUCT_BUG_IDX: u64 = 5;
pub static ECHIDNA_BUG_IDX: u64 = 6;
pub static STATE_COMP_BUG_IDX: u64 = 7;
pub static ARB_CALL_BUG_IDX: u64 = 8;
pub static REENTRANCY_BUG_IDX: u64 = 9;
pub static INVARIANT_BUG_IDX: u64 = 10;
pub static INTEGER_OVERFLOW_BUG_IDX: u64 = 11;

// Cross-chain oracle indices (Phase 4)
pub static CROSS_CHAIN_MINT_IDX: u64 = 12;
pub static CROSS_CHAIN_FAKE_MSG_IDX: u64 = 13;
pub static CROSS_CHAIN_REPLAY_IDX: u64 = 14;
pub static CROSS_CHAIN_DRAIN_IDX: u64 = 15;
pub static CROSS_CHAIN_DESYNC_IDX: u64 = 16;
pub static CROSS_CHAIN_QUEUE_IDX: u64 = 17;
pub static CROSS_CHAIN_ATOMICITY_IDX: u64 = 18;

// Dataset-coverage gap oracles
pub static ACCESS_CONTROL_BUG_IDX: u64 = 19;
pub static PRICE_ORACLE_BUG_IDX: u64 = 20;
pub static CROSS_CHAIN_REENTRANCY_BUG_IDX: u64 = 21;

// ============================================================
// Bug name lookup (used by exploit_path pretty-printer)
// ============================================================
pub fn bug_name(idx: u64) -> &'static str {
    match idx {
        0  => "ERC20_BUG",
        1  => "FUNCTION_BUG",
        2  => "V2_PAIR_BUG",
        4  => "TYPED_BUG",
        5  => "SELFDESTRUCT",
        6  => "ECHIDNA",
        7  => "STATE_COMP",
        8  => "ARB_CALL",
        9  => "REENTRANCY",
        10 => "INVARIANT",
        11 => "INTEGER_OVERFLOW",
        12 => "CROSS_CHAIN_MINT",
        13 => "CROSS_CHAIN_FAKE_MSG",
        14 => "CROSS_CHAIN_REPLAY",
        15 => "CROSS_CHAIN_DRAIN",
        16 => "CROSS_CHAIN_DESYNC",
        17 => "CROSS_CHAIN_QUEUE",
        18 => "CROSS_CHAIN_ATOMICITY",
        19 => "ACCESS_CONTROL",
        20 => "PRICE_ORACLE_MANIP",
        21 => "CROSS_CHAIN_REENTRANCY",
        _  => "UNKNOWN",
    }
}

fn u512_div_float(a: EVMU512, b: EVMU512) -> f64 {
    let a = a.as_limbs();
    let b = b.as_limbs();
    let a = a[0] as f64 + a[1] as f64 * 2f64.powi(64);
    let b = b[0] as f64 + b[1] as f64 * 2f64.powi(64);
    a / b
}
