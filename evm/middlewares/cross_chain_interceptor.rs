/// cross_chain_interceptor.rs — Phase 2: Verification pipeline
///
/// Used by DualChainExecutor to verify messages before enqueuing.
/// The Middleware on_step hook is intentionally omitted — message capture
/// is driven by the executor directly, not the EVM step loop.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::evm::{
    cross_chain::CrossChainMessage,
    types::{EVMAddress, EVMU256},
};

// ============================================================
// Verification result
// ============================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BypassReason {
    ZeroMerkleRoot,
    InsufficientSignatures,
    ReplayedNonce,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    Valid,
    BypassAccepted(BypassReason),
    Rejected,
}

// ============================================================
// MockVerificationConfig
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MockVerificationConfig {
    pub signature_threshold: u32,
    pub total_validators: u32,
    pub allow_insufficient_sigs: bool,
    pub simulate_nomad_bypass: bool,
}

impl Default for MockVerificationConfig {
    fn default() -> Self {
        Self {
            signature_threshold: 5,
            total_validators: 7,
            allow_insufficient_sigs: true,
            simulate_nomad_bypass: true,
        }
    }
}

// ============================================================
// Verification pipeline (called by DualChainExecutor)
// ============================================================

/// Run the three-check verification pipeline on `msg`.
/// Side-effects: sets `*replay_flag = true` if nonce replay is detected.
pub fn verify_message(
    config: &MockVerificationConfig,
    msg: &CrossChainMessage,
    processed_nonces: &HashSet<u64>,
    sig_count: u32,
    replay_flag: &mut bool,
) -> VerificationResult {
    // Check 1 — Zero merkle root (Nomad bypass)
    if msg.merkle_root == [0u8; 32] && config.simulate_nomad_bypass {
        debug!("[Interceptor] Bypass: ZeroMerkleRoot");
        return VerificationResult::BypassAccepted(BypassReason::ZeroMerkleRoot);
    }

    // Check 2 — Signature threshold (Wormhole / Ronin pattern)
    if sig_count < config.signature_threshold {
        if config.allow_insufficient_sigs {
            debug!("[Interceptor] Bypass: InsufficientSignatures");
            return VerificationResult::BypassAccepted(BypassReason::InsufficientSignatures);
        } else {
            debug!("[Interceptor] Reject: InsufficientSignatures");
            return VerificationResult::Rejected;
        }
    }

    // Check 3 — Replay nonce
    if processed_nonces.contains(&msg.nonce) {
        *replay_flag = true;
        debug!("[Interceptor] Bypass: ReplayedNonce nonce={}", msg.nonce);
        return VerificationResult::BypassAccepted(BypassReason::ReplayedNonce);
    }

    VerificationResult::Valid
}

// ============================================================
// Unit Tests
// ============================================================

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use super::*;
    use crate::evm::{
        cross_chain::CrossChainMessage,
        types::{EVMAddress, EVMU256},
    };

    fn make_msg(nonce: u64, merkle_root: [u8; 32]) -> CrossChainMessage {
        CrossChainMessage::new(
            nonce,
            EVMAddress::default(),
            EVMAddress::default(),
            vec![],
            EVMU256::ZERO,
            merkle_root,
            false,
        )
    }

    #[test]
    fn test_zero_merkle_bypass() {
        let config = MockVerificationConfig::default();
        let msg = make_msg(1, [0u8; 32]);
        let mut replay = false;
        let r = verify_message(&config, &msg, &HashSet::new(), 5, &mut replay);
        assert_eq!(r, VerificationResult::BypassAccepted(BypassReason::ZeroMerkleRoot));
    }

    #[test]
    fn test_insufficient_sig_rejected() {
        let config = MockVerificationConfig {
            simulate_nomad_bypass: false,
            allow_insufficient_sigs: false,
            signature_threshold: 5,
            ..Default::default()
        };
        let msg = make_msg(2, [1u8; 32]);
        let mut replay = false;
        let r = verify_message(&config, &msg, &HashSet::new(), 2, &mut replay);
        assert_eq!(r, VerificationResult::Rejected);
    }

    #[test]
    fn test_replay_nonce() {
        let config = MockVerificationConfig {
            simulate_nomad_bypass: false,
            allow_insufficient_sigs: false,
            signature_threshold: 1,
            ..Default::default()
        };
        let msg = make_msg(42, [1u8; 32]);
        let mut processed = HashSet::new();
        processed.insert(42u64);
        let mut replay = false;
        let r = verify_message(&config, &msg, &processed, 5, &mut replay);
        assert_eq!(r, VerificationResult::BypassAccepted(BypassReason::ReplayedNonce));
        assert!(replay);
    }

    #[test]
    fn test_valid_passes_all_checks() {
        let config = MockVerificationConfig {
            simulate_nomad_bypass: false,
            allow_insufficient_sigs: false,
            signature_threshold: 3,
            ..Default::default()
        };
        let msg = make_msg(99, [1u8; 32]);
        let mut replay = false;
        let r = verify_message(&config, &msg, &HashSet::new(), 5, &mut replay);
        assert_eq!(r, VerificationResult::Valid);
    }
}
