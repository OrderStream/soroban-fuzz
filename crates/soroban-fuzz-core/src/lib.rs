//! Soroban Fuzz Core
//!
//! Deterministic host storage lifecycle and invariant fuzzer engine for Soroban smart contracts on Stellar.
//!
//! Features:
//! - `FuzzInvariantHarness`: Hooks `soroban-env-host` storage lifecycle and ledger advancement via `with_mut` on `env.ledger()`.
//! - Storage TTL eviction simulator: Tests temporary, instance, and persistent storage boundaries and eviction behavior.
//! - Invariant evaluation engine: Built-in solvency, total supply conservation, and replay nonce monotonicity invariants.

pub mod harness;
pub mod invariants;
pub mod ledger;
pub mod storage;

pub use harness::{DeterministicFuzzer, FuzzAction, FuzzInvariantHarness, FuzzStepResult};
pub use invariants::{
    FuzzState, Invariant, InvariantEngine, InvariantReport, InvariantViolation,
    ReplayNonceMonotonicityInvariant, SolvencyInvariant, TotalSupplyConservationInvariant,
    ViolationSeverity,
};
pub use ledger::{LedgerAdvancementHook, LedgerSnapshot};
pub use storage::{
    EvictionEvent, StorageEntry, StorageError, StorageTtlManager, StorageType,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_string() {
        assert_eq!(version(), "0.1.0");
    }
}

