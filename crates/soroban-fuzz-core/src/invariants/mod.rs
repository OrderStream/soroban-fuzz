pub mod conservation;
pub mod nonce;
pub mod solvency;

pub use conservation::TotalSupplyConservationInvariant;
pub use nonce::ReplayNonceMonotonicityInvariant;
pub use solvency::SolvencyInvariant;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Global fuzz state accessible by invariant evaluators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzState {
    pub step: usize,
    pub ledger_sequence: u32,
    pub timestamp: u64,

    // Solvency state
    pub total_assets: i128,
    pub total_liabilities: i128,

    // Token & Supply conservation state
    pub initial_supply: i128,
    pub user_balances: HashMap<String, i128>,
    pub protocol_reserves: i128,
    pub total_minted: i128,
    pub total_burned: i128,

    // Nonce replay tracking: address -> sequence of nonces observed
    pub nonces: HashMap<String, u64>,
    pub nonce_history: HashMap<String, Vec<u64>>,

    // Arbitrary key-value store for extensible domain invariants
    pub metadata: HashMap<String, String>,
}

impl Default for FuzzState {
    fn default() -> Self {
        Self {
            step: 0,
            ledger_sequence: 1,
            timestamp: 1_700_000_000,
            total_assets: 0,
            total_liabilities: 0,
            initial_supply: 0,
            user_balances: HashMap::new(),
            protocol_reserves: 0,
            total_minted: 0,
            total_burned: 0,
            nonces: HashMap::new(),
            nonce_history: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
}

impl FuzzState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records account nonce update, maintaining chronological history.
    pub fn update_nonce(&mut self, address: &str, new_nonce: u64) {
        let entry = self.nonce_history.entry(address.to_string()).or_default();
        entry.push(new_nonce);
        self.nonces.insert(address.to_string(), new_nonce);
    }

    /// Sets balance for user.
    pub fn set_balance(&mut self, address: &str, amount: i128) {
        self.user_balances.insert(address.to_string(), amount);
    }

    /// Sums all user balances.
    pub fn sum_user_balances(&self) -> i128 {
        self.user_balances.values().copied().sum()
    }
}

/// Detailed violation report when an invariant check fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub invariant_name: String,
    pub description: String,
    pub expected: String,
    pub actual: String,
    pub step: usize,
    pub ledger_sequence: u32,
    pub severity: ViolationSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Fatal,
    High,
    Medium,
}

impl std::fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}] Invariant '{}' failed at step {} (ledger {}): {}. Expected: {}, Actual: {}",
            self.severity,
            self.invariant_name,
            self.step,
            self.ledger_sequence,
            self.description,
            self.expected,
            self.actual
        )
    }
}

/// Core trait implemented by all invariants in the fuzzer engine.
pub trait Invariant: Send + Sync {
    /// Distinct human-readable identifier for this invariant.
    fn name(&self) -> &'static str;

    /// Evaluates the invariant against current system state.
    fn check(&self, state: &FuzzState) -> Result<(), InvariantViolation>;
}

/// Report summarizing all invariant evaluations across a test run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvariantReport {
    pub total_evaluated: usize,
    pub violations: Vec<InvariantViolation>,
    pub passed: bool,
}

/// Engine managing registration and collective evaluation of invariants.
pub struct InvariantEngine {
    invariants: Vec<Box<dyn Invariant>>,
}

impl Default for InvariantEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl InvariantEngine {
    pub fn new() -> Self {
        Self {
            invariants: Vec::new(),
        }
    }

    /// Creates an engine preconfigured with all default standard invariants.
    pub fn standard() -> Self {
        let mut engine = Self::new();
        engine.register(SolvencyInvariant::default());
        engine.register(TotalSupplyConservationInvariant);
        engine.register(ReplayNonceMonotonicityInvariant::default());
        engine
    }

    /// Registers a new invariant into the engine.
    pub fn register<I: Invariant + 'static>(&mut self, invariant: I) {
        self.invariants.push(Box::new(invariant));
    }

    /// Evaluates all registered invariants against current state.
    pub fn evaluate_all(&self, state: &FuzzState) -> InvariantReport {
        let mut violations = Vec::new();
        for inv in &self.invariants {
            if let Err(violation) = inv.check(state) {
                violations.push(violation);
            }
        }

        let passed = violations.is_empty();
        InvariantReport {
            total_evaluated: self.invariants.len(),
            violations,
            passed,
        }
    }
}
