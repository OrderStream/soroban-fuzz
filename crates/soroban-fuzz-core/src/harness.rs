use crate::invariants::{FuzzState, Invariant, InvariantEngine, InvariantReport};
use crate::ledger::{LedgerAdvancementHook, LedgerSnapshot};
use crate::storage::{EvictionEvent, StorageEntry, StorageError, StorageTtlManager, StorageType};
use serde::{Deserialize, Serialize};
use soroban_sdk::Env;

/// High-level fuzzing action that can be executed on the harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FuzzAction {
    AdvanceLedger {
        delta_ledgers: u32,
    },
    AdvanceLedgerCustom {
        delta_ledgers: u32,
        delta_seconds: u64,
    },
    StoragePut {
        storage_type: StorageType,
        key: String,
        val: Vec<u8>,
        ttl: Option<u32>,
    },
    StorageGet {
        storage_type: StorageType,
        key: String,
    },
    StorageExtendTtl {
        storage_type: StorageType,
        key: String,
        extend_by: u32,
    },
    StorageRestore {
        key: String,
        restore_ttl: u32,
    },
    Mint {
        to: String,
        amount: i128,
    },
    Burn {
        from: String,
        amount: i128,
    },
    Transfer {
        from: String,
        to: String,
        amount: i128,
    },
    DepositCollateral {
        user: String,
        asset_amount: i128,
    },
    BorrowLiability {
        user: String,
        borrow_amount: i128,
    },
    RepayLiability {
        user: String,
        repay_amount: i128,
    },
    SubmitTx {
        sender: String,
        nonce: u64,
    },
}

/// Result of executing a single fuzz step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzStepResult {
    pub step: usize,
    pub action: FuzzAction,
    pub success: bool,
    pub error: Option<String>,
    pub evictions: Vec<EvictionEvent>,
    pub invariant_report: InvariantReport,
}

/// Main Soroban Fuzz Invariant Harness hooking host environment, storage lifecycle, and invariant engine.
pub struct FuzzInvariantHarness {
    pub env: Env,
    pub ledger_hook: LedgerAdvancementHook,
    pub storage: StorageTtlManager,
    pub invariant_engine: InvariantEngine,
    pub state: FuzzState,
    pub step_history: Vec<FuzzStepResult>,
}

impl Default for FuzzInvariantHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl FuzzInvariantHarness {
    /// Creates a new harness with default Soroban Env, ledger hook, storage manager, and standard invariants.
    pub fn new() -> Self {
        let env = Env::default();
        let ledger_hook = LedgerAdvancementHook::default();
        ledger_hook.sync_to_env(&env);

        let storage = StorageTtlManager::default();
        let invariant_engine = InvariantEngine::standard();
        let mut state = FuzzState::new();
        state.ledger_sequence = ledger_hook.sequence_number;
        state.timestamp = ledger_hook.timestamp;

        Self {
            env,
            ledger_hook,
            storage,
            invariant_engine,
            state,
            step_history: Vec::new(),
        }
    }

    /// Registers a custom invariant into the harness.
    pub fn add_invariant<I: Invariant + 'static>(&mut self, invariant: I) {
        self.invariant_engine.register(invariant);
    }

    /// Returns the current ledger snapshot.
    pub fn current_ledger(&self) -> LedgerSnapshot {
        self.ledger_hook.snapshot()
    }

    /// Advances the Soroban host ledger sequence and timestamp, updates the Soroban Env,
    /// performs automated storage TTL eviction checks, and updates state.
    pub fn advance_ledger(&mut self, delta_ledgers: u32) -> (LedgerSnapshot, Vec<EvictionEvent>) {
        let snapshot = self.ledger_hook.advance_ledger(&self.env, delta_ledgers);
        let evictions = self.storage.advance_and_evict(snapshot.sequence_number);

        self.state.ledger_sequence = snapshot.sequence_number;
        self.state.timestamp = snapshot.timestamp;

        (snapshot, evictions)
    }

    /// Advances ledger with custom seconds.
    pub fn advance_ledger_custom(
        &mut self,
        delta_ledgers: u32,
        delta_seconds: u64,
    ) -> (LedgerSnapshot, Vec<EvictionEvent>) {
        let snapshot = self
            .ledger_hook
            .advance_custom(&self.env, delta_ledgers, delta_seconds);
        let evictions = self.storage.advance_and_evict(snapshot.sequence_number);

        self.state.ledger_sequence = snapshot.sequence_number;
        self.state.timestamp = snapshot.timestamp;

        (snapshot, evictions)
    }

    /// Executes a fuzz action, performs boundary checks, evaluates all invariants,
    /// and records the step result.
    pub fn step(&mut self, action: FuzzAction) -> FuzzStepResult {
        self.state.step += 1;
        let step = self.state.step;
        let mut evictions = Vec::new();
        let mut step_err = None;

        match &action {
            FuzzAction::AdvanceLedger { delta_ledgers } => {
                let (_, ev) = self.advance_ledger(*delta_ledgers);
                evictions = ev;
            }
            FuzzAction::AdvanceLedgerCustom {
                delta_ledgers,
                delta_seconds,
            } => {
                let (_, ev) = self.advance_ledger_custom(*delta_ledgers, *delta_seconds);
                evictions = ev;
            }
            FuzzAction::StoragePut {
                storage_type,
                key,
                val,
                ttl,
            } => {
                if let Err(e) = self.storage.put(
                    *storage_type,
                    key,
                    val.clone(),
                    self.state.ledger_sequence,
                    *ttl,
                ) {
                    step_err = Some(e.to_string());
                }
            }
            FuzzAction::StorageGet { storage_type, key } => {
                if let Err(e) = self
                    .storage
                    .get(*storage_type, key, self.state.ledger_sequence)
                {
                    step_err = Some(e.to_string());
                }
            }
            FuzzAction::StorageExtendTtl {
                storage_type,
                key,
                extend_by,
            } => {
                if let Err(e) = self.storage.extend_ttl(
                    *storage_type,
                    key,
                    self.state.ledger_sequence,
                    *extend_by,
                ) {
                    step_err = Some(e.to_string());
                }
            }
            FuzzAction::StorageRestore { key, restore_ttl } => {
                if let Err(e) =
                    self.storage
                        .restore_persistent(key, self.state.ledger_sequence, *restore_ttl)
                {
                    step_err = Some(e.to_string());
                }
            }
            FuzzAction::Mint { to, amount } => {
                if *amount < 0 {
                    step_err = Some("Cannot mint negative amount".to_string());
                } else {
                    let cur = self.state.user_balances.entry(to.clone()).or_insert(0);
                    *cur = cur.saturating_add(*amount);
                    self.state.total_minted = self.state.total_minted.saturating_add(*amount);
                }
            }
            FuzzAction::Burn { from, amount } => {
                if *amount < 0 {
                    step_err = Some("Cannot burn negative amount".to_string());
                } else {
                    let cur = self.state.user_balances.entry(from.clone()).or_insert(0);
                    if *cur < *amount {
                        step_err = Some(format!("Insufficient balance: has {}, burn {}", cur, amount));
                    } else {
                        *cur = cur.saturating_sub(*amount);
                        self.state.total_burned = self.state.total_burned.saturating_add(*amount);
                    }
                }
            }
            FuzzAction::Transfer { from, to, amount } => {
                if *amount < 0 {
                    step_err = Some("Cannot transfer negative amount".to_string());
                } else {
                    let from_bal = self.state.user_balances.entry(from.clone()).or_insert(0);
                    if *from_bal < *amount {
                        step_err = Some(format!("Insufficient balance: has {}, transfer {}", from_bal, amount));
                    } else {
                        *from_bal = from_bal.saturating_sub(*amount);
                        let to_bal = self.state.user_balances.entry(to.clone()).or_insert(0);
                        *to_bal = to_bal.saturating_add(*amount);
                    }
                }
            }
            FuzzAction::DepositCollateral { user: _, asset_amount } => {
                if *asset_amount < 0 {
                    step_err = Some("Cannot deposit negative collateral".to_string());
                } else {
                    self.state.total_assets = self.state.total_assets.saturating_add(*asset_amount);
                }
            }
            FuzzAction::BorrowLiability { user: _, borrow_amount } => {
                if *borrow_amount < 0 {
                    step_err = Some("Cannot borrow negative liability".to_string());
                } else {
                    self.state.total_liabilities =
                        self.state.total_liabilities.saturating_add(*borrow_amount);
                }
            }
            FuzzAction::RepayLiability { user: _, repay_amount } => {
                if *repay_amount < 0 {
                    step_err = Some("Cannot repay negative amount".to_string());
                } else {
                    self.state.total_liabilities =
                        self.state.total_liabilities.saturating_sub(*repay_amount);
                }
            }
            FuzzAction::SubmitTx { sender, nonce } => {
                self.state.update_nonce(sender, *nonce);
            }
        }

        let invariant_report = self.invariant_engine.evaluate_all(&self.state);
        let success = step_err.is_none() && invariant_report.passed;

        let result = FuzzStepResult {
            step,
            action,
            success,
            error: step_err,
            evictions,
            invariant_report,
        };

        self.step_history.push(result.clone());
        result
    }

    /// Evaluates invariants immediately without executing an action.
    pub fn check_invariants(&self) -> InvariantReport {
        self.invariant_engine.evaluate_all(&self.state)
    }

    /// Directly gets a storage entry from the storage manager.
    pub fn get_storage(
        &self,
        storage_type: StorageType,
        key: &str,
    ) -> Result<&StorageEntry, StorageError> {
        self.storage
            .get(storage_type, key, self.state.ledger_sequence)
    }

    /// Runs an automated deterministic fuzz campaign across a given number of steps.
    /// Invariant violations halt the campaign early and return the violation report.
    pub fn run_fuzz_campaign(&mut self, seed: u64, steps: usize) -> InvariantReport {
        let mut fuzzer = DeterministicFuzzer::new(seed);
        for _ in 0..steps {
            let action = fuzzer.next_action(&self.state);
            let res = self.step(action);
            if !res.invariant_report.passed {
                return res.invariant_report;
            }
        }
        self.check_invariants()
    }
}

/// Lightweight, deterministic XorShift64 PRNG and fuzz action generator for reproducible fuzz campaigns.
#[derive(Debug, Clone)]
pub struct DeterministicFuzzer {
    state: u64,
}

impl DeterministicFuzzer {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x853c49e6748fea9b } else { seed },
        }
    }

    /// Generates next 64-bit pseudo-random integer.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn gen_range_u32(&mut self, min: u32, max: u32) -> u32 {
        if min >= max {
            return min;
        }
        let range = (max - min) as u64;
        min + (self.next_u64() % range) as u32
    }

    pub fn gen_range_i128(&mut self, min: i128, max: i128) -> i128 {
        if min >= max {
            return min;
        }
        let range = (max - min) as u64;
        min + (self.next_u64() % range) as i128
    }

    /// Generates a valid or boundary-probing fuzz action based on current system state.
    pub fn next_action(&mut self, current_state: &FuzzState) -> FuzzAction {
        let action_choice = self.gen_range_u32(0, 8);
        match action_choice {
            0 => FuzzAction::AdvanceLedger {
                delta_ledgers: self.gen_range_u32(1, 20),
            },
            1 => {
                let user_idx = self.gen_range_u32(0, 5);
                let user = format!("user_{}", user_idx);
                let amount = self.gen_range_i128(100, 5_000);
                FuzzAction::Mint { to: user, amount }
            }
            2 => {
                let from_idx = self.gen_range_u32(0, 5);
                let to_idx = (from_idx + 1) % 5;
                let from_user = format!("user_{}", from_idx);
                let to_user = format!("user_{}", to_idx);
                let bal = *current_state.user_balances.get(&from_user).unwrap_or(&0);
                let amount = if bal > 0 {
                    self.gen_range_i128(1, bal)
                } else {
                    0
                };
                FuzzAction::Transfer {
                    from: from_user,
                    to: to_user,
                    amount,
                }
            }
            3 => {
                let user_idx = self.gen_range_u32(0, 5);
                let user = format!("user_{}", user_idx);
                let bal = *current_state.user_balances.get(&user).unwrap_or(&0);
                let amount = if bal > 0 {
                    self.gen_range_i128(1, bal.min(500))
                } else {
                    0
                };
                FuzzAction::Burn { from: user, amount }
            }
            4 => {
                let st_choice = self.gen_range_u32(0, 3);
                let storage_type = match st_choice {
                    0 => StorageType::Temporary,
                    1 => StorageType::Instance,
                    _ => StorageType::Persistent,
                };
                let key_idx = self.gen_range_u32(0, 10);
                let key = format!("storage_key_{}", key_idx);
                let ttl = self.gen_range_u32(5, 50);
                let val = format!("val_{}", self.next_u64()).into_bytes();
                FuzzAction::StoragePut {
                    storage_type,
                    key,
                    val,
                    ttl: Some(ttl),
                }
            }
            5 => {
                let sender_idx = self.gen_range_u32(0, 3);
                let sender = format!("sender_{}", sender_idx);
                let cur_nonce = *current_state.nonces.get(&sender).unwrap_or(&0);
                FuzzAction::SubmitTx {
                    sender,
                    nonce: cur_nonce + 1,
                }
            }
            6 => {
                let asset = self.gen_range_i128(500, 3_000);
                FuzzAction::DepositCollateral {
                    user: "alice".to_string(),
                    asset_amount: asset,
                }
            }
            _ => {
                let max_borrow = current_state.total_assets.saturating_sub(current_state.total_liabilities);
                let borrow = if max_borrow > 100 {
                    self.gen_range_i128(50, max_borrow / 2)
                } else {
                    0
                };
                FuzzAction::BorrowLiability {
                    user: "bob".to_string(),
                    borrow_amount: borrow,
                }
            }
        }
    }
}
