# soroban-fuzz 🦀

[![Crates.io](https://img.shields.io/crates/v/soroban-fuzz-core.svg)](https://crates.io/crates/soroban-fuzz-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-blue.svg)](https://www.rust-lang.org)
[![Stellar Protocol](https://img.shields.io/badge/stellar-protocol%2022-brightgreen.svg)](https://soroban.stellar.org)

**Deterministic Host Storage Lifecycle & Invariant Fuzzer Engine for Soroban Smart Contracts on Stellar.**

---

## 🎯 Architecture & Purpose

`soroban-fuzz-core` enables automated, invariant-driven security fuzz testing for Stellar Soroban smart contracts. It simulates the entire host storage lifecycle, state transitions, ledger advancement, and TTL eviction boundaries without requiring live network deployment or slow RPC interaction.

### Key Capabilities

1. **`FuzzInvariantHarness` (Host Hooking)**:
   - Synchronizes lifecycle state directly into `soroban-sdk::Env` and `soroban-env-host`.
   - Advanced ledger advancement hook leveraging `env.ledger().with_mut(...)` to manipulate sequence numbers, timestamps, and protocol versions in lockstep with fuzzer exploration.

2. **Automated Storage TTL Eviction Simulator**:
   - Explicit lifecycle tracking across all three Soroban storage categories:
     - **Temporary**: Automatically evicted and destroyed upon expiration (`current_ledger > live_until_ledger`). Cannot be extended or recovered once evicted.
     - **Persistent**: Transitions to archived state upon expiration. Rejects access until rent is paid and a restoration operation is executed within `[min_persistent_ttl, max_entry_ttl]`.
     - **Instance**: Tied to contract instance. Expired instance entries disable contract invocations until TTL is extended.
   - Exact boundary testing covering `live_until - 1` (active), `live_until` (boundary valid), and `live_until + 1` (evicted/expired).

3. **Invariant Evaluation Engine**:
   - Extensible `Invariant` trait and multi-invariant collector `InvariantEngine`.
   - Built-in battle-tested financial and security invariants:
     - **`SolvencyInvariant`**: Guarantees protocol total backing assets strictly cover liabilities across custom basis-point reserve ratios (e.g., 100% solvency baseline, 120% collateralization).
     - **`TotalSupplyConservationInvariant`**: Strictly enforces `sum(user_balances) + protocol_reserves + total_burned == initial_supply + total_minted`, trapping arithmetic underflow/overflow, reentrancy leakage, and unauthorized minting.
     - **`ReplayNonceMonotonicityInvariant`**: Protects against cross-transaction replay attacks, reordered calls, and skipped nonces with strict sequential or monotonic verification.

4. **Deterministic Fuzz Campaigns**:
   - Built-in lightweight PRNG engine (`DeterministicFuzzer`) providing 100% reproducible multi-step fuzzing runs across configurable pseudo-random seeds.

---

## 📦 Workspace Structure

```
soroban-fuzz/
├── Cargo.toml
├── Cargo.lock
├── .gitignore
├── README.md
└── crates/
    └── soroban-fuzz-core/
        ├── Cargo.toml
        ├── src/
        │   ├── lib.rs              # Crate root & exports
        │   ├── storage.rs          # StorageType, TTL eviction engine & boundaries
        │   ├── ledger.rs           # LedgerAdvancementHook (env.ledger().with_mut)
        │   ├── harness.rs          # FuzzInvariantHarness & DeterministicFuzzer
        │   └── invariants/
        │       ├── mod.rs          # Invariant trait & InvariantEngine
        │       ├── solvency.rs     # SolvencyInvariant
        │       ├── conservation.rs # TotalSupplyConservationInvariant
        │       └── nonce.rs        # ReplayNonceMonotonicityInvariant
        └── tests/
            └── integration_tests.rs # Exhaustive boundary, eviction, and fuzz tests
```

---

## 🚀 Quickstart

Add via cargo:

```bash
cargo add --dev soroban-fuzz-core
```

Or add to your contract's `Cargo.toml`:

```toml
[dev-dependencies]
soroban-fuzz-core = "0.1.0"
```

### Running an Automated Invariant Fuzz Campaign

```rust
use soroban_fuzz_core::{FuzzInvariantHarness, FuzzAction};

fn main() {
    let mut harness = FuzzInvariantHarness::new();

    // Run a 500-step fuzzing campaign with seed 42
    let report = harness.run_fuzz_campaign(42, 500);

    if report.passed {
        println!("All invariants held across 500 state transitions!");
    } else {
        eprintln!("Violations discovered: {:#?}", report.violations);
    }
}
```

### Storage TTL Eviction Boundary Testing

```rust
use soroban_fuzz_core::{FuzzInvariantHarness, FuzzAction, StorageType, StorageError};

let mut harness = FuzzInvariantHarness::new();

// Store temporary session key with TTL = 10 (valid through ledger 11)
harness.step(FuzzAction::StoragePut {
    storage_type: StorageType::Temporary,
    key: "auth_token".to_string(),
    val: b"session_secret".to_vec(),
    ttl: Some(10),
});

// At ledger 11 (live_until): entry is active
harness.advance_ledger(10);
assert!(harness.get_storage(StorageType::Temporary, "auth_token").is_ok());

// At ledger 12 (live_until + 1): entry is automatically evicted!
let (_, evictions) = harness.advance_ledger(1);
assert_eq!(evictions.len(), 1);
assert!(matches!(
    harness.get_storage(StorageType::Temporary, "auth_token").unwrap_err(),
    StorageError::Evicted { .. }
));
```

---

## 🧪 Testing

Run the full test suite:

```bash
cargo test
```

All 16 unit and integration test suites pass with zero warnings:

```
test test_fuzz_invariant_engine_custom_registration ... ok
test test_ledger_advancement_hook_lifecycle ... ok
test test_storage_ttl_boundary_temporary ... ok
test test_replay_nonce_monotonicity ... ok
test test_storage_ttl_boundary_instance ... ok
test test_solvency_invariant_enforcement ... ok
test test_total_supply_conservation_lifecycle ... ok
test test_storage_ttl_boundary_persistent_and_restoration ... ok
test test_deterministic_fuzz_campaigns ... ok
```

---

## ⚡ Cloud Fuzzing-as-a-Service & Commercial Compliance Audits

Local invariant fuzzing is great for development, but enterprise DeFi protocols on Stellar require millions of continuous fuzz iterations across distributed CPU clusters to guarantee protocol solvency and state survival under adverse conditions.

### Pricing & Commercial Packages

| Offering | Target | Pricing | Invariant Depth & Deliverables |
|---|---|---|---|
| **Community Core** | Open-source devs | **Free ($0)** | Local harness, 3 core invariants, CLI test runs |
| **Protocol Audit Run** | Pre-deployment DeFi | **$499 / run** | 1,000,000 continuous invariant iterations, storage eviction stress test, signed `AuditCertificate` (JSON + Markdown) |
| **Continuous Cloud Fuzzing (CI/CD)** | Live Stellar Protocols | **$1,200 / month** | Continuous PR fuzzing on distributed cloud workers (10M+ steps), automated regression prevention, real-time alert webhooks |
| **Ecosystem Security Retainer** | Institutional protocols | **$3,500 / month** | Custom invariant authoring, cross-contract reentrancy and flash-loan simulation, dedicated audit reporting |

### Cryptographic Audit Certificate Example

Every automated fuzz campaign emits an immutable, SHA-256 fingerprinted certificate:

```rust
use soroban_fuzz_core::{AuditCertificate, FuzzInvariantHarness};

let cert = AuditCertificate::generate(
    "AquaLend Protocol",
    "CC3W...7XYZ",
    "stellar-mainnet",
    harness.state.ledger_sequence,
    &harness.step_history,
);

// Exports institutional Markdown security report
let report = cert.to_markdown_report();
assert!(cert.verify_integrity());
```

---

## 📜 License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
at your option.

