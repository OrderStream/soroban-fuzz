use soroban_fuzz_core::{
    FuzzAction, FuzzInvariantHarness, StorageError, StorageType, ViolationSeverity,
};

#[test]
fn test_ledger_advancement_hook_lifecycle() {
    let mut harness = FuzzInvariantHarness::new();

    // Verify initial ledger synchronized into Soroban Env
    assert_eq!(harness.env.ledger().sequence(), 1);
    assert_eq!(harness.env.ledger().timestamp(), 1_700_000_000);
    assert_eq!(harness.env.ledger().protocol_version(), 22);

    // Advance by 15 ledgers (15 * 5s = 75s)
    let (snapshot, evictions) = harness.advance_ledger(15);
    assert_eq!(snapshot.sequence_number, 16);
    assert_eq!(snapshot.timestamp, 1_700_000_075);
    assert_eq!(harness.env.ledger().sequence(), 16);
    assert_eq!(harness.env.ledger().timestamp(), 1_700_000_075);
    assert!(evictions.is_empty());

    // Advance custom delta
    let (custom_snap, _) = harness.advance_ledger_custom(5, 30);
    assert_eq!(custom_snap.sequence_number, 21);
    assert_eq!(custom_snap.timestamp, 1_700_000_105);
    assert_eq!(harness.env.ledger().sequence(), 21);
    assert_eq!(harness.env.ledger().timestamp(), 1_700_000_105);
}

#[test]
fn test_storage_ttl_boundary_temporary() {
    let mut harness = FuzzInvariantHarness::new();
    // Ledger is at 1. Store temporary key with TTL = 10 -> live_until = 11
    harness.step(FuzzAction::StoragePut {
        storage_type: StorageType::Temporary,
        key: "session_token".to_string(),
        val: b"temp_secret_123".to_vec(),
        ttl: Some(10),
    });

    // Boundary Check 1: live_until - 1 (ledger 10)
    harness.advance_ledger(9); // 1 + 9 = 10
    assert_eq!(harness.state.ledger_sequence, 10);
    let entry = harness
        .get_storage(StorageType::Temporary, "session_token")
        .expect("Should be active at live_until - 1");
    assert_eq!(entry.remaining_ttl(10), 1);

    // Boundary Check 2: live_until exactly (ledger 11)
    harness.advance_ledger(1); // 10 + 1 = 11
    assert_eq!(harness.state.ledger_sequence, 11);
    let entry = harness
        .get_storage(StorageType::Temporary, "session_token")
        .expect("Should be active at live_until");
    assert_eq!(entry.remaining_ttl(11), 0);

    // Boundary Check 3: live_until + 1 (ledger 12) -> EVICTED
    let (_, evictions) = harness.advance_ledger(1);
    assert_eq!(harness.state.ledger_sequence, 12);
    assert_eq!(evictions.len(), 1);
    assert_eq!(evictions[0].key, "session_token");
    assert!(evictions[0].permanently_deleted);

    // Access must fail with Evicted error
    let err = harness
        .get_storage(StorageType::Temporary, "session_token")
        .expect_err("Must be evicted");
    match err {
        StorageError::NotFound { .. } | StorageError::Evicted { .. } => {}
        _ => panic!("Expected evicted or not found error, got {:?}", err),
    }

    // Attempting to extend TTL on an evicted temporary key must fail
    let extend_err = harness
        .storage
        .extend_ttl(StorageType::Temporary, "session_token", 12, 100)
        .expect_err("Cannot extend evicted temporary key");
    match extend_err {
        StorageError::NotFound { .. } | StorageError::Evicted { .. } => {}
        _ => panic!("Expected evicted or not found error, got {:?}", extend_err),
    }
}

#[test]
fn test_storage_ttl_boundary_persistent_and_restoration() {
    let mut harness = FuzzInvariantHarness::new();
    // Ledger is at 1. Store persistent key with TTL = 20 -> live_until = 21
    harness.step(FuzzAction::StoragePut {
        storage_type: StorageType::Persistent,
        key: "user_vault_state".to_string(),
        val: b"vault_data_v1".to_vec(),
        ttl: Some(20),
    });

    // Advance to ledger 21: still active
    harness.advance_ledger(20);
    assert_eq!(harness.state.ledger_sequence, 21);
    assert!(harness
        .get_storage(StorageType::Persistent, "user_vault_state")
        .is_ok());

    // Advance past expiration: ledger 22 (live_until + 1)
    let (_, evictions) = harness.advance_ledger(1);
    assert_eq!(harness.state.ledger_sequence, 22);
    assert_eq!(evictions.len(), 1);
    assert_eq!(evictions[0].key, "user_vault_state");
    assert!(!evictions[0].permanently_deleted); // Persistent is archived, not destroyed

    // Direct get fails with Expired
    let err = harness
        .get_storage(StorageType::Persistent, "user_vault_state")
        .expect_err("Persistent key is expired/archived");
    match err {
        StorageError::Expired { live_until, .. } => assert_eq!(live_until, 21),
        _ => panic!("Expected Expired error, got {:?}", err),
    }

    // Restoration: pay rent and restore with valid TTL >= min_persistent_ttl (16)
    let res = harness.step(FuzzAction::StorageRestore {
        key: "user_vault_state".to_string(),
        restore_ttl: 50,
    });
    assert!(res.success);

    // Entry is now restored and accessible!
    let entry = harness
        .get_storage(StorageType::Persistent, "user_vault_state")
        .expect("Should be active after restoration");
    assert_eq!(entry.live_until_ledger, 22 + 50);
    assert!(!entry.is_archived);
}

#[test]
fn test_storage_ttl_boundary_instance() {
    let mut harness = FuzzInvariantHarness::new();
    // Ledger 1. Store instance key with TTL = 15 -> live_until = 16
    harness.step(FuzzAction::StoragePut {
        storage_type: StorageType::Instance,
        key: "contract_config".to_string(),
        val: b"admin_pubkey_hash".to_vec(),
        ttl: Some(15),
    });

    // Advance to ledger 16: valid
    harness.advance_ledger(15);
    assert!(harness
        .get_storage(StorageType::Instance, "contract_config")
        .is_ok());

    // Advance to 17: expired
    harness.advance_ledger(1);
    let err = harness
        .get_storage(StorageType::Instance, "contract_config")
        .expect_err("Should be expired");
    assert!(matches!(err, StorageError::Expired { .. }));

    // Extend TTL restores instance access
    let extend_res = harness.step(FuzzAction::StorageExtendTtl {
        storage_type: StorageType::Instance,
        key: "contract_config".to_string(),
        extend_by: 100,
    });
    assert!(extend_res.success);

    assert!(harness
        .get_storage(StorageType::Instance, "contract_config")
        .is_ok());
}

#[test]
fn test_solvency_invariant_enforcement() {
    let mut harness = FuzzInvariantHarness::new();

    // Initial state: assets = 10_000, liabilities = 8_000 (125% ratio >= 100%)
    harness.step(FuzzAction::DepositCollateral {
        user: "alice".to_string(),
        asset_amount: 10_000,
    });
    harness.step(FuzzAction::BorrowLiability {
        user: "bob".to_string(),
        borrow_amount: 8_000,
    });

    let report = harness.check_invariants();
    assert!(report.passed);
    assert!(report.violations.is_empty());

    // Insolvency trigger: borrow 3_000 more -> liabilities = 11_000 > assets 10_000
    let res = harness.step(FuzzAction::BorrowLiability {
        user: "carol".to_string(),
        borrow_amount: 3_000,
    });

    assert!(!res.success);
    assert_eq!(res.invariant_report.violations.len(), 1);
    let violation = &res.invariant_report.violations[0];
    assert_eq!(violation.invariant_name, "SolvencyInvariant");
    assert_eq!(violation.severity, ViolationSeverity::Fatal);
    assert!(violation.description.contains("Insolvency detected"));

    // Cure insolvency: deposit 2_000 assets -> assets 12_000 >= liabilities 11_000
    let cure_res = harness.step(FuzzAction::DepositCollateral {
        user: "alice".to_string(),
        asset_amount: 2_000,
    });
    assert!(cure_res.success);
    assert!(cure_res.invariant_report.passed);
}

#[test]
fn test_total_supply_conservation_lifecycle() {
    let mut harness = FuzzInvariantHarness::new();

    // Initial mint: mint 1000 to Alice
    let res1 = harness.step(FuzzAction::Mint {
        to: "alice".to_string(),
        amount: 1_000,
    });
    assert!(res1.success);

    // Transfer 400 from Alice to Bob
    let res2 = harness.step(FuzzAction::Transfer {
        from: "alice".to_string(),
        to: "bob".to_string(),
        amount: 400,
    });
    assert!(res2.success);

    // Mint 500 to Bob
    let res3 = harness.step(FuzzAction::Mint {
        to: "bob".to_string(),
        amount: 500,
    });
    assert!(res3.success);

    // Burn 300 from Bob
    let res4 = harness.step(FuzzAction::Burn {
        from: "bob".to_string(),
        amount: 300,
    });
    assert!(res4.success);

    // Balances: Alice = 600, Bob = 600. Total circulating = 1200. Burned = 300.
    // Total minted = 1500. 1200 + 300 == 1500!
    assert_eq!(harness.state.sum_user_balances(), 1_200);
    assert_eq!(harness.state.total_burned, 300);
    assert_eq!(harness.state.total_minted, 1_500);

    let report = harness.check_invariants();
    assert!(report.passed);

    // Simulate token leakage bug (e.g., balance artificially inflated)
    harness.state.set_balance("alice", 700); // 100 unbacked tokens
    let corrupt_report = harness.check_invariants();
    assert!(!corrupt_report.passed);
    let violation = corrupt_report
        .violations
        .iter()
        .find(|v| v.invariant_name == "TotalSupplyConservationInvariant")
        .expect("Conservation invariant must fail");
    assert!(violation.description.contains("Supply conservation violation"));
}

#[test]
fn test_replay_nonce_monotonicity() {
    let mut harness = FuzzInvariantHarness::new();

    // Alice sends tx with nonce 1, 2, 3
    assert!(harness
        .step(FuzzAction::SubmitTx {
            sender: "alice".to_string(),
            nonce: 1,
        })
        .success);
    assert!(harness
        .step(FuzzAction::SubmitTx {
            sender: "alice".to_string(),
            nonce: 2,
        })
        .success);
    assert!(harness
        .step(FuzzAction::SubmitTx {
            sender: "alice".to_string(),
            nonce: 3,
        })
        .success);

    // Replay attack: submitting nonce 2 again!
    let replay_res = harness.step(FuzzAction::SubmitTx {
        sender: "alice".to_string(),
        nonce: 2,
    });
    assert!(!replay_res.success);
    let v = &replay_res.invariant_report.violations[0];
    assert_eq!(v.invariant_name, "ReplayNonceMonotonicityInvariant");
    assert!(v.description.contains("Replay / Nonce regression detected"));

    // Nonce gap detection in isolated harness
    let mut harness2 = FuzzInvariantHarness::new();
    assert!(harness2
        .step(FuzzAction::SubmitTx {
            sender: "bob".to_string(),
            nonce: 1,
        })
        .success);
    let gap_res = harness2.step(FuzzAction::SubmitTx {
        sender: "bob".to_string(),
        nonce: 4, // skipped 2 and 3
    });
    assert!(!gap_res.success);
    let v_gap = &gap_res.invariant_report.violations[0];
    assert!(v_gap.description.contains("Nonce gap detected"));
}

#[test]
fn test_deterministic_fuzz_campaigns() {
    let seeds = [42, 1337, 88888, 999999, 123456789];

    for &seed in &seeds {
        let mut harness = FuzzInvariantHarness::new();
        let report = harness.run_fuzz_campaign(seed, 100);

        assert!(
            report.passed,
            "Fuzz campaign for seed {} failed: {:?}",
            seed, report.violations
        );
        assert_eq!(harness.step_history.len(), 100);
    }
}

#[test]
fn test_fuzz_invariant_engine_custom_registration() {
    use soroban_fuzz_core::{FuzzState, Invariant, InvariantEngine, InvariantViolation};

    struct MinCollateralInvariant;
    impl Invariant for MinCollateralInvariant {
        fn name(&self) -> &'static str {
            "MinCollateralInvariant"
        }
        fn check(&self, state: &FuzzState) -> Result<(), InvariantViolation> {
            if state.total_assets < 500 {
                return Err(InvariantViolation {
                    invariant_name: self.name().to_string(),
                    description: "Total assets below minimum 500 threshold".to_string(),
                    expected: "total_assets >= 500".to_string(),
                    actual: format!("total_assets = {}", state.total_assets),
                    step: state.step,
                    ledger_sequence: state.ledger_sequence,
                    severity: ViolationSeverity::High,
                });
            }
            Ok(())
        }
    }

    let mut engine = InvariantEngine::new();
    engine.register(MinCollateralInvariant);

    let mut state = FuzzState::new();
    state.total_assets = 200;

    let report = engine.evaluate_all(&state);
    assert!(!report.passed);
    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations[0].invariant_name, "MinCollateralInvariant");

    state.total_assets = 600;
    let report_ok = engine.evaluate_all(&state);
    assert!(report_ok.passed);
}

#[test]
fn test_storage_ttl_extension_max_bounds() {
    let mut harness = FuzzInvariantHarness::new();
    harness.step(FuzzAction::StoragePut {
        storage_type: StorageType::Instance,
        key: "config".to_string(),
        val: b"val".to_vec(),
        ttl: Some(100),
    });

    // Attempting to extend TTL beyond max_entry_ttl must fail
    let err = harness
        .storage
        .extend_ttl(
            StorageType::Instance,
            "config",
            1,
            harness.storage.max_entry_ttl + 1,
        )
        .expect_err("Should fail when extend_by > max_entry_ttl");
    assert!(matches!(err, StorageError::InvalidTtl { .. }));
}

#[test]
fn test_storage_ttl_extension_expired_persistent_rejected() {
    let mut harness = FuzzInvariantHarness::new();
    // Persistent key expiring at ledger 11
    harness.step(FuzzAction::StoragePut {
        storage_type: StorageType::Persistent,
        key: "vault".to_string(),
        val: b"data".to_vec(),
        ttl: Some(10),
    });

    // Advance to ledger 12 (entry is now expired / archived)
    harness.advance_ledger(11);
    assert_eq!(harness.state.ledger_sequence, 12);

    // Attempting extend_ttl on expired persistent key MUST be rejected with Expired (restore required)
    let err = harness
        .storage
        .extend_ttl(StorageType::Persistent, "vault", 12, 50)
        .expect_err("extend_ttl on expired persistent key must fail; restore required");
    match err {
        StorageError::Expired { live_until, .. } => assert_eq!(live_until, 11),
        _ => panic!("Expected Expired error, got {:?}", err),
    }

    // However, restore_persistent works properly
    let res = harness.step(FuzzAction::StorageRestore {
        key: "vault".to_string(),
        restore_ttl: 50,
    });
    assert!(res.success);
    assert!(harness
        .get_storage(StorageType::Persistent, "vault")
        .is_ok());
}

#[test]
fn test_storage_ttl_extension_active_persistent_succeeds() {
    let mut harness = FuzzInvariantHarness::new();
    harness.step(FuzzAction::StoragePut {
        storage_type: StorageType::Persistent,
        key: "active_vault".to_string(),
        val: b"data".to_vec(),
        ttl: Some(50),
    });

    // While still active at ledger 10: extending TTL by 100 ledgers succeeds
    harness.advance_ledger(9);
    assert_eq!(harness.state.ledger_sequence, 10);

    let new_live_until = harness
        .storage
        .extend_ttl(StorageType::Persistent, "active_vault", 10, 100)
        .expect("extend_ttl on active persistent key should succeed");
    assert_eq!(new_live_until, 110);
}

#[test]
fn test_eviction_deterministic_ordering() {
    let mut harness = FuzzInvariantHarness::new();
    // Put multiple keys that expire at the same ledger
    harness.step(FuzzAction::StoragePut {
        storage_type: StorageType::Temporary,
        key: "temp_z".to_string(),
        val: b"z".to_vec(),
        ttl: Some(5),
    });
    harness.step(FuzzAction::StoragePut {
        storage_type: StorageType::Temporary,
        key: "temp_a".to_string(),
        val: b"a".to_vec(),
        ttl: Some(5),
    });
    harness.step(FuzzAction::StoragePut {
        storage_type: StorageType::Temporary,
        key: "temp_m".to_string(),
        val: b"m".to_vec(),
        ttl: Some(5),
    });

    // Advance past expiry
    let (_, evictions) = harness.advance_ledger(6);
    assert_eq!(evictions.len(), 3);
    // Keys must be deterministically sorted
    assert_eq!(evictions[0].key, "temp_a");
    assert_eq!(evictions[1].key, "temp_m");
    assert_eq!(evictions[2].key, "temp_z");
}

#[test]
fn test_soroban_env_host_direct_hook() {
    let mut harness = FuzzInvariantHarness::new();
    // Harness host accessor exposes soroban-env-host Host instance directly
    let host = harness.host();
    // Verify host instance is accessible
    assert!(!format!("{:?}", host).is_empty());

    // Verify ledger advancement updates both harness env and ledger hook
    harness.advance_ledger(20);
    assert_eq!(harness.env.ledger().sequence(), 21);
    assert_eq!(harness.current_ledger().sequence_number, 21);
}

#[test]
fn test_audit_certificate_generation_and_integrity() {
    use soroban_fuzz_core::{CertificateStatus, DeterministicFuzzer};

    let mut harness = FuzzInvariantHarness::new();
    let mut fuzzer = DeterministicFuzzer::new(0xDEADBEEF);
    for _ in 0..50 {
        let action = fuzzer.next_action(&harness.state);
        harness.step(action);
    }

    let cert = harness.generate_audit_certificate(
        "AquaLend Protocol",
        "CC3W...7XYZ",
        "stellar-mainnet",
    );

    assert_eq!(cert.protocol_name, "AquaLend Protocol");
    assert_eq!(cert.total_steps_executed, 50);
    assert_eq!(cert.status, CertificateStatus::CertifiedSecure);
    assert!(cert.verify_integrity());

    let md = cert.to_markdown_report();
    assert!(md.contains("AquaLend Protocol"));
    assert!(md.contains("CERTIFIED SECURE"));
    assert!(md.contains(&cert.cryptographic_fingerprint));
}

#[test]
fn test_audit_certificate_tampering_detection() {
    use soroban_fuzz_core::{CertificateStatus, DeterministicFuzzer};

    let mut harness = FuzzInvariantHarness::new();
    let mut fuzzer = DeterministicFuzzer::new(42);
    for _ in 0..20 {
        let action = fuzzer.next_action(&harness.state);
        harness.step(action);
    }

    let cert = harness.generate_audit_certificate("DefiPool", "CD...123", "testnet");
    assert!(cert.verify_integrity());

    // 1. Tampering with solvency boolean must invalidate fingerprint
    let mut tampered_solvency = cert.clone();
    tampered_solvency.solvency_invariants_passed = !tampered_solvency.solvency_invariants_passed;
    assert!(!tampered_solvency.verify_integrity(), "Tampered solvency boolean should fail verification");

    // 2. Tampering with status must invalidate fingerprint
    let mut tampered_status = cert.clone();
    tampered_status.status = CertificateStatus::ViolationsDetected;
    assert!(!tampered_status.verify_integrity(), "Tampered status should fail verification");

    // 3. Tampering with steps count must invalidate fingerprint
    let mut tampered_steps = cert.clone();
    tampered_steps.total_steps_executed += 100;
    assert!(!tampered_steps.verify_integrity(), "Tampered steps should fail verification");
}

#[test]
fn test_audit_certificate_json_roundtrip_and_violations() {
    use soroban_fuzz_core::{CertificateStatus, FuzzAction};

    let mut harness = FuzzInvariantHarness::new();
    // Intentionally trigger a solvency violation: liabilities > assets
    harness.step(FuzzAction::DepositCollateral {
        user: "alice".to_string(),
        asset_amount: 100,
    });
    harness.step(FuzzAction::BorrowLiability {
        user: "alice".to_string(),
        borrow_amount: 200,
    });

    let cert = harness.generate_audit_certificate("LendVault", "CA...999", "stellar-mainnet");
    assert_eq!(cert.status, CertificateStatus::ViolationsDetected);
    assert!(!cert.solvency_invariants_passed);
    assert_eq!(cert.violations.len(), 1);
    assert!(cert.verify_integrity());

    // Verify markdown reflects failure
    let md = cert.to_markdown_report();
    assert!(md.contains("CRITICAL VIOLATIONS DETECTED"));
    assert!(md.contains("BREACHED"));

    // Verify JSON round-trip
    let json_str = cert.to_json_pretty().expect("Failed to serialize certificate");
    let deserialized = soroban_fuzz_core::AuditCertificate::from_json(&json_str)
        .expect("Failed to deserialize certificate");
    assert_eq!(deserialized.certificate_id, cert.certificate_id);
    assert_eq!(deserialized.cryptographic_fingerprint, cert.cryptographic_fingerprint);
    assert!(deserialized.verify_integrity());
}

