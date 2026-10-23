use soroban_audit::{AuditConfig, AuditEngine, TtlBoundaryTester, WasmHook};
use soroban_fuzz_core::AuditCertificate;

#[test]
fn test_audit_engine_execution_and_integrity() {
    let config = AuditConfig {
        protocol_name: "TestLendingProtocol".into(),
        contract_id: "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".into(),
        target_network: "testnet".into(),
        total_campaign_steps: 60,
        ledgers_to_simulate: 40,
        min_ttl: 16,
        max_ttl: 100_000,
        wasm_path: None,
    };

    let summary = AuditEngine::execute(config).expect("Audit execution should succeed");

    assert_eq!(summary.certificate.protocol_name, "TestLendingProtocol");
    assert!(summary.certificate.verify_integrity());
    assert!(!summary.certificate.cryptographic_fingerprint.is_empty());

    // JSON roundtrip test
    let parsed_cert = AuditCertificate::from_json(&summary.json_report)
        .expect("Should deserialize valid JSON certificate");
    assert_eq!(parsed_cert.certificate_id, summary.certificate.certificate_id);
    assert!(parsed_cert.verify_integrity());

    // Markdown content verification
    assert!(summary.markdown_report.contains("Stellar Soroban Invariant Security Audit Certificate"));
    assert!(summary.markdown_report.contains(&summary.certificate.certificate_id));
    assert!(summary.markdown_report.contains("WASM Bytecode Inspection"));
    assert!(summary.markdown_report.contains("Storage TTL Eviction Boundaries Simulation"));
    assert!(summary.ttl_boundary_report.is_some());
    let ttl_rep = summary.ttl_boundary_report.unwrap();
    assert_eq!(ttl_rep.status, "BOUNDARY_ANALYSIS_COMPLETED");
}

#[test]
fn test_wasm_hook_with_real_mock() {
    let mock_bytes = WasmHook::create_mock_soroban_wasm(
        "OrderStreamAMM",
        &["swap", "provide_liquidity", "skim"],
    );
    let info = WasmHook::inspect(&mock_bytes).expect("Inspection should succeed");
    assert!(info.has_soroban_spec);
    assert_eq!(info.exported_functions.len(), 3);
}

#[test]
fn test_tampered_certificate_fails_verification() {
    let config = AuditConfig::default();
    let summary = AuditEngine::execute(config).expect("Audit should run");
    let mut cert = summary.certificate;

    // Tamper with data
    cert.total_steps_executed += 999;
    assert!(!cert.verify_integrity(), "Tampered certificate must fail integrity check");
}

#[test]
fn test_ttl_boundary_stress_simulation() {
    let mut tester = TtlBoundaryTester::new(5, 50);
    let report = tester.run_boundary_campaign(20, 10);
    assert_eq!(report.total_keys_tested, 30);
    assert!(report.temporary_evictions > 0);
}
