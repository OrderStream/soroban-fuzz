//! Audit orchestrator executing full invariant verification campaigns.

use crate::ttl_tester::TtlBoundaryTester;
use crate::wasm_hook::{WasmBytecodeInfo, WasmHook};
use serde::{Deserialize, Serialize};
use soroban_fuzz_core::{
    AuditCertificate, DeterministicFuzzer, FuzzInvariantHarness,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub protocol_name: String,
    pub contract_id: String,
    pub target_network: String,
    pub total_campaign_steps: usize,
    pub ledgers_to_simulate: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub wasm_path: Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            protocol_name: "SorobanProtocol".into(),
            contract_id: "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".into(),
            target_network: "futurenet".into(),
            total_campaign_steps: 100,
            ledgers_to_simulate: 50,
            min_ttl: 16,
            max_ttl: 3110400,
            wasm_path: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditExecutionSummary {
    pub wasm_info: Option<WasmBytecodeInfo>,
    pub ttl_boundary_report: Option<crate::ttl_tester::TtlBoundaryReport>,
    pub certificate: AuditCertificate,
    pub json_report: String,
    pub markdown_report: String,
}

pub struct AuditEngine;

impl AuditEngine {
    pub fn execute(config: AuditConfig) -> Result<AuditExecutionSummary, String> {
        // 1. Inspect WASM bytecode if supplied, or mock it
        let wasm_info = if let Some(path) = &config.wasm_path {
            let bytes = std::fs::read(path)
                .map_err(|e| format!("Failed to read WASM at {}: {}", path, e))?;
            Some(WasmHook::inspect(&bytes)?)
        } else {
            let mock = WasmHook::create_mock_soroban_wasm(
                &config.protocol_name,
                &["initialize", "deposit", "withdraw", "rebalance"],
            );
            Some(WasmHook::inspect(&mock)?)
        };

        // 2. Initialize Harness and Deterministic Invariant Campaign
        let mut harness = FuzzInvariantHarness::new();
        let mut fuzzer = DeterministicFuzzer::new(0xCAFEBABE);

        // Run multi-step campaign with state actions and ledger advances
        for _ in 0..config.total_campaign_steps {
            let action = fuzzer.next_action(&harness.state);
            let _ = harness.step(action);
        }

        // 3. Exercise Storage TTL eviction boundaries
        let mut ttl_tester = TtlBoundaryTester::new(config.min_ttl, config.max_ttl);
        let boundary_report = ttl_tester.run_boundary_campaign(config.ledgers_to_simulate, 10);

        // 4. Generate verifiable audit certificate
        let certificate = AuditCertificate::generate(
            config.protocol_name,
            config.contract_id,
            config.target_network,
            config.ledgers_to_simulate,
            &harness.step_history,
        );

        let json_report = certificate
            .to_json_pretty()
            .map_err(|e| format!("Serialization failure: {}", e))?;
        let mut markdown_report = certificate.to_markdown_report();

        // Enrich markdown report with WASM and TTL boundary sections
        if let Some(info) = &wasm_info {
            markdown_report.push_str("\n## 📦 WASM Bytecode Inspection\n\n");
            markdown_report.push_str(&format!("- **Bytecode SHA-256:** `{}`\n", info.sha256_hash));
            markdown_report.push_str(&format!("- **Module Size:** {} bytes\n", info.bytecode_size_bytes));
            markdown_report.push_str(&format!("- **Total Sections:** {}\n", info.total_sections));
            markdown_report.push_str(&format!("- **Soroban Spec Section:** {}\n", if info.has_soroban_spec { "✅ Detected (`contractspecv0`)" } else { "⚠️ None" }));
            markdown_report.push_str(&format!("- **Exported Functions ({}):** {}\n\n", info.exported_functions.len(), info.exported_functions.join(", ")));
        }

        markdown_report.push_str("## ⏳ Storage TTL Eviction Boundaries Simulation\n\n");
        markdown_report.push_str(&format!("- **Total Storage Keys Tested:** {}\n", boundary_report.total_keys_tested));
        markdown_report.push_str(&format!("- **Temporary Evictions Handled:** {}\n", boundary_report.temporary_evictions));
        markdown_report.push_str(&format!("- **Instance Evictions Handled:** {}\n", boundary_report.instance_evictions));
        markdown_report.push_str(&format!("- **Persistent Evictions Handled:** {}\n", boundary_report.persistent_evictions));
        markdown_report.push_str(&format!("- **Restored Persistent Keys:** {}\n", boundary_report.restored_persistent_keys));
        markdown_report.push_str(&format!("- **Status:** {}\n", boundary_report.status));

        Ok(AuditExecutionSummary {
            wasm_info,
            ttl_boundary_report: Some(boundary_report),
            certificate,
            json_report,
            markdown_report,
        })
    }
}
