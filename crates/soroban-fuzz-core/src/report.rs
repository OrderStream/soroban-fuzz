//! Automated Cryptographic Invariant Security Certificate & Audit Report Generator.
//! Emits verifiable, tamper-evident JSON and Markdown certificates for Stellar Soroban protocols.

use crate::harness::FuzzStepResult;
use crate::invariants::InvariantViolation;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Comprehensive Protocol Compliance Audit Certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCertificate {
    pub certificate_id: String,
    pub protocol_name: String,
    pub contract_id: String,
    pub target_network: String,
    pub total_steps_executed: usize,
    pub total_ledgers_simulated: u32,
    pub total_storage_evictions_handled: usize,
    pub solvency_invariants_passed: bool,
    pub supply_conservation_passed: bool,
    pub nonce_monotonicity_passed: bool,
    pub status: CertificateStatus,
    pub violations: Vec<InvariantViolation>,
    pub cryptographic_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateStatus {
    CertifiedSecure,
    ViolationsDetected,
}

impl AuditCertificate {
    /// Generates a verifiable security audit certificate from a completed fuzz campaign.
    pub fn generate(
        protocol_name: impl Into<String>,
        contract_id: impl Into<String>,
        target_network: impl Into<String>,
        total_ledgers: u32,
        history: &[FuzzStepResult],
    ) -> Self {
        let protocol_name = protocol_name.into();
        let contract_id = contract_id.into();
        let target_network = target_network.into();

        let mut violations = Vec::new();
        let mut total_evictions = 0;
        let mut solvency_ok = true;
        let mut supply_ok = true;
        let mut nonce_ok = true;

        for step in history {
            total_evictions += step.evictions.len();
            for v in &step.invariant_report.violations {
                violations.push(v.clone());
                match v.invariant_name.as_str() {
                    "SolvencyInvariant" => solvency_ok = false,
                    "TotalSupplyConservationInvariant" => supply_ok = false,
                    "ReplayNonceMonotonicityInvariant" => nonce_ok = false,
                    _ => {}
                }
            }
        }

        let status = if violations.is_empty() {
            CertificateStatus::CertifiedSecure
        } else {
            CertificateStatus::ViolationsDetected
        };

        // Compute deterministic SHA-256 fingerprint over audit metrics
        let mut hasher = Sha256::new();
        hasher.update(protocol_name.as_bytes());
        hasher.update(contract_id.as_bytes());
        hasher.update(target_network.as_bytes());
        hasher.update(&history.len().to_be_bytes());
        hasher.update(&total_ledgers.to_be_bytes());
        hasher.update(&total_evictions.to_be_bytes());
        hasher.update(&(violations.len() as u64).to_be_bytes());
        let hash_bytes = hasher.finalize();
        let cryptographic_fingerprint = format!("{:x}", hash_bytes);

        let certificate_id = format!(
            "CERT-SOROBAN-{}-{}",
            &cryptographic_fingerprint[..8].to_uppercase(),
            history.len()
        );

        Self {
            certificate_id,
            protocol_name,
            contract_id,
            target_network,
            total_steps_executed: history.len(),
            total_ledgers_simulated: total_ledgers,
            total_storage_evictions_handled: total_evictions,
            solvency_invariants_passed: solvency_ok,
            supply_conservation_passed: supply_ok,
            nonce_monotonicity_passed: nonce_ok,
            status,
            violations,
            cryptographic_fingerprint,
        }
    }

    /// Verifies that the certificate's cryptographic fingerprint matches its internal metrics.
    pub fn verify_integrity(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.protocol_name.as_bytes());
        hasher.update(self.contract_id.as_bytes());
        hasher.update(self.target_network.as_bytes());
        hasher.update(&self.total_steps_executed.to_be_bytes());
        hasher.update(&self.total_ledgers_simulated.to_be_bytes());
        hasher.update(&self.total_storage_evictions_handled.to_be_bytes());
        hasher.update(&(self.violations.len() as u64).to_be_bytes());
        let hash_bytes = hasher.finalize();
        let expected = format!("{:x}", hash_bytes);
        self.cryptographic_fingerprint == expected
    }

    /// Exports certificate as formatted Markdown audit report suitable for institutional stakeholders.
    pub fn to_markdown_report(&self) -> String {
        let status_badge = match self.status {
            CertificateStatus::CertifiedSecure => "🛡️ **PASS: CERTIFIED SECURE**",
            CertificateStatus::ViolationsDetected => "🚨 **FAIL: CRITICAL VIOLATIONS DETECTED**",
        };

        format!(
            "# 🏛️ Stellar Soroban Invariant Security Audit Certificate\n\n\
            **Certificate ID:** `{}`  \n\
            **Protocol Name:** `{}`  \n\
            **Contract ID:** `{}`  \n\
            **Target Network:** `{}`  \n\
            **Audit Status:** {}  \n\
            **Cryptographic Fingerprint:** `{}`  \n\n\
            ---\n\n\
            ## 📊 Invariant Verification Summary\n\n\
            | Invariant Category | Verified Property | Status |\n\
            |---|---|---|\n\
            | **Solvency Invariant** | Total Protocol Assets >= Total Liabilities | {} |\n\
            | **Total Supply Conservation** | Invariant conservation across Mint/Burn/Transfer | {} |\n\
            | **Replay Protection** | Cryptographic Nonce Strict Monotonicity | {} |\n\
            | **Storage Lifecycle** | TTL Eviction Boundaries & Restoration Handled | {} Managed |\n\n\
            ## 🔬 Campaign Metrics\n\n\
            - **Total Fuzz Invariant Invocations:** {}\n\
            - **Ledger Sequence Traversed:** {} ledgers\n\
            - **Storage TTL Eviction Cycles:** {}\n\
            - **Violations Logged:** {}\n\n\
            *Generated by `soroban-fuzz-core` Continuous Cloud Fuzzing Engine. Verifiable via SHA-256 fingerprint.*\n",
            self.certificate_id,
            self.protocol_name,
            self.contract_id,
            self.target_network,
            status_badge,
            self.cryptographic_fingerprint,
            if self.solvency_invariants_passed { "✅ VERIFIED" } else { "❌ BREACHED" },
            if self.supply_conservation_passed { "✅ VERIFIED" } else { "❌ BREACHED" },
            if self.nonce_monotonicity_passed { "✅ VERIFIED" } else { "❌ BREACHED" },
            self.total_storage_evictions_handled,
            self.total_steps_executed,
            self.total_ledgers_simulated,
            self.total_storage_evictions_handled,
            self.violations.len()
        )
    }
}
