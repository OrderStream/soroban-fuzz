use super::{FuzzState, Invariant, InvariantViolation, ViolationSeverity};

/// Solvency invariant ensuring protocol backing assets strictly cover liabilities.
/// In DeFi / lending / vaults, solvency requires total collateral or reserves >= liabilities
/// scaled by the required reserve ratio basis points (e.g. 10_000 = 100% solvency).
#[derive(Debug, Clone)]
pub struct SolvencyInvariant {
    pub min_solvency_ratio_bps: u32,
}

impl Default for SolvencyInvariant {
    fn default() -> Self {
        Self {
            min_solvency_ratio_bps: 10_000, // 100% solvency baseline
        }
    }
}

impl SolvencyInvariant {
    pub fn new(min_solvency_ratio_bps: u32) -> Self {
        Self {
            min_solvency_ratio_bps,
        }
    }
}

impl Invariant for SolvencyInvariant {
    fn name(&self) -> &'static str {
        "SolvencyInvariant"
    }

    fn check(&self, state: &FuzzState) -> Result<(), InvariantViolation> {
        if state.total_assets < 0 {
            return Err(InvariantViolation {
                invariant_name: self.name().to_string(),
                description: "Protocol total assets is negative".to_string(),
                expected: "total_assets >= 0".to_string(),
                actual: format!("total_assets = {}", state.total_assets),
                step: state.step,
                ledger_sequence: state.ledger_sequence,
                severity: ViolationSeverity::Fatal,
            });
        }

        if state.total_liabilities < 0 {
            return Err(InvariantViolation {
                invariant_name: self.name().to_string(),
                description: "Protocol total liabilities is negative".to_string(),
                expected: "total_liabilities >= 0".to_string(),
                actual: format!("total_liabilities = {}", state.total_liabilities),
                step: state.step,
                ledger_sequence: state.ledger_sequence,
                severity: ViolationSeverity::Fatal,
            });
        }

        // If liabilities are 0, system is fully solvent by definition
        if state.total_liabilities == 0 {
            return Ok(());
        }

        // assets * 10_000 >= liabilities * min_solvency_ratio_bps
        let lhs = (state.total_assets as i128)
            .checked_mul(10_000)
            .ok_or_else(|| InvariantViolation {
                invariant_name: self.name().to_string(),
                description: "Arithmetic overflow calculating asset solvency LHS".to_string(),
                expected: "Non-overflowing product".to_string(),
                actual: format!("total_assets={}", state.total_assets),
                step: state.step,
                ledger_sequence: state.ledger_sequence,
                severity: ViolationSeverity::Fatal,
            })?;

        let rhs = (state.total_liabilities as i128)
            .checked_mul(self.min_solvency_ratio_bps as i128)
            .ok_or_else(|| InvariantViolation {
                invariant_name: self.name().to_string(),
                description: "Arithmetic overflow calculating liability solvency RHS".to_string(),
                expected: "Non-overflowing product".to_string(),
                actual: format!("total_liabilities={}", state.total_liabilities),
                step: state.step,
                ledger_sequence: state.ledger_sequence,
                severity: ViolationSeverity::Fatal,
            })?;

        if lhs < rhs {
            let actual_ratio_bps = if state.total_liabilities > 0 {
                ((state.total_assets as f64 / state.total_liabilities as f64) * 10000.0) as i64
            } else {
                0
            };

            return Err(InvariantViolation {
                invariant_name: self.name().to_string(),
                description: format!(
                    "Insolvency detected: assets ({}) fail to cover liabilities ({}) at required ratio {} bps",
                    state.total_assets, state.total_liabilities, self.min_solvency_ratio_bps
                ),
                expected: format!("solvency_ratio_bps >= {}", self.min_solvency_ratio_bps),
                actual: format!("solvency_ratio_bps = {}", actual_ratio_bps),
                step: state.step,
                ledger_sequence: state.ledger_sequence,
                severity: ViolationSeverity::Fatal,
            });
        }

        Ok(())
    }
}
