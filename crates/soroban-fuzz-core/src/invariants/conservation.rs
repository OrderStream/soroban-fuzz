use super::{FuzzState, Invariant, InvariantViolation, ViolationSeverity};

/// Invariant ensuring total token supply is strictly conserved.
/// Any minting must increase supply or reserves, any burn must deduct from supply,
/// and transfers cannot leak or inflate value.
/// Equation: sum(user_balances) + protocol_reserves + total_burned == initial_supply + total_minted.
#[derive(Debug, Clone, Default)]
pub struct TotalSupplyConservationInvariant;

impl TotalSupplyConservationInvariant {
    pub fn new() -> Self {
        Self
    }
}

impl Invariant for TotalSupplyConservationInvariant {
    fn name(&self) -> &'static str {
        "TotalSupplyConservationInvariant"
    }

    fn check(&self, state: &FuzzState) -> Result<(), InvariantViolation> {
        // Individual balances must not be negative
        for (user, &bal) in &state.user_balances {
            if bal < 0 {
                return Err(InvariantViolation {
                    invariant_name: self.name().to_string(),
                    description: format!("User '{}' has negative balance: {}", user, bal),
                    expected: "balance >= 0".to_string(),
                    actual: format!("balance = {}", bal),
                    step: state.step,
                    ledger_sequence: state.ledger_sequence,
                    severity: ViolationSeverity::Fatal,
                });
            }
        }

        if state.protocol_reserves < 0 {
            return Err(InvariantViolation {
                invariant_name: self.name().to_string(),
                description: "Protocol reserves are negative".to_string(),
                expected: "protocol_reserves >= 0".to_string(),
                actual: format!("protocol_reserves = {}", state.protocol_reserves),
                step: state.step,
                ledger_sequence: state.ledger_sequence,
                severity: ViolationSeverity::Fatal,
            });
        }

        let total_circulating = state.sum_user_balances();
        let total_held = total_circulating
            .checked_add(state.protocol_reserves)
            .and_then(|sum| sum.checked_add(state.total_burned))
            .ok_or_else(|| InvariantViolation {
                invariant_name: self.name().to_string(),
                description: "Overflow calculating total held tokens".to_string(),
                expected: "Non-overflowing sum".to_string(),
                actual: "Overflow".to_string(),
                step: state.step,
                ledger_sequence: state.ledger_sequence,
                severity: ViolationSeverity::Fatal,
            })?;

        let expected_total = state
            .initial_supply
            .checked_add(state.total_minted)
            .ok_or_else(|| InvariantViolation {
                invariant_name: self.name().to_string(),
                description: "Overflow calculating expected total supply".to_string(),
                expected: "Non-overflowing sum".to_string(),
                actual: "Overflow".to_string(),
                step: state.step,
                ledger_sequence: state.ledger_sequence,
                severity: ViolationSeverity::Fatal,
            })?;

        if total_held != expected_total {
            let diff = total_held - expected_total;
            return Err(InvariantViolation {
                invariant_name: self.name().to_string(),
                description: format!(
                    "Supply conservation violation: circulating ({}) + reserves ({}) + burned ({}) = {}, but expected (initial {} + minted {}) = {} (delta: {})",
                    total_circulating,
                    state.protocol_reserves,
                    state.total_burned,
                    total_held,
                    state.initial_supply,
                    state.total_minted,
                    expected_total,
                    diff
                ),
                expected: format!("total_held == {}", expected_total),
                actual: format!("total_held == {}", total_held),
                step: state.step,
                ledger_sequence: state.ledger_sequence,
                severity: ViolationSeverity::Fatal,
            });
        }

        Ok(())
    }
}
