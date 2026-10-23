use super::{FuzzState, Invariant, InvariantViolation, ViolationSeverity};

/// Replay protection invariant ensuring that account nonces increase monotonically.
/// Replaying an old nonce or decrementing nonce state signals critical replay vulnerability
/// or authorization desynchronization.
#[derive(Debug, Clone)]
pub struct ReplayNonceMonotonicityInvariant {
    pub strict_sequential: bool,
}

impl Default for ReplayNonceMonotonicityInvariant {
    fn default() -> Self {
        Self {
            strict_sequential: true, // Requires exact nonce + 1 progression
        }
    }
}

impl ReplayNonceMonotonicityInvariant {
    pub fn new(strict_sequential: bool) -> Self {
        Self { strict_sequential }
    }
}

impl Invariant for ReplayNonceMonotonicityInvariant {
    fn name(&self) -> &'static str {
        "ReplayNonceMonotonicityInvariant"
    }

    fn check(&self, state: &FuzzState) -> Result<(), InvariantViolation> {
        for (address, history) in &state.nonce_history {
            if history.len() <= 1 {
                continue;
            }

            for window in history.windows(2) {
                let prev = window[0];
                let curr = window[1];

                if curr <= prev {
                    return Err(InvariantViolation {
                        invariant_name: self.name().to_string(),
                        description: format!(
                            "Replay / Nonce regression detected for '{}': nonce jumped from {} to {}",
                            address, prev, curr
                        ),
                        expected: format!("next_nonce > {}", prev),
                        actual: format!("next_nonce = {}", curr),
                        step: state.step,
                        ledger_sequence: state.ledger_sequence,
                        severity: ViolationSeverity::Fatal,
                    });
                }

                if self.strict_sequential && curr != prev + 1 {
                    return Err(InvariantViolation {
                        invariant_name: self.name().to_string(),
                        description: format!(
                            "Nonce gap detected for '{}': expected exact increment from {} to {}, got {}",
                            address,
                            prev,
                            prev + 1,
                            curr
                        ),
                        expected: format!("next_nonce == {}", prev + 1),
                        actual: format!("next_nonce = {}", curr),
                        step: state.step,
                        ledger_sequence: state.ledger_sequence,
                        severity: ViolationSeverity::High,
                    });
                }
            }
        }

        Ok(())
    }
}
