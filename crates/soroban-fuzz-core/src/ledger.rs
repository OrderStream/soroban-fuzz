use serde::{Deserialize, Serialize};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::Env;

/// Ledger state snapshot containing sequence number, timestamp, network id, and protocol version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    pub sequence_number: u32,
    pub timestamp: u64,
    pub protocol_version: u32,
}

/// Ledger manager hook that synchronizes Soroban host environment ledger with fuzz simulation.
pub struct LedgerAdvancementHook {
    pub sequence_number: u32,
    pub timestamp: u64,
    pub protocol_version: u32,
    pub block_time_seconds: u64,
}

impl Default for LedgerAdvancementHook {
    fn default() -> Self {
        Self {
            sequence_number: 1,
            timestamp: 1_700_000_000,
            protocol_version: 22,
            block_time_seconds: 5,
        }
    }
}

impl LedgerAdvancementHook {
    pub fn new(initial_sequence: u32, initial_timestamp: u64, protocol_version: u32) -> Self {
        Self {
            sequence_number: initial_sequence,
            timestamp: initial_timestamp,
            protocol_version,
            block_time_seconds: 5,
        }
    }

    /// Synchronizes the Soroban SDK Env with the hook's current state via `with_mut`.
    pub fn sync_to_env(&self, env: &Env) {
        let seq = self.sequence_number;
        let ts = self.timestamp;
        let proto = self.protocol_version;
        env.ledger().with_mut(|li| {
            li.sequence_number = seq;
            li.timestamp = ts;
            li.protocol_version = proto;
        });
    }

    /// Advances ledger by a given number of ledgers, updating timestamp and hooking into Soroban Env.
    pub fn advance_ledger(&mut self, env: &Env, delta_ledgers: u32) -> LedgerSnapshot {
        let delta_seq = delta_ledgers.max(1);
        self.sequence_number = self.sequence_number.saturating_add(delta_seq);
        self.timestamp = self
            .timestamp
            .saturating_add((delta_seq as u64) * self.block_time_seconds);

        self.sync_to_env(env);

        LedgerSnapshot {
            sequence_number: self.sequence_number,
            timestamp: self.timestamp,
            protocol_version: self.protocol_version,
        }
    }

    /// Advances ledger by custom ledgers and explicit timestamp delta.
    pub fn advance_custom(
        &mut self,
        env: &Env,
        delta_ledgers: u32,
        delta_seconds: u64,
    ) -> LedgerSnapshot {
        self.sequence_number = self.sequence_number.saturating_add(delta_ledgers);
        self.timestamp = self.timestamp.saturating_add(delta_seconds);

        self.sync_to_env(env);

        LedgerSnapshot {
            sequence_number: self.sequence_number,
            timestamp: self.timestamp,
            protocol_version: self.protocol_version,
        }
    }

    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            sequence_number: self.sequence_number,
            timestamp: self.timestamp,
            protocol_version: self.protocol_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledger_hook_default_and_snapshot() {
        let hook = LedgerAdvancementHook::default();
        let snap = hook.snapshot();
        assert_eq!(snap.sequence_number, 1);
        assert_eq!(snap.timestamp, 1_700_000_000);
        assert_eq!(snap.protocol_version, 22);
    }

    #[test]
    fn test_ledger_advance_zero_defaults_to_one() {
        let env = Env::default();
        let mut hook = LedgerAdvancementHook::default();
        let snap = hook.advance_ledger(&env, 0); // min 1
        assert_eq!(snap.sequence_number, 2);
        assert_eq!(snap.timestamp, 1_700_000_005);
    }
}
