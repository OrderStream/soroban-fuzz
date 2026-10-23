//! Storage TTL Eviction Boundary and Lifecycle Stress Tester.

use serde::{Deserialize, Serialize};
use soroban_fuzz_core::{EvictionEvent, StorageTtlManager, StorageType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlBoundaryReport {
    pub total_keys_tested: usize,
    pub temporary_evictions: usize,
    pub instance_evictions: usize,
    pub persistent_evictions: usize,
    pub restored_persistent_keys: usize,
    pub simulated_ledgers: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub eviction_log: Vec<EvictionEvent>,
    pub status: String,
}

pub struct TtlBoundaryTester {
    manager: StorageTtlManager,
}

impl TtlBoundaryTester {
    pub fn new(min_ttl: u32, max_ttl: u32) -> Self {
        Self {
            manager: StorageTtlManager::new(min_ttl, max_ttl),
        }
    }

    /// Runs a deterministic TTL boundary test simulating ledgers advancing and testing
    /// proper eviction and restoration behaviors.
    pub fn run_boundary_campaign(&mut self, total_ledgers: u32, keys_per_type: usize) -> TtlBoundaryReport {
        let mut eviction_log = Vec::new();
        let mut current_ledger = 100u32;

        // 1. Seed keys across Temporary, Instance, and Persistent storages with varied TTLs
        for i in 0..keys_per_type {
            let ttl_offset = (i % 10) as u32 + 2;
            let key = format!("key_{}", i);

            // Temporary entry
            let _ = self.manager.put(
                StorageType::Temporary,
                &format!("temp_{}", key),
                vec![i as u8],
                current_ledger,
                Some(ttl_offset),
            );

            // Instance entry
            let _ = self.manager.put(
                StorageType::Instance,
                &format!("inst_{}", key),
                vec![i as u8],
                current_ledger,
                Some(ttl_offset + 5),
            );

            // Persistent entry
            let _ = self.manager.put(
                StorageType::Persistent,
                &format!("pers_{}", key),
                vec![i as u8],
                current_ledger,
                Some(ttl_offset + 10),
            );
        }

        let mut restored_count = 0;

        // 2. Advance ledgers step by step
        for step in 0..total_ledgers {
            current_ledger += 1;
            let evictions = self.manager.advance_and_evict(current_ledger);
            for ev in &evictions {
                eviction_log.push(ev.clone());
            }

            // Test restoration of some expired persistent keys halfway through
            if step == total_ledgers / 2 {
                for i in 0..(keys_per_type / 2) {
                    let k = format!("pers_key_{}", i);
                    if self.manager.restore_persistent(&k, current_ledger, 50).is_ok() {
                        restored_count += 1;
                    }
                }
            }
        }

        let mut temp_count = 0;
        let mut inst_count = 0;
        let mut pers_count = 0;

        for ev in &eviction_log {
            match ev.storage_type {
                StorageType::Temporary => temp_count += 1,
                StorageType::Instance => inst_count += 1,
                StorageType::Persistent => pers_count += 1,
            }
        }

        TtlBoundaryReport {
            total_keys_tested: keys_per_type * 3,
            temporary_evictions: temp_count,
            instance_evictions: inst_count,
            persistent_evictions: pers_count,
            restored_persistent_keys: restored_count,
            simulated_ledgers: total_ledgers,
            min_ttl: self.manager.min_persistent_ttl,
            max_ttl: self.manager.max_entry_ttl,
            eviction_log,
            status: "BOUNDARY_ANALYSIS_COMPLETED".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_boundary_campaign() {
        let mut tester = TtlBoundaryTester::new(1, 100);
        let report = tester.run_boundary_campaign(30, 5);

        assert_eq!(report.total_keys_tested, 15);
        assert!(report.temporary_evictions > 0);
        assert_eq!(report.status, "BOUNDARY_ANALYSIS_COMPLETED");
    }
}
