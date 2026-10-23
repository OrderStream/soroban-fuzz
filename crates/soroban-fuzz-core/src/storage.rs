use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Category of Soroban storage entry according to Stellar Soroban architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageType {
    /// Temporary storage: automatically evicted when expired; permanently lost.
    Temporary,
    /// Instance storage: tied to the contract instance; expired entries disable contract execution.
    Instance,
    /// Persistent storage: archived when expired; cannot be accessed without restoration.
    Persistent,
}

impl std::fmt::Display for StorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageType::Temporary => write!(f, "temporary"),
            StorageType::Instance => write!(f, "instance"),
            StorageType::Persistent => write!(f, "persistent"),
        }
    }
}

/// Metadata and value of a storage entry in the host storage model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageEntry {
    pub key: String,
    pub val: Vec<u8>,
    pub storage_type: StorageType,
    pub created_at_ledger: u32,
    pub live_until_ledger: u32,
    pub is_archived: bool,
}

impl StorageEntry {
    /// Checks if entry is expired given current ledger sequence.
    pub fn is_expired(&self, current_ledger: u32) -> bool {
        current_ledger > self.live_until_ledger
    }

    /// Remaining TTL in ledgers from the current ledger.
    pub fn remaining_ttl(&self, current_ledger: u32) -> u32 {
        self.live_until_ledger.saturating_sub(current_ledger)
    }
}

/// Errors occurring during storage operations and TTL boundary checks.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum StorageError {
    #[error("Key '{key}' not found in {storage_type} storage")]
    NotFound {
        key: String,
        storage_type: StorageType,
    },

    #[error("Key '{key}' in {storage_type} storage was permanently evicted at ledger {evicted_at_ledger} (current: {current_ledger})")]
    Evicted {
        key: String,
        storage_type: StorageType,
        evicted_at_ledger: u32,
        current_ledger: u32,
    },

    #[error("Key '{key}' in {storage_type} storage is expired/archived at ledger {live_until} (current: {current_ledger}), restore required")]
    Expired {
        key: String,
        storage_type: StorageType,
        live_until: u32,
        current_ledger: u32,
    },

    #[error("Invalid TTL extension: requested {requested_ttl}, must be within [{min_ttl}, {max_ttl}]")]
    InvalidTtl {
        requested_ttl: u32,
        min_ttl: u32,
        max_ttl: u32,
    },
}

/// Record of an eviction event during ledger simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictionEvent {
    pub key: String,
    pub storage_type: StorageType,
    pub live_until_ledger: u32,
    pub evicted_at_ledger: u32,
    pub permanently_deleted: bool,
}

/// Storage TTL manager simulating Soroban storage rent, boundaries, and eviction lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageTtlManager {
    entries: HashMap<String, StorageEntry>,
    eviction_history: Vec<EvictionEvent>,
    pub min_persistent_ttl: u32,
    pub max_entry_ttl: u32,
    pub default_temp_ttl: u32,
    pub default_persistent_ttl: u32,
}

impl Default for StorageTtlManager {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            eviction_history: Vec::new(),
            min_persistent_ttl: 16,
            max_entry_ttl: 3_110_400, // ~6 months at 5s/ledger
            default_temp_ttl: 100,
            default_persistent_ttl: 50_000,
        }
    }
}

impl StorageTtlManager {
    pub fn new(min_persistent_ttl: u32, max_entry_ttl: u32) -> Self {
        Self {
            entries: HashMap::new(),
            eviction_history: Vec::new(),
            min_persistent_ttl,
            max_entry_ttl,
            default_temp_ttl: 100,
            default_persistent_ttl: 50_000,
        }
    }

    fn composite_key(storage_type: StorageType, key: &str) -> String {
        format!("{}:{}", storage_type, key)
    }

    /// Sets or updates an entry in storage.
    pub fn put(
        &mut self,
        storage_type: StorageType,
        key: &str,
        val: Vec<u8>,
        current_ledger: u32,
        ttl_ledgers: Option<u32>,
    ) -> Result<StorageEntry, StorageError> {
        let ttl = ttl_ledgers.unwrap_or(match storage_type {
            StorageType::Temporary => self.default_temp_ttl,
            StorageType::Instance | StorageType::Persistent => self.default_persistent_ttl,
        });

        if ttl > self.max_entry_ttl {
            return Err(StorageError::InvalidTtl {
                requested_ttl: ttl,
                min_ttl: self.min_persistent_ttl,
                max_ttl: self.max_entry_ttl,
            });
        }

        let live_until = current_ledger.saturating_add(ttl);
        let entry = StorageEntry {
            key: key.to_string(),
            val,
            storage_type,
            created_at_ledger: current_ledger,
            live_until_ledger: live_until,
            is_archived: false,
        };

        let ck = Self::composite_key(storage_type, key);
        self.entries.insert(ck, entry.clone());
        Ok(entry)
    }

    /// Retrieves an entry, verifying TTL expiration and eviction boundaries.
    pub fn get(
        &self,
        storage_type: StorageType,
        key: &str,
        current_ledger: u32,
    ) -> Result<&StorageEntry, StorageError> {
        let ck = Self::composite_key(storage_type, key);
        let entry = self.entries.get(&ck).ok_or_else(|| StorageError::NotFound {
            key: key.to_string(),
            storage_type,
        })?;

        if entry.is_expired(current_ledger) {
            match storage_type {
                StorageType::Temporary => Err(StorageError::Evicted {
                    key: key.to_string(),
                    storage_type,
                    evicted_at_ledger: entry.live_until_ledger,
                    current_ledger,
                }),
                StorageType::Instance | StorageType::Persistent => Err(StorageError::Expired {
                    key: key.to_string(),
                    storage_type,
                    live_until: entry.live_until_ledger,
                    current_ledger,
                }),
            }
        } else {
            Ok(entry)
        }
    }

    /// Extends the TTL of an active or restorable entry.
    pub fn extend_ttl(
        &mut self,
        storage_type: StorageType,
        key: &str,
        current_ledger: u32,
        extend_by_ledgers: u32,
    ) -> Result<u32, StorageError> {
        let ck = Self::composite_key(storage_type, key);
        let entry = self.entries.get_mut(&ck).ok_or_else(|| StorageError::NotFound {
            key: key.to_string(),
            storage_type,
        })?;

        if extend_by_ledgers > self.max_entry_ttl {
            return Err(StorageError::InvalidTtl {
                requested_ttl: extend_by_ledgers,
                min_ttl: self.min_persistent_ttl,
                max_ttl: self.max_entry_ttl,
            });
        }

        // Temporary storage cannot be restored if already expired (evicted)
        if storage_type == StorageType::Temporary && entry.is_expired(current_ledger) {
            return Err(StorageError::Evicted {
                key: key.to_string(),
                storage_type,
                evicted_at_ledger: entry.live_until_ledger,
                current_ledger,
            });
        }

        // Persistent storage cannot be extended if already expired/archived; it must be restored
        if storage_type == StorageType::Persistent && (entry.is_expired(current_ledger) || entry.is_archived) {
            return Err(StorageError::Expired {
                key: key.to_string(),
                storage_type,
                live_until: entry.live_until_ledger,
                current_ledger,
            });
        }

        let new_live_until = current_ledger.saturating_add(extend_by_ledgers);
        if new_live_until > entry.live_until_ledger {
            entry.live_until_ledger = new_live_until;
            entry.is_archived = false;
        }

        Ok(entry.live_until_ledger)
    }

    /// Restores an archived persistent entry.
    pub fn restore_persistent(
        &mut self,
        key: &str,
        current_ledger: u32,
        restore_ttl: u32,
    ) -> Result<u32, StorageError> {
        let ck = Self::composite_key(StorageType::Persistent, key);
        let entry = self
            .entries
            .get_mut(&ck)
            .ok_or_else(|| StorageError::NotFound {
                key: key.to_string(),
                storage_type: StorageType::Persistent,
            })?;

        if restore_ttl < self.min_persistent_ttl || restore_ttl > self.max_entry_ttl {
            return Err(StorageError::InvalidTtl {
                requested_ttl: restore_ttl,
                min_ttl: self.min_persistent_ttl,
                max_ttl: self.max_entry_ttl,
            });
        }

        entry.live_until_ledger = current_ledger.saturating_add(restore_ttl);
        entry.is_archived = false;
        Ok(entry.live_until_ledger)
    }

    /// Advances ledger sequence and executes automated eviction for expired temporary entries.
    /// Persistent & Instance entries transition to archived state.
    pub fn advance_and_evict(&mut self, current_ledger: u32) -> Vec<EvictionEvent> {
        let mut new_evictions = Vec::new();
        let mut keys_to_remove = Vec::new();

        for (composite_key, entry) in self.entries.iter_mut() {
            if entry.is_expired(current_ledger) {
                match entry.storage_type {
                    StorageType::Temporary => {
                        new_evictions.push(EvictionEvent {
                            key: entry.key.clone(),
                            storage_type: StorageType::Temporary,
                            live_until_ledger: entry.live_until_ledger,
                            evicted_at_ledger: current_ledger,
                            permanently_deleted: true,
                        });
                        keys_to_remove.push(composite_key.clone());
                    }
                    StorageType::Instance | StorageType::Persistent => {
                        if !entry.is_archived {
                            entry.is_archived = true;
                            new_evictions.push(EvictionEvent {
                                key: entry.key.clone(),
                                storage_type: entry.storage_type,
                                live_until_ledger: entry.live_until_ledger,
                                evicted_at_ledger: current_ledger,
                                permanently_deleted: false,
                            });
                        }
                    }
                }
            }
        }

        for ck in keys_to_remove {
            self.entries.remove(&ck);
        }

        // Guarantee deterministic order across runs
        new_evictions.sort_by(|a, b| {
            a.live_until_ledger
                .cmp(&b.live_until_ledger)
                .then_with(|| a.key.cmp(&b.key))
        });

        self.eviction_history.extend(new_evictions.clone());
        new_evictions
    }

    pub fn eviction_history(&self) -> &[EvictionEvent] {
        &self.eviction_history
    }

    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_type_display() {
        assert_eq!(StorageType::Temporary.to_string(), "temporary");
        assert_eq!(StorageType::Instance.to_string(), "instance");
        assert_eq!(StorageType::Persistent.to_string(), "persistent");
    }

    #[test]
    fn test_invalid_ttl_exceeded() {
        let mut mgr = StorageTtlManager::default();
        let err = mgr
            .put(
                StorageType::Persistent,
                "key1",
                b"val1".to_vec(),
                1,
                Some(mgr.max_entry_ttl + 1),
            )
            .expect_err("Should fail when TTL exceeds max");
        assert!(matches!(err, StorageError::InvalidTtl { .. }));
    }

    #[test]
    fn test_restore_persistent_bounds() {
        let mut mgr = StorageTtlManager::default();
        mgr.put(
            StorageType::Persistent,
            "key1",
            b"val1".to_vec(),
            1,
            Some(20),
        )
        .unwrap();

        // Restore below min_persistent_ttl
        let err_min = mgr
            .restore_persistent("key1", 25, mgr.min_persistent_ttl - 1)
            .expect_err("Should fail when restore TTL < min");
        assert!(matches!(err_min, StorageError::InvalidTtl { .. }));

        // Restore above max_entry_ttl
        let err_max = mgr
            .restore_persistent("key1", 25, mgr.max_entry_ttl + 1)
            .expect_err("Should fail when restore TTL > max");
        assert!(matches!(err_max, StorageError::InvalidTtl { .. }));
    }

    #[test]
    fn test_composite_key_collision_avoidance() {
        let mut mgr = StorageTtlManager::default();
        mgr.put(StorageType::Temporary, "balance", b"100".to_vec(), 1, Some(10))
            .unwrap();
        mgr.put(StorageType::Persistent, "balance", b"200".to_vec(), 1, Some(50))
            .unwrap();

        assert_eq!(mgr.total_entries(), 2);
        assert_eq!(
            mgr.get(StorageType::Temporary, "balance", 1).unwrap().val,
            b"100"
        );
        assert_eq!(
            mgr.get(StorageType::Persistent, "balance", 1).unwrap().val,
            b"200"
        );
    }
}
