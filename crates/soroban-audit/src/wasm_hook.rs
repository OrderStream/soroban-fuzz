//! WASM bytecode analyzer and inspection hook for Soroban contracts.

use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WasmBytecodeInfo {
    pub sha256_hash: String,
    pub bytecode_size_bytes: usize,
    pub has_soroban_spec: bool,
    pub has_soroban_meta: bool,
    pub exported_functions: Vec<String>,
    pub custom_sections: HashMap<String, usize>,
    pub total_sections: usize,
}

pub struct WasmHook;

impl WasmHook {
    /// Inspects raw WASM bytes or loads mock bytecode if minimal format.
    pub fn inspect(bytes: &[u8]) -> Result<WasmBytecodeInfo, String> {
        if bytes.len() < 8 {
            return Err("Bytecode too small to be a valid WebAssembly module".into());
        }

        // Check magic bytes \0asm
        if &bytes[0..4] != b"\0asm" {
            return Err("Invalid WebAssembly magic number; expected \\0asm".into());
        }

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let sha256_hash = format!("{:x}", hasher.finalize());

        let mut pos = 8; // skip magic (4) and version (4)
        let mut custom_sections = HashMap::new();
        let mut exported_functions = Vec::new();
        let mut total_sections = 0;

        while pos < bytes.len() {
            let section_id = bytes[pos];
            pos += 1;
            if pos >= bytes.len() {
                break;
            }

            let (section_len, bytes_read) = Self::read_varuint32(&bytes[pos..])
                .map_err(|e| format!("Failed to read section length at byte {}: {}", pos, e))?;
            pos += bytes_read;

            let section_end = pos + section_len as usize;
            if section_end > bytes.len() {
                return Err("Truncated WASM section detected".into());
            }

            total_sections += 1;

            if section_id == 0 {
                // Custom section
                if let Ok((name_len, name_bytes_read)) = Self::read_varuint32(&bytes[pos..section_end]) {
                    let name_start = pos + name_bytes_read;
                    let name_end = name_start + name_len as usize;
                    if name_end <= section_end {
                        if let Ok(name) = std::str::from_utf8(&bytes[name_start..name_end]) {
                            custom_sections.insert(name.to_string(), section_len as usize);
                        }
                    }
                }
            } else if section_id == 7 {
                // Export section
                let _ = Self::parse_exports(&bytes[pos..section_end], &mut exported_functions);
            }

            pos = section_end;
        }

        let has_soroban_spec = custom_sections.contains_key("contractspecv0");
        let has_soroban_meta = custom_sections.contains_key("contractenvmetav0");

        Ok(WasmBytecodeInfo {
            sha256_hash,
            bytecode_size_bytes: bytes.len(),
            has_soroban_spec,
            has_soroban_meta,
            exported_functions,
            custom_sections,
            total_sections,
        })
    }

    fn read_varuint32(bytes: &[u8]) -> Result<(u32, usize), &'static str> {
        let mut result = 0u32;
        let mut shift = 0;
        let mut count = 0;

        for &byte in bytes {
            count += 1;
            if shift >= 32 {
                return Err("LEB128 integer overflow");
            }
            result |= ((byte & 0x7F) as u32) << shift;
            if (byte & 0x80) == 0 {
                return Ok((result, count));
            }
            shift += 7;
        }
        Err("Unexpected end of LEB128 input")
    }

    fn parse_exports(bytes: &[u8], exports: &mut Vec<String>) -> Result<(), &'static str> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut pos = 0;
        let (count, read) = Self::read_varuint32(&bytes[pos..])?;
        pos += read;

        for _ in 0..count {
            if pos >= bytes.len() {
                break;
            }
            let (str_len, read) = Self::read_varuint32(&bytes[pos..])?;
            pos += read;
            let end = pos + str_len as usize;
            if end > bytes.len() {
                break;
            }
            if let Ok(export_name) = std::str::from_utf8(&bytes[pos..end]) {
                exports.push(export_name.to_string());
            }
            pos = end;
            // kind (1 byte) + index (LEB128)
            if pos < bytes.len() {
                pos += 1;
                if let Ok((_, idx_read)) = Self::read_varuint32(&bytes[pos..]) {
                    pos += idx_read;
                }
            }
        }
        Ok(())
    }

    /// Creates a minimal valid WASM binary with a custom `contractspecv0` section for testing.
    pub fn create_mock_soroban_wasm(contract_name: &str, exports: &[&str]) -> Vec<u8> {
        let mut wasm = Vec::new();
        // Magic + version
        wasm.extend_from_slice(b"\0asm");
        wasm.extend_from_slice(&[1, 0, 0, 0]);

        // Custom section for contractspecv0
        let spec_name = b"contractspecv0";
        let mut spec_payload = Vec::new();
        spec_payload.push(spec_name.len() as u8);
        spec_payload.extend_from_slice(spec_name);
        spec_payload.extend_from_slice(contract_name.as_bytes());

        wasm.push(0); // custom section id
        wasm.push(spec_payload.len() as u8);
        wasm.extend_from_slice(&spec_payload);

        // Export section id = 7
        let mut export_payload = Vec::new();
        export_payload.push(exports.len() as u8);
        for (idx, exp) in exports.iter().enumerate() {
            export_payload.push(exp.len() as u8);
            export_payload.extend_from_slice(exp.as_bytes());
            export_payload.push(0); // func export
            export_payload.push(idx as u8);
        }
        wasm.push(7);
        wasm.push(export_payload.len() as u8);
        wasm.extend_from_slice(&export_payload);

        wasm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_mock_wasm() {
        let mock_wasm = WasmHook::create_mock_soroban_wasm("LiquidityPool", &["deposit", "withdraw", "swap"]);
        let info = WasmHook::inspect(&mock_wasm).expect("inspection should succeed");

        assert!(info.has_soroban_spec);
        assert!(!info.has_soroban_meta);
        assert_eq!(info.exported_functions, vec!["deposit", "withdraw", "swap"]);
        assert_eq!(info.sha256_hash.len(), 64);
        assert_eq!(info.total_sections, 2);
    }

    #[test]
    fn test_invalid_magic() {
        let bad_bytes = vec![0, 1, 2, 3, 4, 5, 6, 7];
        assert!(WasmHook::inspect(&bad_bytes).is_err());
    }
}
