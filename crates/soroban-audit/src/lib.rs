//! Unified Soroban Security Audit and Invariant Verification Engine.
//!
//! Provides WASM contract bytecode hooking, fuzz campaign orchestration via `soroban-fuzz-core`,
//! storage TTL eviction boundary testing, and SHA-256 tamper-evident security certificate generation.

pub mod wasm_hook;
pub mod audit_engine;
pub mod ttl_tester;

pub use audit_engine::{AuditConfig, AuditEngine, AuditExecutionSummary};
pub use wasm_hook::{WasmBytecodeInfo, WasmHook};
pub use ttl_tester::{TtlBoundaryReport, TtlBoundaryTester};
