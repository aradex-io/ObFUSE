//! Evasion primitives for defense bypass and anti-analysis.
//!
//! Provides building blocks for evading host-based and network-based
//! security controls, including:
//! - Direct syscall stubs (bypass userland hooks)
//! - AMSI bypass patterns (for .NET payload execution)
//! - ETW bypass patterns (disable telemetry)
//! - Anti-analysis checks (sandbox, debugger, VM detection)
//! - Sleep obfuscation (encrypt payload in memory during sleep)
//! - Process hollowing and module stomping primitives

pub mod syscall;
pub mod amsi;
pub mod anti_analysis;
pub mod sleep;
pub mod masquerade;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EvasionError {
    #[error("evasion technique failed: {0}")]
    Failed(String),
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),
    #[error("anti-analysis check triggered: {0}")]
    Detected(String),
}
