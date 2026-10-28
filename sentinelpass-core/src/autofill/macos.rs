//! macOS native autofill stub (disabled).
//!
//! Native autofill is disabled on macOS. This module provides the platform-specific
//! `AutoFillContext` struct and re-exports the shared stub implementations.

/// Context for auto-fill operation (macOS-specific).
#[derive(Debug, Clone)]
pub struct AutoFillContext {
    /// Window title
    pub window_title: String,
    /// Bundle ID
    pub bundle_id: String,
    /// Domain
    pub domain: Option<String>,
    /// Process ID
    pub pid: i32,
}

// Re-export shared stub implementations
pub use super::stubs::*;
