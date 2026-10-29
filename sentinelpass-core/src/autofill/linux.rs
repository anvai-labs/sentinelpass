//! Linux native autofill stub (disabled).
//!
//! Native autofill is disabled on Linux. This module provides the platform-specific
//! `AutoFillContext` struct and re-exports the shared stub implementations.

/// Context for auto-fill operation (Linux-specific).
#[derive(Debug, Clone)]
pub struct AutoFillContext {
    /// Window title
    pub window_title: String,
    /// Window class
    pub window_class: String,
    /// Domain
    pub domain: Option<String>,
    /// Window ID
    pub window_id: u64,
}

// Re-export shared stub implementations
pub use super::stubs::*;
