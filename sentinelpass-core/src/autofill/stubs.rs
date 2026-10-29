//! Shared stub implementations for disabled native autofill platforms.
//!
//! Linux and macOS both have native autofill disabled (returning
//! `native_autofill_unavailable()`). This module provides the common
//! function implementations to eliminate duplication between platform modules.

use super::{native_autofill_unavailable, AutoFillContext, AutoFillResult, CredentialMatch};
use crate::vault::VaultManager;

/// Disabled: native app/field binding and authorization are not implemented.
pub fn get_context() -> Result<AutoFillContext, crate::PasswordManagerError> {
    Err(native_autofill_unavailable())
}

/// Disabled before any credential read or clipboard access.
pub async fn autofill_via_clipboard(
    _credential: &CredentialMatch,
    _vault_manager: &VaultManager,
) -> Result<AutoFillResult, crate::PasswordManagerError> {
    Err(native_autofill_unavailable())
}

/// Disabled before any credential read or input injection.
pub async fn autofill_via_input(
    _credential: &CredentialMatch,
    _vault_manager: &VaultManager,
) -> Result<AutoFillResult, crate::PasswordManagerError> {
    Err(native_autofill_unavailable())
}

/// Disabled with the legacy native credential-delivery path.
pub fn register_hotkey(_modifiers: u32, _vk: u32) -> Result<(), crate::PasswordManagerError> {
    Err(native_autofill_unavailable())
}
