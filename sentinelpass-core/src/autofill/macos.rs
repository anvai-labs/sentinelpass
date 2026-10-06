//! Disabled compatibility surface for the unshipped native-autofill prototype.
//! Browser autofill uses the daemon/native-host protocol instead.

#![forbid(unsafe_code)]

use super::{native_autofill_unavailable, AutoFillResult, CredentialMatch};
use crate::Result;

/// Retained for source compatibility; never establishes a verified origin.
pub struct AutoFillContext {
    pub window_title: String,
    pub bundle_id: String,
    pub domain: Option<String>,
    pub pid: i32,
}

/// Disabled: native app/field binding and authorization are not implemented.
pub fn get_context() -> Result<AutoFillContext> {
    Err(native_autofill_unavailable())
}

/// Disabled before any credential read or clipboard access.
pub async fn autofill_via_clipboard(
    _credential: &CredentialMatch,
    _vault_manager: &crate::vault::VaultManager,
) -> Result<AutoFillResult> {
    Err(native_autofill_unavailable())
}

/// Disabled before any credential read or input injection.
pub async fn autofill_via_input(
    _credential: &CredentialMatch,
    _vault_manager: &crate::vault::VaultManager,
) -> Result<AutoFillResult> {
    Err(native_autofill_unavailable())
}

/// Disabled with the legacy native credential-delivery path.
pub fn register_hotkey(_modifiers: u32, _vk: u32) -> Result<()> {
    Err(native_autofill_unavailable())
}
