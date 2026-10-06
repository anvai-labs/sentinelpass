//! Compatibility surface for the retired native-autofill prototype.
//!
//! Credential search/delivery is disabled: window titles, entry IDs and a direct
//! vault reference do not establish consent or destination authority. Browser
//! autofill uses the separate daemon/native-host protocol, not this module.

fn native_autofill_unavailable() -> crate::PasswordManagerError {
    crate::PasswordManagerError::NotImplemented(
        "Native autofill is disabled until daemon authorization and destination binding are implemented; use the browser extension".into(),
    )
}

#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(all(target_os = "linux", feature = "x11"))]
pub mod linux;

/// Result of an auto-fill operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoFillResult {
    /// Auto-fill completed successfully
    Success,
    /// No credentials found for the target
    NoCredentials,
    /// User cancelled the operation
    Cancelled,
    /// Auto-fill failed with error
    Failed(String),
}

/// Information about a credential match
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CredentialMatch {
    /// Entry ID
    pub id: String,
    /// Domain/URL that matched
    pub domain: String,
    /// Username
    pub username: String,
    /// Entry title
    pub title: String,
}

/// Context for auto-fill operation (platform-specific)
#[cfg(windows)]
pub use windows::AutoFillContext;

#[cfg(target_os = "macos")]
pub use macos::AutoFillContext;

#[cfg(all(target_os = "linux", feature = "x11"))]
pub use linux::AutoFillContext;

/// Auto-fill manager (platform-specific)
pub struct AutoFillManager {
    _private: (),
}

impl AutoFillManager {
    /// Create a new auto-fill manager
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Get the current auto-fill context (detect active window/domain)
    #[cfg(windows)]
    pub fn get_context(&self) -> Result<AutoFillContext, crate::PasswordManagerError> {
        windows::get_context()
    }

    /// Disabled: a caller-supplied domain/title is not an authorized native target.
    pub async fn find_credentials(
        &self,
        _domain: &str,
        _vault_manager: &crate::vault::VaultManager,
    ) -> Result<Vec<CredentialMatch>, crate::PasswordManagerError> {
        Err(native_autofill_unavailable())
    }

    /// Auto-fill credentials via clipboard
    #[cfg(windows)]
    pub fn autofill_via_clipboard(
        &self,
        credential: &CredentialMatch,
        vault_manager: &crate::vault::VaultManager,
    ) -> Result<AutoFillResult, crate::PasswordManagerError> {
        windows::autofill_via_clipboard(credential, vault_manager)
    }

    /// Auto-fill credentials via direct input simulation
    #[cfg(windows)]
    pub fn autofill_via_input(
        &self,
        credential: &CredentialMatch,
        vault_manager: &crate::vault::VaultManager,
    ) -> Result<AutoFillResult, crate::PasswordManagerError> {
        windows::autofill_via_input(credential, vault_manager)
    }

    /// Register global hotkey for auto-fill
    #[cfg(windows)]
    pub fn register_hotkey(
        &self,
        modifiers: u32,
        vk: u32,
    ) -> Result<(), crate::PasswordManagerError> {
        windows::register_hotkey(modifiers, vk)
    }
}

impl Default for AutoFillManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_os = "linux", feature = "x11"))]
    use super::linux as native;
    #[cfg(target_os = "macos")]
    use super::macos as native;

    #[cfg(any(target_os = "macos", all(target_os = "linux", feature = "x11")))]
    #[tokio::test]
    async fn native_platform_paths_deny_before_vault_or_desktop_access() {
        let vault = unavailable_vault();
        for id in ["1", "not-an-id"] {
            let credential = synthetic_match(id);
            for result in [
                native::autofill_via_clipboard(&credential, &vault).await,
                native::autofill_via_input(&credential, &vault).await,
            ] {
                assert!(matches!(
                    result,
                    Err(crate::PasswordManagerError::NotImplemented(_))
                ));
            }
        }
        assert!(matches!(
            native::get_context(),
            Err(crate::PasswordManagerError::NotImplemented(_))
        ));
        assert!(matches!(
            native::register_hotkey(6, 0x74),
            Err(crate::PasswordManagerError::NotImplemented(_))
        ));
    }

    // No key, schema, audit logger or default config directory. Any accidental
    // vault read would produce a different error, rather than the expected denial.
    pub(super) fn unavailable_vault() -> crate::vault::VaultManager {
        crate::vault::VaultManager {
            key_hierarchy: crate::crypto::KeyHierarchy::new(),
            db: std::sync::Arc::new(std::sync::Mutex::new(
                crate::database::Database::open(":memory:").unwrap(),
            )),
            vault_path: ":memory:".into(),
            audit_logger: None,
            epoch_sidecar: None,
            vault_uuid: None,
            session_epoch: std::sync::atomic::AtomicI64::new(0),
        }
    }

    #[cfg(any(
        windows,
        target_os = "macos",
        all(target_os = "linux", feature = "x11")
    ))]
    pub(super) fn synthetic_match(id: &str) -> CredentialMatch {
        CredentialMatch {
            id: id.into(),
            domain: "example.invalid".into(),
            username: "synthetic".into(),
            title: "synthetic".into(),
        }
    }

    #[tokio::test]
    async fn native_search_never_enumerates_vault_for_title_or_domain() {
        let vault = unavailable_vault();
        for domain in [
            "",
            "example.invalid",
            "https://example.invalid",
            "*",
            "example.invalid - Google Chrome",
        ] {
            assert!(matches!(
                AutoFillManager::new()
                    .find_credentials(domain, &vault)
                    .await,
                Err(crate::PasswordManagerError::NotImplemented(_))
            ));
        }
    }

    #[test]
    fn test_autofill_manager_creation() {
        let _manager = AutoFillManager::new();
        // Test passes if manager creates successfully
    }
}
