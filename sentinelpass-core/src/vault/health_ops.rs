//! Password health analysis methods for VaultManager.

use crate::{PasswordManagerError, Result};

use super::VaultManager;

impl VaultManager {
    /// Get a summary of password health for all vault entries.
    pub fn get_vault_health_summary(&self) -> Result<crate::crypto::health::VaultHealthSummary> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }
        crate::crypto::health::PasswordHealthAnalyzer::analyze_vault(self)
    }

    /// Get a detailed health report for every vault entry.
    pub fn get_password_health_report(&self) -> Result<Vec<crate::crypto::health::PasswordHealth>> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }
        crate::crypto::health::PasswordHealthAnalyzer::get_health_report(self)
    }
}
