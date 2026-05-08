//! Biometric authentication operations for VaultManager

use super::VaultManager;
use crate::{
    audit::{get_audit_log_dir, AuditEventType, AuditLogger},
    crypto::KeyHierarchy,
    database::Database,
    DatabaseError, PasswordManagerError, Result,
};
use std::path::Path;
use std::sync::{Arc, Mutex};

impl VaultManager {
    /// Open an existing vault using biometric authentication and OS key storage.
    pub fn open_with_biometric<P: AsRef<Path>>(path: P, reason: &str) -> Result<Self> {
        let vault_path = path.as_ref().to_path_buf();
        let db = Database::open(&vault_path)?;
        db.validate_schema_version()?;

        let biometric_ref = Self::load_biometric_ref(&db)?.ok_or_else(|| {
            PasswordManagerError::NotFound("Biometric unlock configuration".to_string())
        })?;

        let mut key_hierarchy = KeyHierarchy::new();
        let dek = crate::biometric::BiometricManager::authenticate_and_load_vault_dek(
            &biometric_ref,
            reason,
        )?;
        key_hierarchy.unlock_vault_with_dek(dek);

        Self::clear_failed_attempts(&db)?;

        let audit_logger = AuditLogger::new(get_audit_log_dir()).map(Arc::new).ok();

        let vault_manager = Self {
            key_hierarchy,
            db: Arc::new(Mutex::new(db)),
            vault_path,
            audit_logger,
        };

        if let Some(ref logger) = vault_manager.audit_logger {
            let _ = logger.log(
                AuditEventType::VaultUnlocked { success: true },
                "Vault unlocked via biometric authentication",
            );
        }

        Ok(vault_manager)
    }

    /// Perform biometric authentication and retrieve the stored vault DEK.
    ///
    /// This is intended for scenarios where a caller needs local key material
    /// after platform authentication without persisting or exposing the master
    /// password.
    pub fn retrieve_dek_via_biometric<P: AsRef<Path>>(
        path: P,
        reason: &str,
    ) -> Result<crate::crypto::DataEncryptionKey> {
        let vault_path = path.as_ref().to_path_buf();
        let db = Database::open(&vault_path)?;

        let biometric_ref = Self::load_biometric_ref(&db)?.ok_or_else(|| {
            PasswordManagerError::NotFound("Biometric unlock configuration".to_string())
        })?;

        crate::biometric::BiometricManager::authenticate_and_load_vault_dek(&biometric_ref, reason)
    }

    /// Check whether biometric unlock is configured for a vault path.
    pub fn is_biometric_unlock_enabled<P: AsRef<Path>>(path: P) -> Result<bool> {
        let db = Database::open(path)?;
        Ok(Self::load_biometric_ref(&db)?.is_some())
    }

    /// Enable biometric unlock for this vault.
    ///
    /// This validates the provided master password, then stores the vault DEK
    /// in OS key storage and links it via `biometric_ref` metadata.
    pub fn enable_biometric_unlock(&self, master_password: &[u8]) -> Result<()> {
        if master_password.is_empty() {
            return Err(PasswordManagerError::InvalidInput(
                "Master password cannot be empty".to_string(),
            ));
        }

        if !crate::biometric::BiometricManager::is_available() {
            return Err(PasswordManagerError::NotFound(format!(
                "{} is not available on this system",
                crate::biometric::BiometricManager::get_method_name()
            )));
        }

        if !crate::biometric::BiometricManager::is_enrolled() {
            return Err(PasswordManagerError::NotFound(format!(
                "{} is not enrolled on this system",
                crate::biometric::BiometricManager::get_method_name()
            )));
        }

        let db = self.db.lock().map_err(|_| {
            PasswordManagerError::from(DatabaseError::LockPoisoned(
                "Failed to lock database".to_string(),
            ))
        })?;

        // Validate that the provided master password can actually unlock this vault.
        let (kdf_params, wrapped_dek) = Self::load_vault_metadata(&db)?;
        let mut verifier = KeyHierarchy::new();
        verifier
            .unlock_vault(master_password, &kdf_params, &wrapped_dek)
            .map_err(PasswordManagerError::Crypto)?;

        let dek = verifier.dek()?.clone();
        verifier.lock_vault();
        let biometric_ref =
            crate::biometric::BiometricManager::store_vault_dek(&self.vault_path, &dek)?;
        Self::set_biometric_ref(&db, Some(&biometric_ref))?;
        Ok(())
    }

    /// Disable biometric unlock and clear keychain stored secret.
    pub fn disable_biometric_unlock(&self) -> Result<()> {
        let db = self.db.lock().map_err(|_| {
            PasswordManagerError::from(DatabaseError::LockPoisoned(
                "Failed to lock database".to_string(),
            ))
        })?;

        if let Some(biometric_ref) = Self::load_biometric_ref(&db)? {
            let _ = crate::biometric::BiometricManager::clear_vault_dek(&biometric_ref);
        }

        Self::set_biometric_ref(&db, None)?;
        Ok(())
    }

    /// Check whether biometric unlock is enabled for this vault instance.
    pub fn biometric_unlock_enabled(&self) -> Result<bool> {
        let db = self.db.lock().map_err(|_| {
            PasswordManagerError::from(DatabaseError::LockPoisoned(
                "Failed to lock database".to_string(),
            ))
        })?;
        Ok(Self::load_biometric_ref(&db)?.is_some())
    }
}
