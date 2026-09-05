//! Biometric authentication operations for VaultManager

use super::VaultManager;
use crate::{
    audit::{get_audit_log_dir, AuditEventType, AuditLogger},
    crypto::KeyHierarchy,
    database::Database,
    PasswordManagerError, Result,
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

        // Epoch high-water enforcement (WBS-301 / ADR-004 rev 4): this path
        // unlocks without the password-derived master key, so rolled-back or
        // rewound state has no other detection — check before anything.
        // Refusals/TOFU are audited (the biometric surface must not be the
        // silent one); a pending one-step heal is deliberately NOT adopted
        // here — there is no password proof of the new state — and waits for
        // the next password unlock.
        let early_logger = AuditLogger::new(get_audit_log_dir()).map(Arc::new).ok();
        let snapshot = Self::load_vault_snapshot(&db)?;
        let (epoch_sidecar, vault_uuid, bio_check) =
            match Self::enforce_epoch_guard(&snapshot, &vault_path) {
                Ok(triple) => triple,
                Err(guard_err) => {
                    if let Some(ref logger) = early_logger {
                        let _ = logger.log(
                            AuditEventType::EpochHighWaterRebased { refused: true },
                            &format!("biometric open refused by epoch guard: {guard_err}"),
                        );
                    }
                    return Err(guard_err);
                }
            };
        // Shared outcome auditing; the deferred-heal nuance (no password
        // proof on this surface) is recorded in the ADR residual.
        if let (Some(ref check), Some(ref logger)) = (&bio_check, &early_logger) {
            Self::log_epoch_outcome(logger, check, "biometric open (heal deferred)");
        }

        let mut key_hierarchy = KeyHierarchy::new();
        let dek = crate::biometric::BiometricManager::authenticate_and_load_vault_dek(
            &biometric_ref,
            reason,
        )?;
        key_hierarchy.unlock_vault_with_dek(dek);

        // Registry MAC verification/bootstrap with the DEK in hand — this
        // full unlock surface must not be the one that skips it (review
        // round 1, finding 2): without this check, a biometric-only user's
        // MAC stays NULL forever, and a tampered registry could be laundered
        // through a later revoke's MAC recompute.
        if let Err(e) = Self::ensure_or_verify_slot_registry(
            &key_hierarchy,
            &db,
            &snapshot,
            &epoch_sidecar,
            &vault_uuid,
            false, // biometric DEK is unauthenticated vs the wrap: no bootstrap
        ) {
            // A bare `?` here left this refusal silent (review round 2,
            // finding 3) — the biometric surface must not be the one with
            // no audit trace, matching retrieve_dek_via_biometric's handling.
            if let Some(ref logger) = early_logger {
                let event = if matches!(&e, PasswordManagerError::SlotRegistryTampered) {
                    AuditEventType::SlotRegistryIntegrityRefused
                } else {
                    AuditEventType::EpochHighWaterRebased { refused: true }
                };
                let _ = logger.log(
                    event,
                    &format!("biometric open refused by slot registry: {e}"),
                );
            }
            return Err(e);
        }

        Self::clear_failed_attempts(&db)?;

        let audit_logger = early_logger;

        let vault_manager = Self {
            key_hierarchy,
            db: Arc::new(Mutex::new(db)),
            vault_path,
            audit_logger,
            epoch_sidecar,
            vault_uuid,
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
        // Migrate if needed (parity with open(): a v5 vault must gain its
        // identity columns before the guard can run — adversarial finding).
        db.validate_schema_version()?;

        let biometric_ref = Self::load_biometric_ref(&db)?.ok_or_else(|| {
            PasswordManagerError::NotFound("Biometric unlock configuration".to_string())
        })?;

        // Same epoch guard as open_with_biometric: this path also releases
        // the DEK without the password, so rolled-back or rewound state must
        // be caught here too (adversarial-review finding). Outcomes are
        // audited — this DEK-releasing surface must not be the silent one
        // (round-4 finding).
        let logger = AuditLogger::new(get_audit_log_dir()).map(Arc::new).ok();
        let snapshot = Self::load_vault_snapshot(&db)?;
        match Self::enforce_epoch_guard(&snapshot, &vault_path) {
            Ok((_, _, check)) => {
                if let (Some(ref logger), Some(ref c)) = (&logger, &check) {
                    Self::log_epoch_outcome(logger, c, "biometric dek retrieval");
                }
            }
            Err(guard_err) => {
                if let Some(ref logger) = &logger {
                    let _ = logger.log(
                        AuditEventType::EpochHighWaterRebased { refused: true },
                        &format!("biometric dek retrieval refused by epoch guard: {guard_err}"),
                    );
                }
                return Err(guard_err);
            }
        }

        let dek = crate::biometric::BiometricManager::authenticate_and_load_vault_dek(
            &biometric_ref,
            reason,
        )?;

        // Registry verification with the released DEK (parity with
        // open_with_biometric — this DEK-releasing surface must not skip it;
        // review round 1). A temporary hierarchy carries the DEK; the
        // sidecar/uuid inputs come from the guard result above.
        let mut hierarchy = KeyHierarchy::new();
        hierarchy.unlock_vault_with_dek(dek.clone());
        let sidecar = Self::sidecar_for(&vault_path);
        let uuid = snapshot.vault_uuid.clone();
        match Self::ensure_or_verify_slot_registry(
            &hierarchy, &db, &snapshot, &sidecar, &uuid, false,
        ) {
            Ok(()) => {}
            Err(e) => {
                if let Some(ref logger) = &logger {
                    // Structural match (review round 2, finding 5): a typed
                    // error variant, not error-prose matching, selects the
                    // audit event — a future reword of the tamper message
                    // can no longer silently misfile this under the epoch
                    // event.
                    let event = if matches!(&e, PasswordManagerError::SlotRegistryTampered) {
                        AuditEventType::SlotRegistryIntegrityRefused
                    } else {
                        AuditEventType::EpochHighWaterRebased { refused: true }
                    };
                    let _ = logger.log(
                        event,
                        &format!("biometric dek retrieval refused by slot registry: {e}"),
                    );
                }
                return Err(e);
            }
        }

        Ok(dek)
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

        let db = self.lock_db()?;

        // Validate that the provided master password can actually unlock this
        // vault. Wraps created after a master-password rotation (ADR-002) bind
        // key_epoch as AEAD associated data, so verification must be
        // epoch-aware — the legacy unlock_vault() always fails GCM auth on a
        // rotated wrap and would make it impossible to newly enable biometric
        // unlock after any rotation.
        let (kdf_params, wrapped_dek, key_epoch) = Self::load_vault_metadata(&db)?;
        let mut verifier = KeyHierarchy::new();
        verifier
            .unlock_vault_with_epoch(master_password, &kdf_params, &wrapped_dek, key_epoch)
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
        let db = self.lock_db()?;

        // Clear the keychain entry FIRST and propagate failure: swallowing it
        // (the old `let _ =`) left the DEK in the platform store while the
        // DB column was NULLed — a DB-only writer could then restore the
        // deterministic ref and resurrect biometric unlock with zero signal
        // (adversarial-review finding). Failing here leaves biometric
        // ENABLED — the fail-safe direction. ONE exception (review round 1,
        // finding 10): on platforms with no keychain support there is
        // nothing to clear, and refusing would make a restored biometric_ref
        // permanently undisableable there — clear the stale column instead.
        if let Some(biometric_ref) = Self::load_biometric_ref(&db)? {
            if let Err(e) = crate::biometric::BiometricManager::clear_vault_dek(&biometric_ref) {
                let unsupported = matches!(
                    &e,
                    PasswordManagerError::NotFound(msg)
                        if msg.contains(crate::biometric::UNSUPPORTED_PLATFORM_MSG)
                );
                if !unsupported {
                    return Err(e);
                }
                tracing::warn!(
                    "biometric key storage unsupported on this platform; clearing the \
                     stale biometric_ref column only"
                );
            }
        }

        Self::set_biometric_ref(&db, None)?;
        Ok(())
    }

    /// Check whether biometric unlock is enabled for this vault instance.
    pub fn biometric_unlock_enabled(&self) -> Result<bool> {
        let db = self.lock_db()?;
        Ok(Self::load_biometric_ref(&db)?.is_some())
    }
}
