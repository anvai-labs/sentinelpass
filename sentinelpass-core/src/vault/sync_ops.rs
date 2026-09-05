//! Sync-related VaultManager methods.

use crate::{
    crypto::{KdfParams, KeyHierarchy, WrappedKey},
    DatabaseError, PasswordManagerError, Result,
};
use chrono::Utc;

use super::{epoch_guard, VaultManager};

impl VaultManager {
    /// Get sync status from the database.
    pub fn get_sync_status(&self) -> Result<crate::sync::models::SyncStatus> {
        let db = self.lock_db()?;
        let config = crate::sync::config::SyncConfig::load(db.conn())?;
        let pending = crate::sync::change_tracker::count_pending_changes(db.conn())?;

        Ok(crate::sync::models::SyncStatus {
            enabled: config.sync_enabled,
            device_id: config.device_id,
            device_name: config.device_name.clone(),
            relay_url: config.relay_url.clone(),
            last_sync_at: config.last_sync_at,
            pending_changes: pending,
        })
    }

    /// Load the local sync device identity (Ed25519 signing key + metadata) if present.
    pub fn load_sync_device_identity(&self) -> Result<Option<crate::sync::device::DeviceIdentity>> {
        let dek = self.key_hierarchy.dek()?;
        let db = self.lock_db()?;
        crate::sync::device::DeviceIdentity::load_from_db(db.conn(), dek)
    }

    /// Export the encrypted pairing bootstrap payload used to onboard a new sync device.
    pub fn export_pairing_bootstrap(&self) -> Result<crate::sync::models::VaultBootstrap> {
        let db = self.lock_db()?;
        let config = crate::sync::config::SyncConfig::load(db.conn())?;
        let relay_url = config.relay_url.ok_or_else(|| {
            PasswordManagerError::InvalidInput("Sync relay URL not set".to_string())
        })?;
        let vault_id = config.vault_id.ok_or_else(|| {
            PasswordManagerError::InvalidInput("Sync vault ID not set".to_string())
        })?;

        let (kdf_params, wrapped_dek, key_epoch) = Self::load_vault_metadata(&db)?;
        let kdf_params_blob = bincode::serialize(&kdf_params)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let wrapped_dek_blob = bincode::serialize(&wrapped_dek)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        Ok(crate::sync::models::VaultBootstrap {
            kdf_params_blob,
            wrapped_dek_blob,
            relay_url,
            vault_id,
            key_epoch,
        })
    }

    /// Import a pairing bootstrap into an empty local vault and switch this instance to the
    /// remote vault's KDF parameters and wrapped DEK.
    ///
    /// The local vault must be unlocked and contain no entries/SSH keys/TOTP
    /// secrets/registry entities.
    ///
    /// The bootstrap's wrap may be epoch-bound (ADR-002: the origin vault
    /// was rotated at least once) — `unlock_vault_with_epoch` verifies the
    /// bound epoch as AEAD associated data, and the imported `key_epoch` is
    /// persisted so a subsequent `open()` on this device verifies against
    /// the same epoch the wrap was created under. Using the legacy
    /// (non-epoch) unlock here would make pair-join from any rotated
    /// origin vault fail outright, and skipping the epoch persist would
    /// brick this vault on next open even if the unlock itself succeeded.
    pub fn import_pairing_bootstrap(
        &mut self,
        master_password: &[u8],
        bootstrap: &crate::sync::models::VaultBootstrap,
    ) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let imported_kdf: KdfParams = bincode::deserialize(&bootstrap.kdf_params_blob)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        // Accept both the current 4-field wrap shape and the legacy
        // (<= v0.8.0) 3-field shape a pre-ADR-002 origin device may still
        // export.
        let imported_wrapped = WrappedKey::from_bincode_bytes(&bootstrap.wrapped_dek_blob)
            .map_err(PasswordManagerError::Crypto)?;

        let mut imported_hierarchy = KeyHierarchy::new();
        imported_hierarchy.unlock_vault_with_epoch(
            master_password,
            &imported_kdf,
            &imported_wrapped,
            bootstrap.key_epoch,
        )?;

        let db = self.lock_db()?;
        let conn = db.conn();

        let entry_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .map_err(DatabaseError::Sqlite)?;
        let ssh_key_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ssh_keys", [], |row| row.get(0))
            .map_err(DatabaseError::Sqlite)?;
        let totp_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM totp_secrets", [], |row| row.get(0))
            .map_err(DatabaseError::Sqlite)?;
        // Registry entities (ADR-001): their name/notes columns are
        // DEK-encrypted. Allowing entities to survive a DEK replacement
        // would leave them permanently undecryptable under the new DEK, so
        // they must be included in the "must be empty" guard alongside
        // entries/ssh_keys/totp_secrets.
        let entity_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM entities", [], |row| row.get(0))
            .map_err(DatabaseError::Sqlite)?;

        if entry_count > 0 || ssh_key_count > 0 || totp_count > 0 || entity_count > 0 {
            return Err(PasswordManagerError::InvalidInput(
                "Pair-join target vault must be empty".to_string(),
            ));
        }

        let nonce_blob = bincode::serialize(&imported_wrapped.nonce)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let wrapped_dek_blob = bincode::serialize(&imported_wrapped)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        // Clear any pre-join biometric BEFORE adopting imported material
        // (round-4 ordering fix): pair-join replaces the DEK, and doing this
        // after the durable adoption half-commits when the keychain clear
        // fails — the caller sees failure while disk holds the imported
        // vault. Clearing first means a later failure merely leaves biometric
        // disabled on a throwaway vault (fail-safe).
        if let Some(bio_ref) = Self::load_biometric_ref(&db)? {
            if let Err(e) = crate::biometric::BiometricManager::clear_vault_dek(&bio_ref) {
                // Same platform-unsupported tolerance as
                // disable_biometric_unlock (review round 1): on a platform
                // with no keychain there is nothing to clear, and refusing
                // would permanently brick pair-join for vaults that carry a
                // foreign biometric_ref.
                let unsupported = matches!(
                    &e,
                    PasswordManagerError::NotFound(msg)
                        if msg.contains(crate::biometric::UNSUPPORTED_PLATFORM_MSG)
                );
                if !unsupported {
                    return Err(e);
                }
            }
            Self::set_biometric_ref(&db, None)?;
        }

        // db_metadata's wrap and the key-slot registry must become durable
        // TOGETHER: the registry MAC is bound to the imported DEK
        // (`sync_password_slot_after_material_change` derives it from
        // `imported_hierarchy`), so a partial write — metadata reverted but
        // the registry left reflecting the imported DEK, or vice versa —
        // produces a vault whose crypto wrap unlocks fine but whose registry
        // MAC can never again verify (a permanent brick requiring manual SQL
        // surgery, found by re-deriving the MAC-key/DEK relationship under
        // adversarial review). One transaction; no partial DB-level
        // compensation on later failures.
        let tx = conn
            .unchecked_transaction()
            .map_err(DatabaseError::Sqlite)?;

        let rows = tx
            .execute(
                "UPDATE db_metadata
                 SET kdf_params = ?1, wrapped_dek = ?2, dek_nonce = ?3, key_epoch = ?4
                 WHERE id = 1",
                rusqlite::params![
                    &bootstrap.kdf_params_blob,
                    &wrapped_dek_blob,
                    &nonce_blob,
                    bootstrap.key_epoch,
                ],
            )
            .map_err(DatabaseError::Sqlite)?;
        if rows == 0 {
            let _ = tx.rollback();
            return Err(PasswordManagerError::NotFound("Vault metadata".to_string()));
        }

        // Mirror the adopted material into the password slot + recompute the
        // registry MAC (WBS-302) in the SAME transaction as the metadata
        // write above.
        if let Err(e) = Self::sync_password_slot_after_material_change(
            &imported_hierarchy,
            &tx,
            &bootstrap.kdf_params_blob,
            &wrapped_dek_blob,
            &nonce_blob,
            bootstrap.key_epoch,
            true,
        ) {
            let _ = tx.rollback();
            return Err(e);
        }
        // Throwaway sync state from the pre-join vault is part of the
        // adoption: cleared inside the SAME transaction (review round 1,
        // finding 6 — previously it ran after the sidecar write, so the
        // post-commit error path skipped it, leaving stale device/tombstone
        // rows against the adopted identity).
        tx.execute("DELETE FROM sync_devices", [])
            .map_err(DatabaseError::Sqlite)?;
        tx.execute("DELETE FROM sync_tombstones", [])
            .map_err(DatabaseError::Sqlite)?;
        tx.commit().map_err(DatabaseError::Sqlite)?;
        drop(db);

        // From here the adoption is DURABLE: the in-memory hierarchy must
        // match disk no matter what happens next (review round 1, finding
        // 6 — previously the swap sat at the very end, so a sidecar-rebase
        // failure returned with the caller holding the OLD throwaway DEK
        // against imported disk state: any write in that session produced
        // ciphertext nothing could ever decrypt).
        self.key_hierarchy = imported_hierarchy;

        // Pair-join deliberately adopts the origin vault's epoch and key
        // material: rebase the epoch high-water sidecar to the imported
        // state. Without this, a joining device whose origin rotated more
        // than once would hit the at-most-+1 jump rule at next open and be
        // permanently locked out (adversarial-review finding).
        //
        // The metadata/registry write above is already durable at this
        // point — a failure here must NOT attempt to revert it (that is the
        // bug this replaced: a partial revert desyncs the wrap from the
        // registry MAC and bricks the vault beyond the sidecar's reach). The
        // vault stays internally consistent; only the external anchor is
        // stale. Surfacing the error (rather than self-healing, as rotation
        // does for its always-+1 case) is deliberate: an adopted epoch jump
        // can exceed +1, so the next open may hard-refuse as "unexplained
        // jump" until the user deletes the sidecar file named in that error.
        if let (Some(ref sidecar), Some(ref uuid)) = (&self.epoch_sidecar, &self.vault_uuid) {
            let digest = {
                let db = self.lock_db()?;
                epoch_guard::material_digest(db.conn())?
            };
            if let Err(e) = epoch_guard::rebase(sidecar, uuid, bootstrap.key_epoch, &digest) {
                // The adoption itself is complete and consistent (hierarchy
                // adopted above; registry + metadata committed together).
                // Only the external anchor is stale — surface it WITH the
                // remediation, since the raw Io error does not name the file
                // (review round 1, finding 6).
                return Err(PasswordManagerError::InvalidInput(format!(
                    "pair-join adopted the imported vault, but updating the epoch \
                     high-water sidecar failed: {e}. Delete the sidecar file {} — the \
                     next open re-bases rollback protection from the adopted state.",
                    sidecar.display()
                )));
            }
        }

        Ok(())
    }

    /// Configure sync for this vault, saving the device identity.
    pub fn init_sync(
        &self,
        relay_url: &str,
        device_name: &str,
        vault_id: uuid::Uuid,
        identity: &crate::sync::device::DeviceIdentity,
    ) -> Result<()> {
        // Transport policy: HTTPS for real relays; cleartext only for an
        // explicit loopback-development allowance. Rejected before anything
        // is persisted.
        crate::sync::config::validate_relay_url(relay_url)?;
        let db = self.lock_db()?;
        let config = crate::sync::config::SyncConfig {
            sync_enabled: true,
            vault_id: Some(vault_id),
            device_id: Some(identity.device_id),
            device_name: Some(device_name.to_string()),
            relay_url: Some(relay_url.to_string()),
            last_push_sequence: 0,
            last_pull_sequence: 0,
            last_sync_at: None,
        };
        config.save(db.conn())?;
        let dek = self.key_hierarchy.dek()?;
        identity.save_to_db(db.conn(), dek)?;
        Ok(())
    }

    /// Disable sync (preserves identity but sets enabled = false).
    pub fn disable_sync(&self) -> Result<()> {
        let db = self.lock_db()?;
        let mut config = crate::sync::config::SyncConfig::load(db.conn())?;
        config.sync_enabled = false;
        config.save(db.conn())?;
        Ok(())
    }

    /// Run a full sync cycle against the configured relay (push pending changes, pull remote changes).
    #[cfg(feature = "sync")]
    pub async fn sync_now(&self) -> Result<crate::sync::models::SyncStatus> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?.clone();
        let identity = self.load_sync_device_identity()?.ok_or_else(|| {
            PasswordManagerError::InvalidInput("Sync device identity missing".to_string())
        })?;

        let (relay_url, vault_id) = {
            let db = self
                .db
                .lock()
                .map_err(|e| DatabaseError::LockPoisoned(e.to_string()))?;
            let config = crate::sync::config::SyncConfig::load(db.conn())?;
            if !config.sync_enabled {
                return Err(PasswordManagerError::InvalidInput(
                    "Sync is not enabled".to_string(),
                ));
            }

            let relay_url = config.relay_url.ok_or_else(|| {
                PasswordManagerError::InvalidInput("Sync relay URL missing".to_string())
            })?;
            let vault_id = config.vault_id.ok_or_else(|| {
                PasswordManagerError::InvalidInput("Sync vault ID missing".to_string())
            })?;
            (relay_url, vault_id)
        };

        {
            let preflight = crate::sync::client::SyncClient::new(
                &relay_url,
                identity.device_id,
                identity.signing_key.clone(),
            )?;

            if let Err(err) = preflight.list_devices().await {
                if is_unknown_device_relay_error(&err) {
                    preflight
                        .register_device(
                            &identity.device_name,
                            crate::sync::device::DeviceIdentity::current_device_type(),
                            &identity.public_key_bytes(),
                            &vault_id,
                        )
                        .await?;
                } else {
                    return Err(err);
                }
            }
        }

        let client = crate::sync::client::SyncClient::new(
            &relay_url,
            identity.device_id,
            identity.signing_key,
        )?;
        let engine =
            crate::sync::engine::SyncEngine::new(client, self.db.clone(), identity.device_id);
        engine.sync(&dek).await
    }

    /// List sync devices from local cache.
    pub fn list_sync_devices(&self) -> Result<Vec<crate::sync::models::SyncDeviceInfo>> {
        let db = self.lock_db()?;
        let mut stmt = db.conn().prepare(
            "SELECT device_id, device_name, device_type, public_key, registered_at, last_sync, revoked, revoked_at
             FROM sync_devices ORDER BY registered_at"
        ).map_err(DatabaseError::Sqlite)?;

        let devices = stmt
            .query_map([], |row: &rusqlite::Row<'_>| {
                let device_id_str: String = row.get(0)?;
                Ok(crate::sync::models::SyncDeviceInfo {
                    device_id: uuid::Uuid::parse_str(&device_id_str).unwrap_or_default(),
                    device_name: row.get(1)?,
                    device_type: row.get(2)?,
                    public_key: row.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
                    registered_at: row.get(4)?,
                    last_sync: row.get(5)?,
                    revoked: row.get(6)?,
                    revoked_at: row.get(7)?,
                })
            })
            .map_err(DatabaseError::Sqlite)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(DatabaseError::Sqlite)?;

        Ok(devices)
    }

    /// Revoke a sync device locally.
    pub fn revoke_sync_device(&self, device_id: &str) -> Result<()> {
        let db = self.lock_db()?;
        let now = Utc::now().timestamp();
        db.conn()
            .execute(
                "UPDATE sync_devices SET revoked = 1, revoked_at = ?1 WHERE device_id = ?2",
                rusqlite::params![now, device_id],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }
}

#[cfg(feature = "sync")]
fn is_unknown_device_relay_error(err: &PasswordManagerError) -> bool {
    match err {
        PasswordManagerError::InvalidInput(msg) => {
            msg.contains("Unknown device") || msg.contains("Relay error 401")
        }
        _ => false,
    }
}
