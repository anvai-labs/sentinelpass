// Authenticated backup/export (WBS-827): the ADR-008 `.spbackup` bundle
// format, exposed to mobile.
//
// - CREATE: `VaultManager::create_backup` (requires an UNLOCKED vault — the
//   bundle binds key material, ADR-008) writes an atomic, refusing-to-
//   overwrite bundle with an authenticated manifest.
// - RESTORE: `VaultManager::restore_bundle` is a STATIC, OFFLINE-EXCLUSIVE
//   operation (ADR-007): it takes the vault's maintenance lock, verifies
//   bundle authenticity, and replaces the target. CALLER CONTRACT: every
//   open bridge handle for `vault_path` must be DESTROYED first — the
//   registry does not track paths, and a live SQLite handle on the target
//   is a real conflict. The app's restore flow destroys its handle before
//   calling; the maintenance lock makes any concurrent-open fail safe.
//
// `allow_epoch_rewind` (ADR-004 rev 4 supervised override) and `disable_sync`
// (ADR-008 branch 2: restored state re-pairs, never reuses relay lineage)
// ride the core RestoreOptions — both audit-logged by core.

use crate::bridge::{get_registry, VaultHandle};
use crate::error::{BridgeError, BridgeResult};
use sentinelpass_core::vault::VaultManager;
use sentinelpass_core::vault::backup_ops::RestoreOptions;
use std::path::Path;

/// Create an authenticated `.spbackup` bundle from the unlocked vault at
/// `handle`. Refuses to overwrite an existing output. Returns the summary
/// as JSON (entries count, bytes, backup id — non-secret metadata).
pub fn bridge_backup_create(handle: VaultHandle, output_path: &str) -> BridgeResult<String> {
    if output_path.is_empty() {
        return Err(BridgeError::InvalidParam("output_path cannot be empty".into()));
    }

    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;
    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {handle}")))?;
    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    if !vault.is_unlocked() {
        return Err(BridgeError::Vault("Vault is locked".to_string()));
    }

    let summary = vault
        .create_backup(Path::new(output_path))
        .map_err(BridgeError::from)?;
    serde_json::to_string(&summary)
        .map_err(|e| BridgeError::Sync(format!("Failed to serialize backup summary: {e}")))
}

/// Restore a `.spbackup` bundle onto `vault_path` (static, offline). See the
/// module doc for the close-handles-first caller contract. Returns the
/// restore report as JSON.
#[allow(clippy::too_many_arguments)]
pub fn bridge_backup_restore(
    vault_path: &str,
    bundle_path: &str,
    master_password: &str,
    allow_replace: bool,
    allow_epoch_rewind: bool,
    disable_sync: bool,
) -> BridgeResult<String> {
    if vault_path.is_empty() || bundle_path.is_empty() {
        return Err(BridgeError::InvalidParam(
            "vault_path and bundle_path cannot be empty".into(),
        ));
    }

    let opts = RestoreOptions {
        allow_replace,
        allow_epoch_rewind,
        disable_sync,
    };
    let report = VaultManager::restore_bundle(
        Path::new(vault_path),
        Path::new(bundle_path),
        master_password.as_bytes(),
        &opts,
    )
    .map_err(BridgeError::from)?;
    serde_json::to_string(&report)
        .map_err(|e| BridgeError::Sync(format!("Failed to serialize restore report: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sp_backup_test_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn create_and_restore_round_trip_preserves_entries() {
        let dir = temp_dir();
        let vault_path = dir.join("vault.db");
        let bundle = dir.join("out.spbackup");
        let binding = vault_path.to_str().unwrap().to_string();

        // Create + populate through the normal bridge path.
        let vault = VaultManager::create(&vault_path, b"master-password").unwrap();
        let entry = sentinelpass_core::vault::Entry {
            entry_id: None,
            title: "backed-up-entry".to_string(),
            username: "u".to_string(),
            password: "p".to_string().into(),
            url: None,
            notes: None,
            credential_type: sentinelpass_core::vault::CredentialType::Password,
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            favorite: false,
        };
        vault.add_entry(&entry).unwrap();
        let mut registry = get_registry().lock().unwrap();
        let handle = registry.register_vault(vault);
        drop(registry);

        // CREATE.
        let summary = bridge_backup_create(handle, bundle.to_str().unwrap())
            .expect("backup create must succeed");
        assert!(summary.contains("backup_id") || summary.contains("entries"));

        // CREATE refuses to overwrite.
        assert!(bridge_backup_create(handle, bundle.to_str().unwrap()).is_err());

        // DESTROY the live handle (caller contract), then RESTORE onto a
        // fresh path with the correct password.
        crate::bridge::bridge_vault_destroy(handle).unwrap();
        let restored_path = dir.join("restored.db");
        let report = bridge_backup_restore(
            restored_path.to_str().unwrap(),
            bundle.to_str().unwrap(),
            "master-password",
            false,
            false,
            true,
        )
        .expect("restore must succeed");
        assert!(report.contains("vault_uuid"));

        // The restored vault opens with the password and has the entry.
        let restored = VaultManager::open(&restored_path, b"master-password").unwrap();
        let entries = restored.list_entries().unwrap();
        assert!(
            entries.iter().any(|e| e.title == "backed-up-entry"),
            "restored vault must contain the backed-up entry"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_with_wrong_password_fails() {
        let dir = temp_dir();
        let vault_path = dir.join("vault.db");
        let bundle = dir.join("out.spbackup");

        let vault = VaultManager::create(&vault_path, b"correct-password").unwrap();
        let mut registry = get_registry().lock().unwrap();
        let handle = registry.register_vault(vault);
        drop(registry);

        bridge_backup_create(handle, bundle.to_str().unwrap()).unwrap();
        crate::bridge::bridge_vault_destroy(handle).unwrap();

        let restored_path = dir.join("restored.db");
        assert!(bridge_backup_restore(
            restored_path.to_str().unwrap(),
            bundle.to_str().unwrap(),
            "wrong-password",
            false,
            false,
            true
        )
        .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_requires_an_unlocked_vault() {
        let dir = temp_dir();
        let vault_path = dir.join("vault.db");
        let vault = VaultManager::create(&vault_path, b"master-password").unwrap();
        let mut registry = get_registry().lock().unwrap();
        let handle = registry.register_vault(vault);
        drop(registry);

        crate::bridge::bridge_vault_lock(handle).unwrap();
        assert!(bridge_backup_create(handle, dir.join("b.spbackup").to_str().unwrap()).is_err());

        crate::bridge::bridge_vault_destroy(handle).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
