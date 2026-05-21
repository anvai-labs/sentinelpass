// Core bridge functionality shared between iOS and Android

use crate::error::{BridgeError, BridgeResult};
use sentinelpass_core::vault::{CredentialType, Entry, EntrySummary, VaultManager};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

/// Global vault handle storage
///
/// On mobile, we typically have only one vault per device, but we use
/// handles to support future multi-vault scenarios and testing.
static VAULT_REGISTRY: OnceLock<Mutex<VaultRegistry>> = OnceLock::new();

fn get_registry() -> &'static Mutex<VaultRegistry> {
    VAULT_REGISTRY.get_or_init(|| Mutex::new(VaultRegistry::new()))
}

struct VaultRegistry {
    vaults: HashMap<u64, Arc<Mutex<VaultManager>>>,
    next_handle: u64,
    biometric_keys: HashMap<u64, Vec<u8>>,
}

impl VaultRegistry {
    fn new() -> Self {
        Self {
            vaults: HashMap::new(),
            next_handle: 1,
            biometric_keys: HashMap::new(),
        }
    }

    fn register_vault(&mut self, vault: VaultManager) -> u64 {
        let handle = self.next_handle;
        self.next_handle = handle.wrapping_add(1);
        self.vaults.insert(handle, Arc::new(Mutex::new(vault)));
        handle
    }

    fn get_vault(&self, handle: u64) -> Option<Arc<Mutex<VaultManager>>> {
        self.vaults.get(&handle).cloned()
    }

    fn remove_vault(&mut self, handle: u64) -> Option<Arc<Mutex<VaultManager>>> {
        self.vaults.remove(&handle)
    }

    fn set_biometric_key(&mut self, handle: u64, key: Vec<u8>) {
        self.biometric_keys.insert(handle, key);
    }

    fn get_biometric_key(&self, handle: u64) -> Option<&Vec<u8>> {
        self.biometric_keys.get(&handle)
    }

    fn remove_biometric_key(&mut self, handle: u64) -> Option<Vec<u8>> {
        self.biometric_keys.remove(&handle)
    }
}

/// Vault handle type (opaque u64 for FFI)
pub type VaultHandle = u64;

/// Initialize a new vault or unlock existing one
pub fn bridge_vault_init(vault_path: &str, master_password: &str) -> BridgeResult<VaultHandle> {
    if vault_path.is_empty() || master_password.is_empty() {
        return Err(BridgeError::InvalidParam(
            "vault_path and master_password cannot be empty".into(),
        ));
    }

    let vault_exists = Path::new(vault_path).exists();

    let vault = if vault_exists {
        VaultManager::open(vault_path, master_password.as_bytes())?
    } else {
        VaultManager::create(vault_path, master_password.as_bytes())?
    };

    let mut registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let handle = registry.register_vault(vault);
    Ok(handle)
}

/// Destroy a vault and free resources
pub fn bridge_vault_destroy(handle: VaultHandle) -> BridgeResult<()> {
    let mut registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    registry.remove_biometric_key(handle);
    registry
        .remove_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    Ok(())
}

/// Check if vault is unlocked
pub fn bridge_vault_is_unlocked(handle: VaultHandle) -> BridgeResult<bool> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    Ok(vault.is_unlocked())
}

/// Lock the vault
pub fn bridge_vault_lock(handle: VaultHandle) -> BridgeResult<()> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let mut vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    vault.lock();
    Ok(())
}

/// Add an entry to the vault
pub fn bridge_entry_add(
    handle: VaultHandle,
    title: &str,
    username: &str,
    password: &str,
    url: &str,
    notes: &str,
) -> BridgeResult<String> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    let entry = Entry {
        entry_id: None,
        title: title.to_string(),
        username: username.to_string(),
        password: password.to_string().into(),
        url: if url.is_empty() {
            None
        } else {
            Some(url.to_string())
        },
        notes: if notes.is_empty() {
            None
        } else {
            Some(notes.to_string())
        },
        credential_type: CredentialType::Password,
        created_at: chrono::Utc::now(),
        modified_at: chrono::Utc::now(),
        favorite: false,
    };

    let entry_id_i64 = vault.add_entry(&entry)?;
    Ok(entry_id_i64.to_string())
}

/// Update an existing entry
#[allow(dead_code)] // FFI function - called from mobile platforms
pub fn bridge_entry_update(
    handle: VaultHandle,
    entry_id: &str,
    title: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    url: Option<&str>,
    notes: Option<&str>,
) -> BridgeResult<()> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    let id_i64: i64 = entry_id
        .parse()
        .map_err(|_| BridgeError::InvalidParam(format!("Invalid entry ID: {}", entry_id)))?;

    let mut existing = vault.get_entry(id_i64)?;

    if let Some(t) = title {
        existing.title = t.to_string();
    }
    if let Some(u) = username {
        existing.username = u.to_string();
    }
    if let Some(p) = password {
        existing.password = p.to_string().into();
    }
    if let Some(u) = url {
        existing.url = if u.is_empty() {
            None
        } else {
            Some(u.to_string())
        };
    }
    if let Some(n) = notes {
        existing.notes = if n.is_empty() {
            None
        } else {
            Some(n.to_string())
        };
    }
    existing.modified_at = chrono::Utc::now();

    vault.update_entry(id_i64, &existing)?;
    Ok(())
}

/// Delete an entry
pub fn bridge_entry_delete(handle: VaultHandle, entry_id: &str) -> BridgeResult<()> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    let id_i64: i64 = entry_id
        .parse()
        .map_err(|_| BridgeError::InvalidParam(format!("Invalid entry ID: {}", entry_id)))?;

    vault.delete_entry(id_i64)?;
    Ok(())
}

/// Get a specific entry by ID
pub fn bridge_entry_get(handle: VaultHandle, entry_id: &str) -> BridgeResult<Entry> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    let id_i64: i64 = entry_id
        .parse()
        .map_err(|_| BridgeError::InvalidParam(format!("Invalid entry ID: {}", entry_id)))?;

    Ok(vault.get_entry(id_i64)?)
}

/// List all entries
pub fn bridge_entry_list(handle: VaultHandle) -> BridgeResult<Vec<EntrySummary>> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    Ok(vault.list_entries()?)
}

/// Search entries by query
pub fn bridge_entry_search(handle: VaultHandle, query: &str) -> BridgeResult<Vec<EntrySummary>> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    let all_entries = vault.list_entries()?;
    let query_lower = query.to_lowercase();

    let filtered: Vec<EntrySummary> = all_entries
        .into_iter()
        .filter(|e| {
            e.title.to_lowercase().contains(&query_lower)
                || e.username.to_lowercase().contains(&query_lower)
        })
        .collect();

    Ok(filtered)
}

/// Generate TOTP code for an entry
pub fn bridge_totp_generate_code(
    handle: VaultHandle,
    entry_id: &str,
) -> BridgeResult<sentinelpass_core::TotpCode> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    let id_i64: i64 = entry_id
        .parse()
        .map_err(|_| BridgeError::InvalidParam(format!("Invalid entry ID: {}", entry_id)))?;

    Ok(vault.generate_totp_code(id_i64)?)
}

/// Generate a random password
pub fn bridge_password_generate(length: usize, include_symbols: bool) -> BridgeResult<String> {
    use sentinelpass_core::crypto::password;

    let config = password::PasswordGeneratorConfig {
        length,
        include_lowercase: true,
        include_uppercase: true,
        include_digits: true,
        include_symbols,
        exclude_ambiguous: false,
    };

    let password = password::generate_password(&config)?;
    Ok(password)
}

/// Check password strength
pub fn bridge_password_check_strength(
    password: &str,
) -> BridgeResult<sentinelpass_core::crypto::strength::PasswordAnalysis> {
    use sentinelpass_core::crypto::strength;

    let analysis = strength::analyze_password(password)?;
    Ok(analysis)
}

/// Set biometric key data for a vault
pub fn bridge_biometric_set_key(handle: VaultHandle, wrapped_key_data: &[u8]) -> BridgeResult<()> {
    let mut registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    registry.set_biometric_key(handle, wrapped_key_data.to_vec());
    Ok(())
}

/// Check if biometric key is set
pub fn bridge_biometric_has_key(handle: VaultHandle) -> BridgeResult<bool> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    Ok(registry.get_biometric_key(handle).is_some())
}

/// Remove biometric key
pub fn bridge_biometric_remove_key(handle: VaultHandle) -> BridgeResult<()> {
    let mut registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    registry
        .remove_biometric_key(handle)
        .ok_or_else(|| BridgeError::Biometric("No biometric key set".into()))?;

    Ok(())
}

/// Unlock vault using biometric key (placeholder for platform-specific implementation)
pub fn bridge_biometric_unlock(_handle: VaultHandle) -> BridgeResult<()> {
    // Platform-specific implementation required
    // This would decrypt the wrapped master key using platform keystore
    // and then unlock the vault
    Err(BridgeError::Biometric(
        "Platform-specific biometric unlock not yet implemented".into(),
    ))
}

// ============================================================================
// Sync Operations
// ============================================================================

/// Sync status information
#[derive(Debug, Clone)]
pub struct SyncStatus {
    pub enabled: bool,
    pub last_sync_at: Option<i64>,
    pub pending_changes: u64,
    pub device_id: Option<String>,
}

/// Result of a sync operation
#[allow(dead_code)] // FFI struct - used on mobile platforms
#[derive(Debug, Clone)]
pub struct SyncResult {
    pub success: bool,
    pub pushed: u64,
    pub pulled: u64,
    pub error: Option<String>,
}

/// Get sync status for a vault
pub fn bridge_sync_get_status(handle: VaultHandle) -> BridgeResult<SyncStatus> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let _vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    // Note: Mobile sync uses iCloud/Google Drive, not the relay server
    // This is a placeholder that returns basic status
    Ok(SyncStatus {
        enabled: false, // Mobile sync must be explicitly enabled
        last_sync_at: None,
        pending_changes: 0,
        device_id: None,
    })
}

/// Collect entries pending sync (for upload to CloudKit/Drive)
pub fn bridge_sync_collect_pending(handle: VaultHandle) -> BridgeResult<Vec<u8>> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    if !vault.is_unlocked() {
        return Err(BridgeError::Vault("Vault is locked".to_string()));
    }

    // Collect all entries (in a real implementation, this would use change tracking)
    let entries = vault.list_entries()?;

    // Convert to sync blobs
    let mut blobs = Vec::new();
    for entry in entries {
        // Create a sync entry blob from the vault entry
        // Note: This is a simplified version - real implementation would use
        // the sync module's change tracking and proper encryption
        blobs.push(format!(
            "{{\"id\":{},\"title\":\"{}\"}}",
            entry.entry_id, entry.title
        ));
    }

    // Return as JSON bytes
    serde_json::to_string(&blobs)
        .map(|s| s.into_bytes())
        .map_err(|e| BridgeError::Sync(format!("Failed to serialize entries: {}", e)))
}

/// Apply downloaded entries from CloudKit/Drive
pub fn bridge_sync_apply_entries(handle: VaultHandle, entries_json: &[u8]) -> BridgeResult<u64> {
    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    if !vault.is_unlocked() {
        return Err(BridgeError::Vault("Vault is locked".to_string()));
    }

    // Parse the JSON entries
    let entries: Vec<serde_json::Value> = serde_json::from_slice(entries_json)
        .map_err(|e| BridgeError::Sync(format!("Invalid entries JSON: {}", e)))?;

    // Apply entries (simplified - real implementation would handle conflict resolution)
    let mut applied = 0u64;
    for _entry in entries {
        // In a real implementation, this would decrypt and apply each entry
        // For now, just count them
        applied += 1;
    }

    Ok(applied)
}

/// Prepare entries for CloudKit upload (convert to CloudKit records JSON)
pub fn bridge_sync_prepare_cloudkit(handle: VaultHandle, device_id: &str) -> BridgeResult<Vec<u8>> {
    use crate::icloud::ICloudSyncManager;

    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    if !vault.is_unlocked() {
        return Err(BridgeError::Vault("Vault is locked".to_string()));
    }

    // Initialize sync manager
    let sync_manager = ICloudSyncManager::new();
    let device_uuid = uuid::Uuid::parse_str(device_id)
        .map_err(|_| BridgeError::InvalidParam("Invalid device ID format".into()))?;
    sync_manager.init(device_uuid, None)?;

    // Collect entries (simplified - would use change tracking)
    let entries = vault.list_entries()?;

    // Convert to CloudKit records
    // Note: This is a placeholder - real implementation would convert
    // actual sync blobs, not just entry summaries
    let records: Vec<String> = entries
        .iter()
        .map(|e| {
            format!(
                "{{\"recordType\":\"SyncEntry\",\"recordID\":\"{}\",\"title\":\"{}\"}}",
                e.entry_id, e.title
            )
        })
        .collect();

    serde_json::to_string(&records)
        .map(|s| s.into_bytes())
        .map_err(|e| BridgeError::Sync(format!("Failed to serialize CloudKit records: {}", e)))
}

/// Prepare entries for Google Drive upload (convert to Drive files JSON)
pub fn bridge_sync_prepare_drive(handle: VaultHandle, device_id: &str) -> BridgeResult<Vec<u8>> {
    use crate::drive::DriveSyncManager;

    let registry = get_registry()
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault registry lock".into()))?;

    let vault_arc = registry
        .get_vault(handle)
        .ok_or_else(|| BridgeError::InvalidParam(format!("Invalid vault handle: {}", handle)))?;

    let vault = vault_arc
        .lock()
        .map_err(|_| BridgeError::Unknown("Failed to acquire vault lock".into()))?;

    if !vault.is_unlocked() {
        return Err(BridgeError::Vault("Vault is locked".to_string()));
    }

    // Initialize sync manager
    let sync_manager = DriveSyncManager::new();
    let device_uuid = uuid::Uuid::parse_str(device_id)
        .map_err(|_| BridgeError::InvalidParam("Invalid device ID format".into()))?;
    sync_manager.init(device_uuid)?;

    // Collect entries (simplified - would use change tracking)
    let entries = vault.list_entries()?;

    // Convert to Drive files
    let files: Vec<String> = entries
        .iter()
        .map(|e| {
            format!(
                "{{\"id\":\"{}\",\"name\":\"{}.json\",\"title\":\"{}\"}}",
                e.entry_id, e.entry_id, e.title
            )
        })
        .collect();

    serde_json::to_string(&files)
        .map(|s| s.into_bytes())
        .map_err(|e| BridgeError::Sync(format!("Failed to serialize Drive files: {}", e)))
}
