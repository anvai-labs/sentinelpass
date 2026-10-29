//! Shared JSON file store operations for daemon configuration files.
//!
//! Provides common load/save patterns for owner-only JSON files used by
//! capabilities and site permissions stores.

use crate::{DatabaseError, PasswordManagerError, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

// Load a JSON store from an owner-only file.
// Eliminates duplication between capabilities and site_permissions stores.
pub(crate) fn load_json_store<T: DeserializeOwned + Default>(
    path: &Path,
    store_name: &str,
) -> Result<T> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Serialization(format!(
                "{store_name} store unreadable: {e}"
            )))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(PasswordManagerError::Io(e)),
    }
}

// Save a JSON store to an owner-only file.
// Eliminates duplication between capabilities and site_permissions stores.
pub(crate) fn save_json_store<T: Serialize>(value: &T, path: &Path) -> Result<()> {
    let json = serde_json::to_vec_pretty(value)
        .map_err(|e| PasswordManagerError::from(DatabaseError::Serialization(e.to_string())))?;
    // Owner-only FROM BIRTH (adversarial review F6): write through the
    // platform's owner-only creator (symlink/regular-file checks, 0600
    // at open) so a first grant never lands umask-loose even for a
    // moment; the mode repair below remains for pre-existing files.
    let mut file = crate::platform::create_owner_only_file(path).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!(
            "failed to create store file: {e}"
        )))
    })?;
    use std::io::Write;
    file.write_all(&json).map_err(|e| {
        PasswordManagerError::from(DatabaseError::FileIo(format!("failed to write store: {e}")))
    })?;
    // Repair mode for pre-existing files that were created before the
    // owner-only creator was used.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}
