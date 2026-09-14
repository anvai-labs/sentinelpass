//! Exclusive offline-maintenance lock (WBS-501/503, ADR-007).
//!
//! Vault creation/onboarding and offline maintenance run as EXCLUSIVE
//! operations under an advisory lock beside the vault (`<vault>.maint-lock`):
//!
//! - the daemon acquires it at startup and holds it for its LIFETIME, so a
//!   second daemon (or any offline maintenance process) refuses coexistence;
//! - offline maintenance processes (CLI init/passwd/backup-restore/recovery)
//!   acquire it for the duration of the operation and refuse while it is
//!   held by anyone else;
//! - during offline maintenance, audit ownership transfers to the exclusive
//!   maintenance process: the WBS-415 audit chain supports multi-process
//!   append (the chain head is re-derived from the file tail under
//!   `audit.lock`), so the maintenance process's appends remain verifiable
//!   and the daemon cannot write concurrently because it does not run.
//!
//! Implementation: a persistent, owner-only (0600) lock file locked with
//! `File::try_lock` (flock on Unix, LockFileEx on Windows). The lock FILE is
//! never unlinked while or after being held — unlinking a held advisory lock
//! reintroduces the classic TOCTOU race where two processes lock two
//! different inodes behind one path.

use crate::{PasswordManagerError, Result};
use std::fs::File;
use std::path::{Path, PathBuf};

/// Path of the advisory lock guarding `vault_path` (beside the vault).
pub fn maintenance_lock_path(vault_path: &Path) -> PathBuf {
    let mut name = vault_path.as_os_str().to_os_string();
    name.push(".maint-lock");
    PathBuf::from(name)
}

/// A held exclusive maintenance lock. Release by dropping.
#[derive(Debug)]
pub struct MaintenanceLockGuard {
    file: File,
    lock_path: PathBuf,
}

impl MaintenanceLockGuard {
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

impl Drop for MaintenanceLockGuard {
    fn drop(&mut self) {
        // Relinquish the OS lock; the file itself persists (see module doc).
        let _ = self.file.unlock();
    }
}

/// Try to acquire the exclusive maintenance lock for `vault_path`.
///
/// Fails with [`PasswordManagerError::MaintenanceLockHeld`] when any other
/// process (a live daemon, another maintenance run) holds it. Creates the
/// lock file owner-only (0600) and its parent directory owner-only (0700)
/// when they do not exist yet — the bootstrap (no-vault) case must not open
/// a permission window next to where the vault will live.
pub fn try_acquire(vault_path: &Path) -> Result<MaintenanceLockGuard> {
    let lock_path = maintenance_lock_path(vault_path);

    if let Some(parent) = lock_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(PasswordManagerError::Io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                    .map_err(PasswordManagerError::Io)?;
            }
        }
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&lock_path).map_err(PasswordManagerError::Io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file
            .metadata()
            .map(|m| m.permissions().mode())
            .unwrap_or(0o600);
        if mode & 0o077 != 0 {
            // A pre-existing loose lock file is tightened, never trusted.
            let _ = std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600));
        }
    }

    use std::fs::TryLockError;
    match file.try_lock() {
        Ok(()) => Ok(MaintenanceLockGuard { file, lock_path }),
        Err(TryLockError::WouldBlock) => Err(PasswordManagerError::MaintenanceLockHeld {
            lock_path: lock_path.to_string_lossy().to_string(),
        }),
        Err(TryLockError::Error(e)) => Err(PasswordManagerError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_path_sits_beside_the_vault() {
        let vault = Path::new("/data/PasswordManager/vault.db");
        assert_eq!(
            maintenance_lock_path(vault),
            Path::new("/data/PasswordManager/vault.db.maint-lock")
        );
    }

    /// Positive + negative mutual exclusion: the first holder wins, a second
    /// acquire is refused while held, and release allows re-acquisition.
    #[test]
    fn exclusive_acquire_refuses_coexistence_and_release_allows() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vault = tmp.path().join("vault.db");

        let guard = try_acquire(&vault).expect("first acquire must succeed");
        assert_eq!(guard.lock_path(), maintenance_lock_path(&vault));

        let err = try_acquire(&vault).expect_err("second acquire must refuse coexistence");
        match &err {
            PasswordManagerError::MaintenanceLockHeld { lock_path } => {
                assert_eq!(
                    Path::new(lock_path),
                    maintenance_lock_path(&vault),
                    "refusal names the lock path"
                );
            }
            other => panic!("expected MaintenanceLockHeld, got {other:?}"),
        }

        drop(guard);
        let again = try_acquire(&vault).expect("release must allow re-acquisition");
        drop(again);
    }

    /// The bootstrap case (no vault yet, no data dir) creates the parent
    /// owner-only so no permission window opens beside the future vault.
    #[cfg(unix)]
    #[test]
    fn bootstrap_creates_owner_only_parent_and_lock_file() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let vault = tmp.path().join("fresh").join("nested").join("vault.db");

        let _guard = try_acquire(&vault).expect("bootstrap acquire must succeed");

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(vault.parent().unwrap()), 0o700, "parent born 0700");
        assert_eq!(
            mode(&maintenance_lock_path(&vault)),
            0o600,
            "lock file born 0600"
        );
    }

    #[cfg(unix)]
    #[test]
    fn loose_preexisting_lock_file_is_tightened_on_acquire() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let vault = tmp.path().join("vault.db");
        let lock_path = maintenance_lock_path(&vault);
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let _guard = try_acquire(&vault).unwrap();
        let mode = std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "loose lock file must be tightened on acquire");
    }
}
