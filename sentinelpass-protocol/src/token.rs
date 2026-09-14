//! IPC auth token file management.
//!
//! WBS-412 (SR-DATA-003): the token is a bearer credential for the whole
//! IPC surface, so it is created with an explicit owner-only mode (0600 on
//! Unix, no umask-exposed window), inside an owner-only directory created on
//! demand. A loose mode found at load is warned about and tightened
//! (warn-level policy: refusing daemon startup would turn a loose mode into
//! a local DoS; the owner-only parent directory is the primary guard). The
//! core helper mirrors `sentinelpass_core::platform` but is duplicated here
//! because the protocol crate must not depend on core.

use crate::paths::default_ipc_token_path;
use crate::{ProtocolError, Result};
use rand::{rngs::OsRng, RngCore};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::warn;
use zeroize::Zeroize;

/// Read IPC auth token from disk.
pub fn load_ipc_token() -> Result<String> {
    load_ipc_token_from(&default_ipc_token_path())
}

/// Path of the native-host installation capability secret (WBS-505):
/// `<config dir>/PasswordManager/native_host.capability`, 0600, provisioned
/// by the daemon. The host reads and presents it; only its hash lives in
/// the daemon's capability store.
pub fn native_host_capability_path() -> PathBuf {
    crate::paths::get_config_dir().join("native_host.capability")
}

/// Load the presented native-host capability secret, if provisioned.
/// `None` = not installed yet (the daemon mints it on its first start).
pub fn load_native_host_capability() -> Option<String> {
    std::fs::read_to_string(native_host_capability_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Path-parameterized variant of [`load_ipc_token`] (used by tests and
/// embedders that keep the token outside the default location).
pub fn load_ipc_token_from(token_path: &Path) -> Result<String> {
    let token = std::fs::read_to_string(token_path)?.trim().to_string();
    if token.is_empty() {
        return Err(ProtocolError::Ipc(format!(
            "IPC token file is empty: {:?}",
            token_path
        )));
    }
    enforce_owner_only(token_path);
    Ok(token)
}

/// Load existing IPC auth token or create one if it does not exist.
pub fn load_or_create_ipc_token() -> Result<String> {
    load_or_create_ipc_token_at(&default_ipc_token_path())
}

/// Path-parameterized variant of [`load_or_create_ipc_token`].
pub fn load_or_create_ipc_token_at(token_path: &Path) -> Result<String> {
    if let Some(parent) = token_path.parent() {
        if !parent.exists() {
            // Directory the daemon is creating: owner-only from birth
            // (WBS-412). A pre-existing parent (user-chosen, or a test
            // tempdir) is never re-chmod'd.
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        } else {
            std::fs::create_dir_all(parent)?;
        }
    }

    if token_path.exists() {
        return load_ipc_token_from(token_path);
    }

    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    token_bytes.zeroize();

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        // Born owner-only: no window where the token exists with umask
        // permissions (WBS-412). The chmod below stays as a backstop.
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(token_path)?;
    file.write_all(token.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(token_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(token)
}

/// Warn about and tighten (best-effort) a token file whose mode is not
/// owner-only. No-op on platforms without POSIX modes (the Windows ACL story
/// relies on user-profile inheritance; see `paths.rs` / the status matrix).
fn enforce_owner_only(token_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let owner_only = std::fs::metadata(token_path)
            .map(|m| m.permissions().mode() & 0o077 == 0)
            .unwrap_or(true); // vanished between read and stat: nothing to tighten
        if !owner_only {
            warn!(
                "IPC token file {:?} is group/world-accessible; tightening to 0600",
                token_path
            );
            let _ = std::fs::set_permissions(token_path, std::fs::Permissions::from_mode(0o600));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = token_path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn created_token_and_parent_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let outer = tempfile::TempDir::new().unwrap();
        let token_path = outer.path().join("cfg").join("ipc.token");

        load_or_create_ipc_token_at(&token_path).unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&token_path), 0o600, "token must be born 0600");
        assert_eq!(
            mode(token_path.parent().unwrap()),
            0o700,
            "created parent dir must be 0700"
        );

        // Round-trip: the same token loads again.
        let again = load_or_create_ipc_token_at(&token_path).unwrap();
        let first = std::fs::read_to_string(&token_path).unwrap();
        assert_eq!(again.trim(), first.trim());
    }

    #[cfg(unix)]
    #[test]
    fn loose_token_mode_is_repaired_on_load() {
        use std::os::unix::fs::PermissionsExt;

        let outer = tempfile::TempDir::new().unwrap();
        let token_path = outer.path().join("ipc.token");
        load_or_create_ipc_token_at(&token_path).unwrap();

        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        load_ipc_token_from(&token_path).unwrap();
        let mode = std::fs::metadata(&token_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "load must tighten a loose token mode");
    }

    // Pre-existing parents are never re-chmod'd (a token stored beside
    // unrelated files must not change their directory's mode).
    #[cfg(unix)]
    #[test]
    fn preexisting_parent_directory_is_left_untouched() {
        use std::os::unix::fs::PermissionsExt;

        let outer = tempfile::TempDir::new().unwrap(); // already exists, 0700
        let token_path = outer.path().join("ipc.token");
        load_or_create_ipc_token_at(&token_path).unwrap();
        // If this ran with an unconditional chmod the assertion below would
        // be trivially true; it guards the else-branch against regressions
        // by asserting nothing changed even with a deliberately looser dir.
        let loose = outer.path().join("loose");
        std::fs::create_dir_all(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        let token_path = loose.join("ipc.token");
        load_or_create_ipc_token_at(&token_path).unwrap();
        let mode = std::fs::metadata(&loose).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "pre-existing parent must stay untouched");
    }
}
