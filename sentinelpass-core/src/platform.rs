//! Platform-specific utilities for cross-platform support

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Errors raised while validating a sensitive file's ownership, type, or
/// permissions (WBS-412 / WBS-413, SR-DATA-003 / TD-ROB-09).
///
/// The type is the enforcement contract: callers convert it into
/// [`crate::PasswordManagerError`] at the boundary via [`From`], but tests
/// and callers can match on the specific variant.
#[derive(Debug, Error)]
pub enum SensitivePathError {
    /// The path is a symlink. Sensitive files must never be followed through
    /// a symlink: a same-host attacker who can create a symlink at the path
    /// could otherwise redirect reads/writes to a file they control.
    #[error(
        "sensitive path {path} is a symlink; refusing (possible symlink swap). \
         Remove the symlink and let the application recreate the file"
    )]
    Symlink { path: PathBuf },

    /// The path exists but is not a regular file (directory, socket, fifo,
    /// device).
    #[error("sensitive path {path} is not a regular file; refusing")]
    NotRegularFile { path: PathBuf },

    /// (Unix) The file is owned by a different uid than the current user.
    #[error(
        "sensitive path {path} is owned by uid {owner} but this process runs \
         as uid {expected}; refusing"
    )]
    ForeignOwner {
        path: PathBuf,
        owner: u32,
        expected: u32,
    },

    /// (Unix) Group or world permission bits are set on a file that must be
    /// owner-only (0600).
    #[error(
        "sensitive path {path} has permissive mode {actual:#06o} (group/world \
         bits set); owner-only mode 0600 is required"
    )]
    LooseMode { path: PathBuf, actual: u32 },

    /// The path could not be inspected (missing, or stat failed).
    #[error("sensitive path {path} could not be inspected: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl From<SensitivePathError> for crate::PasswordManagerError {
    fn from(e: SensitivePathError) -> Self {
        crate::PasswordManagerError::InvalidInput(e.to_string())
    }
}

/// Policy for how a loose (group/world-readable) mode is handled at open.
///
/// Chosen policy (WBS-412, documented decision):
/// - [`OwnerOnlyPolicy::Refuse`] — the **vault database**: a vault file with
///   group/world read is refused outright with a remediation hint. The vault
///   db is the crown jewel; silent repair would launder an attacker-loosened
///   state without the user ever learning about it.
/// - [`OwnerOnlyPolicy::WarnAndRepair`] — every other sensitive file (IPC
///   token, epoch sidecar, grants, exports): warn and tighten to 0600.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerOnlyPolicy {
    /// Refuse the operation if group/world bits are set.
    Refuse,
    /// Log a warning and tighten the mode to owner-only.
    WarnAndRepair,
}

/// (Unix) Current effective uid; `None` cannot occur on Unix in practice but
/// keeps the non-Unix build trivially correct.
#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: geteuid is always safe to call and cannot fail.
    unsafe { libc::geteuid() }
}

/// Set an explicit owner-only mode on a freshly created sensitive file
/// (0600) or directory (0700).
///
/// Unix-only: on other platforms this is a no-op — Windows files inherit the
/// user-profile DACL (owner + SYSTEM + Administrators), which is the same
/// mechanism the daemon's named-pipe transport uses for its per-user ACL
/// (`daemon/transport/windows.rs`). See docs/SECURITY_STATUS_MATRIX.md.
pub fn set_owner_only_mode(path: &Path, is_dir: bool) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_dir { 0o700 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, is_dir);
        Ok(())
    }
}

/// Verify that a sensitive path has an owner-only mode.
///
/// Returns the current (low 12 bits) mode on Unix. Errors with
/// [`SensitivePathError::LooseMode`] when group or world bits are set. On
/// non-Unix platforms returns `Ok(0)`: POSIX modes do not exist there and
/// access control is inherited from the user profile (documented residual).
pub fn verify_owner_only_mode(path: &Path) -> Result<u32, SensitivePathError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| SensitivePathError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(SensitivePathError::LooseMode {
                path: path.to_path_buf(),
                actual: mode,
            });
        }
        Ok(mode)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(0)
    }
}

/// Validate a sensitive path for open/create: not a symlink, a regular file,
/// owned by the current user (Unix), and owner-only per `policy`.
///
/// Symlink, type, and ownership violations are ALWAYS refused regardless of
/// policy — only the mode check is policy-dependent.
pub fn validate_sensitive_path(
    path: &Path,
    policy: OwnerOnlyPolicy,
) -> Result<(), SensitivePathError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| SensitivePathError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    if meta.file_type().is_symlink() {
        return Err(SensitivePathError::Symlink {
            path: path.to_path_buf(),
        });
    }
    if !meta.is_file() {
        return Err(SensitivePathError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        // Skip the ownership check when running as root: root reads files of
        // any owner and st_uid comparisons would be meaningless (and are
        // untestable in CI, which runs unprivileged).
        if current_uid() != 0 {
            let owner = meta.uid();
            if owner != current_uid() {
                return Err(SensitivePathError::ForeignOwner {
                    path: path.to_path_buf(),
                    owner,
                    expected: current_uid(),
                });
            }
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return match policy {
                OwnerOnlyPolicy::Refuse => Err(SensitivePathError::LooseMode {
                    path: path.to_path_buf(),
                    actual: mode,
                }),
                OwnerOnlyPolicy::WarnAndRepair => {
                    tracing::warn!(
                        "sensitive file {} had permissive mode {mode:#06o}; tightening to 0600",
                        path.display()
                    );
                    set_owner_only_mode(path, false).map_err(|e| SensitivePathError::Io {
                        path: path.to_path_buf(),
                        source: e,
                    })
                }
            };
        }
    }

    #[cfg(not(unix))]
    {
        let _ = policy;
    }

    Ok(())
}

/// Warn (never fail, never chmod) when the parent directory of a sensitive
/// path is group/world-accessible.
///
/// Deliberately does NOT tighten or refuse: the parent may be a user-chosen
/// directory the app does not own (e.g. a vault at `/tmp/x.db` — chmod'ing
/// `/tmp` would damage the system). Directories the app itself creates get
/// 0700 at creation via [`create_private_dir`].
pub fn warn_on_loose_parent_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(parent) = path.parent() {
            if let Ok(meta) = std::fs::metadata(parent) {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        "parent directory {} of sensitive file {} is group/world-accessible \
                         (mode {mode:#06o}); expected owner-only 0700",
                        parent.display(),
                        path.display()
                    );
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Create a directory (and parents) with an explicit owner-only mode (0700).
///
/// `create_dir_all` applies the process umask (typically 0755); this helper
/// tightens the leaf directory afterwards so sensitive-file directories are
/// owner-only from creation.
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    set_owner_only_mode(path, true)
}

/// Create (or truncate) a sensitive file owner-only from birth (WBS-412).
///
/// - Refuses a symlink at `path` with [`SensitivePathError::Symlink`]:
///   plaintext-sensitive content must never be written through a link an
///   attacker may have planted at a guessable path.
/// - On Unix the file is created with mode 0600 (no umask-exposed window);
///   a pre-existing file is tightened explicitly, since opening an existing
///   file keeps its old mode.
/// - On non-Unix, creation is a plain open: files inherit the user-profile
///   DACL (documented Windows story — same mechanism as the daemon's
///   named-pipe per-user ACL).
pub fn create_owner_only_file(path: &Path) -> Result<std::fs::File, SensitivePathError> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(SensitivePathError::Symlink {
                path: path.to_path_buf(),
            });
        }
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|e| SensitivePathError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| SensitivePathError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;
    }

    Ok(file)
}

/// Get the platform-specific data directory for storing application data
///
/// Returns:
/// - Windows: %APPDATA%\PasswordManager
/// - macOS: ~/Library/Application Support/PasswordManager
/// - Linux/Other: ~/.config/passwordmanager
pub fn get_data_dir() -> PathBuf {
    let base = dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .or_else(|| dirs::home_dir().map(|h| h.join(".data")))
        .unwrap_or_else(|| PathBuf::from("."));

    base.join("PasswordManager")
}

/// Get the platform-specific config directory
///
/// Returns:
/// - Windows: %APPDATA%\PasswordManager
/// - macOS: ~/Library/Application Support/PasswordManager
/// - Linux/Other: ~/.config/passwordmanager
pub fn get_config_dir() -> PathBuf {
    let base = dirs::config_dir()
        .or_else(dirs::data_dir)
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));

    base.join("PasswordManager")
}

/// Get the default vault database path
pub fn get_default_vault_path() -> PathBuf {
    get_data_dir().join("vault.db")
}

/// Ensure the audit log directory exists, creating it owner-only (0700 on
/// Unix) when necessary (WBS-412).
///
/// `audit.rs` owns the logger itself; this call-site helper keeps the
/// directory hardening next to the other directory helpers without touching
/// that file. On Unix, an owner-only directory also shields the audit log
/// FILE from other users (path traversal requires +x on every parent).
pub fn ensure_audit_log_dir() -> std::io::Result<PathBuf> {
    let dir = crate::audit::get_audit_log_dir();
    create_private_dir(&dir)?;
    Ok(dir)
}

/// Get the installation directory for binaries
///
/// Returns different paths based on platform:
/// - Windows: C:\Program Files\PasswordManager
/// - macOS: /Applications/PasswordManager
/// - Linux: /opt/passwordmanager
pub fn get_install_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        PathBuf::from(r"C:\Program Files\PasswordManager")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Applications/PasswordManager")
    } else {
        PathBuf::from("/opt/passwordmanager")
    }
}

/// Get Chrome's native messaging hosts directory
///
/// Returns different paths based on platform:
/// - Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Native Messaging Hosts
/// - macOS: ~/Library/Application Support/Google/Chrome/NativeMessagingHosts
/// - Linux: ~/.config/google-chrome/NativeMessagingHosts
pub fn get_chrome_native_messaging_dir() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        // Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Native Messaging Hosts
        std::env::var("LOCALAPPDATA").ok().map(|p| {
            PathBuf::from(p)
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("Native Messaging Hosts")
        })
    } else if cfg!(target_os = "macos") {
        // macOS: ~/Library/Application Support/Google/Chrome/NativeMessagingHosts
        dirs::home_dir().map(|h| {
            h.join("Library")
                .join("Application Support")
                .join("Google")
                .join("Chrome")
                .join("NativeMessagingHosts")
        })
    } else {
        // Linux: ~/.config/google-chrome/NativeMessagingHosts
        dirs::home_dir().map(|h| {
            h.join(".config")
                .join("google-chrome")
                .join("NativeMessagingHosts")
        })
    }
}

/// Get the native messaging host manifest path
pub fn get_native_messaging_manifest_path() -> PathBuf {
    get_install_dir().join("com.passwordmanager.host.json")
}

/// Ensure the data directory exists, creating it if necessary
///
/// Created owner-only (0700 on Unix) — it holds the vault database and the
/// epoch sidecar (WBS-412).
pub fn ensure_data_dir() -> std::io::Result<PathBuf> {
    let dir = get_data_dir();
    create_private_dir(&dir)?;
    Ok(dir)
}

/// Ensure the config directory exists, creating it if necessary
///
/// Created owner-only (0700 on Unix) — it holds the IPC auth token and the
/// external-secret grants file (WBS-412).
pub fn ensure_config_dir() -> std::io::Result<PathBuf> {
    let dir = get_config_dir();
    create_private_dir(&dir)?;
    Ok(dir)
}

/// Get the binary name for the current platform
///
/// Returns the name with .exe extension on Windows, without on Unix
pub fn get_binary_name(base: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{}.exe", base)
    } else {
        base.to_string()
    }
}

/// Get current platform as a string
pub fn get_platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

/// Get current architecture as a string
pub fn get_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_data_dir() {
        let dir = get_data_dir();
        // The directory should end with PasswordManager
        assert!(dir.to_string_lossy().ends_with("PasswordManager"));
    }

    #[test]
    fn test_get_config_dir() {
        let dir = get_config_dir();
        // The directory should end with PasswordManager
        assert!(dir.to_string_lossy().ends_with("PasswordManager"));
    }

    #[test]
    fn test_get_default_vault_path() {
        let path = get_default_vault_path();
        // The path should end with vault.db
        assert!(path.to_string_lossy().ends_with("vault.db"));
    }

    #[test]
    fn test_get_binary_name() {
        let cli_name = get_binary_name("pm-cli");
        let host_name = get_binary_name("pm-host");

        // Verify names are not empty
        assert!(!cli_name.is_empty());
        assert!(!host_name.is_empty());

        // On Windows, should have .exe extension
        if cfg!(target_os = "windows") {
            assert!(cli_name.ends_with(".exe"));
            assert!(host_name.ends_with(".exe"));
        } else {
            assert!(!cli_name.ends_with(".exe"));
            assert!(!host_name.ends_with(".exe"));
        }
    }

    #[test]
    fn test_get_platform() {
        let platform = get_platform();
        assert!(!platform.is_empty());
        assert!(
            platform == "windows"
                || platform == "macos"
                || platform == "linux"
                || platform == "unknown"
        );
    }

    #[test]
    fn test_get_arch() {
        let arch = get_arch();
        assert!(!arch.is_empty());
    }

    // ---- WBS-412 / WBS-413: sensitive-file mode and type validation ----
    //
    // POSIX modes and uids do not exist on Windows (files there inherit the
    // user-profile DACL; see the module docs on `set_owner_only_mode`), so
    // every mode/uid/symlink-creation test is `#[cfg(unix)]`. A `#[cfg(not(unix))]`
    // test below pins the documented no-op contract so the Windows CI leg
    // still exercises this module.

    #[cfg(unix)]
    #[test]
    fn set_and_verify_owner_only_mode_roundtrip() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("secret.bin");
        std::fs::write(&file, b"data").unwrap();

        // A plain fs::write honors the umask (typically 0644) — verify flags it.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = verify_owner_only_mode(&file).unwrap_err();
        assert!(
            matches!(err, SensitivePathError::LooseMode { actual: 0o644, .. }),
            "expected LooseMode, got: {err:?}"
        );

        set_owner_only_mode(&file, false).unwrap();
        assert_eq!(verify_owner_only_mode(&file).unwrap(), 0o600);
        assert!(validate_sensitive_path(&file, OwnerOnlyPolicy::Refuse).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn create_private_dir_sets_0700() {
        let outer = tempfile::TempDir::new().unwrap();
        let dir = outer.path().join("nested").join("private");
        create_private_dir(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn validate_sensitive_path_rejects_symlink() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("target.bin");
        std::fs::write(&target, b"data").unwrap();
        let link = dir.path().join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = validate_sensitive_path(&link, OwnerOnlyPolicy::Refuse).unwrap_err();
        assert!(
            matches!(err, SensitivePathError::Symlink { .. }),
            "expected Symlink, got: {err:?}"
        );
        // Symlinks are refused under BOTH policies — warn-and-repair must not
        // follow the link to "tighten" the attacker's target either.
        assert!(validate_sensitive_path(&link, OwnerOnlyPolicy::WarnAndRepair).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn validate_sensitive_path_rejects_non_regular_file() {
        let dir = tempfile::TempDir::new().unwrap();
        // A directory at the sensitive path is not a regular file.
        let err = validate_sensitive_path(dir.path(), OwnerOnlyPolicy::Refuse).unwrap_err();
        assert!(
            matches!(err, SensitivePathError::NotRegularFile { .. }),
            "expected NotRegularFile, got: {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn loose_mode_refuses_or_repairs_by_policy() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();

        // Refuse policy: error, file untouched.
        let refused = dir.path().join("refused.bin");
        std::fs::write(&refused, b"data").unwrap();
        std::fs::set_permissions(&refused, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = validate_sensitive_path(&refused, OwnerOnlyPolicy::Refuse).unwrap_err();
        assert!(matches!(
            err,
            SensitivePathError::LooseMode { actual: 0o644, .. }
        ));
        assert_eq!(
            std::fs::metadata(&refused).unwrap().permissions().mode() & 0o777,
            0o644,
            "Refuse policy must not modify the file"
        );

        // WarnAndRepair policy: tightened to 0600.
        let repaired = dir.path().join("repaired.bin");
        std::fs::write(&repaired, b"data").unwrap();
        std::fs::set_permissions(&repaired, std::fs::Permissions::from_mode(0o644)).unwrap();
        validate_sensitive_path(&repaired, OwnerOnlyPolicy::WarnAndRepair).unwrap();
        assert_eq!(
            std::fs::metadata(&repaired).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn warn_on_loose_parent_dir_is_advisory_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let loose_parent = dir.path().join("loose");
        std::fs::create_dir_all(&loose_parent).unwrap();
        std::fs::set_permissions(&loose_parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = loose_parent.join("vault.db");
        std::fs::write(&file, b"data").unwrap();

        // Must neither fail nor touch the parent's mode (a vault at
        // /tmp/x.db must not cause chmod 0700 /tmp).
        warn_on_loose_parent_dir(&file);
        assert_eq!(
            std::fs::metadata(&loose_parent)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    // The ForeignOwner check (st_uid != euid) is implemented but not
    // asserted here: creating a foreign-owned file requires root, and CI
    // runs unprivileged (documented in the WBS-412 report). The check is
    // additionally skipped for euid 0, where st_uid comparisons are
    // meaningless.

    #[test]
    fn verify_owner_only_mode_is_documented_noop_without_posix_modes() {
        // On non-Unix there is no POSIX mode: verification reports Ok(0)
        // ("no POSIX mode to enforce") and the Windows ACL story relies on
        // user-profile inheritance. On Unix this asserts an owner-only file
        // verifies cleanly.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("f.bin");
        std::fs::write(&file, b"data").unwrap();
        set_owner_only_mode(&file, false).unwrap();
        #[cfg(unix)]
        assert_eq!(verify_owner_only_mode(&file).unwrap(), 0o600);
        #[cfg(not(unix))]
        assert_eq!(verify_owner_only_mode(&file).unwrap(), 0);
    }
}
