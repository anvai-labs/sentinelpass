//! Platform path helpers for the IPC socket and token file.

use std::path::PathBuf;

/// Directory holding user-level config files (IPC token, grants).
///
/// Mirrors `sentinelpass_core::platform::get_config_dir`; duplicated here so
/// protocol clients do not need the core crate.
pub fn get_config_dir() -> PathBuf {
    let base = dirs::config_dir()
        .or_else(dirs::data_dir)
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));

    base.join("PasswordManager")
}

/// Owner-only runtime directory for the IPC socket (WBS-507).
///
/// `$XDG_RUNTIME_DIR/SentinelPass` when the runtime dir is available, else
/// `<config dir>/runtime` (owner-only). The `/tmp` fallback is REMOVED per
/// ADR-007: a world-traversable socket directory is exactly what the
/// owner-only-directory requirement exists to prevent.
pub fn default_runtime_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        return get_config_dir().join("runtime");
    }
    match std::env::var("XDG_RUNTIME_DIR") {
        Ok(dir) if !dir.trim().is_empty() => PathBuf::from(dir).join("SentinelPass"),
        _ => get_config_dir().join("runtime"),
    }
}

/// Get the default IPC socket path for the platform.
pub fn default_ipc_socket_path() -> PathBuf {
    if cfg!(target_os = "windows") {
        // Windows: per-user named pipe (WBS-508 hardens the server side).
        PathBuf::from(r"\\.\pipe\SentinelPass")
    } else {
        default_runtime_dir().join("sentinelpass.sock")
    }
}

/// Get the default IPC auth token path for the platform
pub fn default_ipc_token_path() -> PathBuf {
    get_config_dir().join("ipc.token")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn test_default_socket_path_unix() {
        let path = default_ipc_socket_path();
        assert!(path.to_string_lossy().ends_with("sentinelpass.sock"));
    }

    #[cfg(windows)]
    #[test]
    fn test_default_socket_path_windows() {
        let path = default_ipc_socket_path();
        assert!(path.to_string_lossy().contains("\\\\.\\pipe\\"));
    }

    /// Env vars are process-global: these two tests mutate
    /// XDG_RUNTIME_DIR and run in parallel by default, so they serialize
    /// on this lock (a race here fails the not-tmp assertion flakily).
    static XDG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// WBS-507: the default socket path uses $XDG_RUNTIME_DIR when present,
    /// nested in the private SentinelPass runtime dir — never bare /tmp.
    #[test]
    fn test_socket_path_with_xdg_runtime_dir() {
        let _guard = XDG_ENV_LOCK.lock().unwrap();
        let custom_runtime = "/tmp/custom_runtime";
        std::env::set_var("XDG_RUNTIME_DIR", custom_runtime);

        let path = default_ipc_socket_path();

        #[cfg(unix)]
        {
            let path_str = path.to_string_lossy();
            assert!(
                path_str.contains(custom_runtime) && path_str.contains("SentinelPass"),
                "default socket must live in the private runtime dir: {path_str}"
            );
        }

        #[cfg(windows)]
        {
            // On Windows, just verify the function runs without error
            let _ = path;
        }

        std::env::remove_var("XDG_RUNTIME_DIR");
    }

    /// WBS-507: the /tmp fallback is REMOVED — with XDG_RUNTIME_DIR unset,
    /// the default falls back to the config dir's private runtime subdir.
    #[test]
    fn test_socket_path_without_xdg_runtime_dir_is_not_tmp() {
        let _guard = XDG_ENV_LOCK.lock().unwrap();
        std::env::remove_var("XDG_RUNTIME_DIR");
        let path = default_ipc_socket_path();
        let path_str = path.to_string_lossy().to_string();

        #[cfg(unix)]
        assert!(
            !path_str.starts_with("/tmp/") && !path_str.starts_with("/private/tmp/"),
            "the /tmp fallback must stay removed: {path_str}"
        );
        assert!(
            path_str.contains("runtime") || path_str.contains("SentinelPass"),
            "default must use the private runtime dir: {path_str}"
        );
    }
}
