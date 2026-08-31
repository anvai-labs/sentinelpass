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

/// Get the default IPC socket path for the platform
pub fn default_ipc_socket_path() -> PathBuf {
    if cfg!(target_os = "windows") {
        // Windows: Use named pipes with per-user ACLs
        // Default to named pipe format; custom tcp://... paths still work as legacy fallback
        PathBuf::from(r"\\.\pipe\SentinelPass")
    } else {
        // Unix: Use Unix domain socket
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());

        PathBuf::from(runtime_dir).join("sentinelpass.sock")
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

    #[test]
    fn test_socket_path_with_xdg_runtime_dir() {
        let custom_runtime = "/tmp/custom_runtime";
        std::env::set_var("XDG_RUNTIME_DIR", custom_runtime);

        let path = default_ipc_socket_path();

        #[cfg(unix)]
        {
            let path_str = path.to_string_lossy();
            assert!(path_str.contains(custom_runtime));
        }

        #[cfg(windows)]
        {
            // On Windows, just verify the function runs without error
            let _ = path;
        }

        std::env::remove_var("XDG_RUNTIME_DIR");
    }
}
