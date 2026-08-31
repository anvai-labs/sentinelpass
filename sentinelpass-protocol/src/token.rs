//! IPC auth token file management.

use crate::paths::default_ipc_token_path;
use crate::{ProtocolError, Result};
use rand::{rngs::OsRng, RngCore};
use std::io::Write;
use zeroize::Zeroize;

/// Read IPC auth token from disk.
pub fn load_ipc_token() -> Result<String> {
    let token_path = default_ipc_token_path();
    let token = std::fs::read_to_string(&token_path)?.trim().to_string();
    if token.is_empty() {
        return Err(ProtocolError::Ipc(format!(
            "IPC token file is empty: {:?}",
            token_path
        )));
    }
    Ok(token)
}

/// Load existing IPC auth token or create one if it does not exist.
pub fn load_or_create_ipc_token() -> Result<String> {
    let token_path = default_ipc_token_path();

    if let Some(parent) = token_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if token_path.exists() {
        return load_ipc_token();
    }

    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    token_bytes.zeroize();

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&token_path)?;
    file.write_all(token.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(token)
}
