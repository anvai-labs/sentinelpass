//! Windows named-pipe frame encryption (AES-256-GCM, token-derived key).
//!
//! The frame format is fixed: `nonce (12 bytes) || ciphertext || tag`.
//! Changing it would break mixed-version daemon/client fleets.

use crate::error::{ProtocolError, Result};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};

const WINDOWS_IPC_NONCE_LEN: usize = 12;

fn windows_ipc_cipher(auth_token: &str) -> Result<Aes256Gcm> {
    let key_bytes = hex::decode(auth_token).map_err(|e| {
        ProtocolError::Ipc(format!(
            "Invalid IPC token encoding for Windows transport encryption: {}",
            e
        ))
    })?;

    if key_bytes.len() != 32 {
        return Err(ProtocolError::Ipc(format!(
            "Invalid IPC token length for Windows transport encryption: expected 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| {
        ProtocolError::Ipc(format!(
            "Failed to initialize Windows IPC transport cipher: {}",
            e
        ))
    })?;

    Ok(cipher)
}

pub fn encrypt_windows_ipc_frame(auth_token: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = windows_ipc_cipher(auth_token)?;
    let mut nonce_bytes = [0u8; WINDOWS_IPC_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| ProtocolError::Ipc(format!("Failed to encrypt Windows IPC frame: {}", e)))?;

    let mut frame = Vec::with_capacity(WINDOWS_IPC_NONCE_LEN + ciphertext.len());
    frame.extend_from_slice(&nonce_bytes);
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

pub fn decrypt_windows_ipc_frame(auth_token: &str, frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() <= WINDOWS_IPC_NONCE_LEN {
        return Err(ProtocolError::Ipc(
            "Windows IPC frame too short".to_string(),
        ));
    }

    let cipher = windows_ipc_cipher(auth_token)?;
    let nonce = Nonce::from_slice(&frame[..WINDOWS_IPC_NONCE_LEN]);
    let ciphertext = &frame[WINDOWS_IPC_NONCE_LEN..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| ProtocolError::Ipc(format!("Failed to decrypt Windows IPC frame: {}", e)))
}

/// Get the default named pipe path for Windows.
pub fn windows_named_pipe_path() -> String {
    // Use a unique pipe name based on the username for multi-user support
    // Format: \\.\pipe\SentinelPass-<username>
    let username = std::env::var("USERNAME")
        .unwrap_or_else(|_| "default".to_string())
        .replace(|c: char| !c.is_alphanumeric(), "");
    format!(r"\\.\pipe\SentinelPass-{}", username)
}

#[cfg(windows)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_named_pipe_path_format() {
        let pipe_path = windows_named_pipe_path();

        assert!(pipe_path.contains("\\\\.\\pipe\\"));
        assert!(pipe_path.contains("SentinelPass"));
    }

    #[test]
    fn frame_crypto_round_trip() {
        let token = hex::encode([7u8; 32]);
        let plaintext = b"hello frame";
        let encrypted = encrypt_windows_ipc_frame(&token, plaintext).unwrap();
        let decrypted = decrypt_windows_ipc_frame(&token, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
