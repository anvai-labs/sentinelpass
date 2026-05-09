//! IPC (Inter-Process Communication) for daemon communication
//!
//! Uses Unix domain sockets on Linux/macOS.
//! Windows uses named pipes with per-user ACLs for OS-level security,
//! plus AES-256-GCM transport encryption as defense-in-depth.
//! Loopback TCP is retained as a legacy fallback for custom `tcp://...` paths.

use crate::external_secret_access::ExternalSecretField;
use crate::{get_config_dir, DatabaseError, PasswordManagerError, Result};
use crate::{AuditEventType, AuditLogger};

#[cfg(windows)]
use aes_gcm::aead::{Aead, KeyInit};
#[cfg(windows)]
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use tracing::warn;
use zeroize::Zeroize;

pub(super) fn log_daemon_audit(logger: Option<&AuditLogger>, event_type: AuditEventType, context: &str) {
    if let Some(lg) = logger {
        if let Err(e) = lg.log(event_type, context) {
            warn!("Failed to write daemon audit event: {}", e);
        }
    }
    // No logger → init failed at startup; that warning was already emitted then.
}

pub(super) fn log_external_secret_audit(
    logger: Option<&AuditLogger>,
    client_id: Option<&str>,
    domain: &str,
    field: Option<&str>,
    purpose: Option<&str>,
    success: bool,
    context: &str,
) {
    log_daemon_audit(
        logger,
        AuditEventType::ExternalSecretAccess {
            client_id: client_id.map(ToString::to_string),
            domain: domain.to_string(),
            field: field.map(ToString::to_string),
            purpose: purpose.map(ToString::to_string),
            success,
        },
        context,
    );
}

/// IPC message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    GetCredential {
        domain: String,
    },
    GetExternalSecret {
        client_id: String,
        domain: String,
        field: ExternalSecretField,
        purpose: Option<String>,
    },
    GetExternalSecretResponse {
        value: Option<String>,
        authorized: bool,
        error: Option<String>,
    },
    GetCredentialResponse {
        username: Option<String>,
        password: Option<String>,
        title: Option<String>,
    },
    ListDomainCredentials {
        base_domain: String,
    },
    ListDomainCredentialsResponse {
        credentials: Vec<CredentialSummary>,
    },
    GetTotpCode {
        domain: String,
    },
    GetTotpCodeResponse {
        code: Option<String>,
        seconds_remaining: Option<u32>,
    },
    SaveCredential {
        domain: String,
        username: String,
        password: String,
        url: Option<String>,
    },
    SaveCredentialResponse {
        success: bool,
        error: Option<String>,
    },
    UnlockVault {
        master_password: String,
    },
    UnlockVaultBiometric {
        prompt_reason: Option<String>,
    },
    UnlockVaultResponse {
        success: bool,
        error: Option<String>,
    },
    CheckVault,
    VaultStatusResponse {
        unlocked: bool,
    },
    LockVault,
    Shutdown,

    // --- Sync messages ---
    /// Trigger a sync cycle now (push + pull).
    SyncNow,
    /// Response to SyncNow.
    SyncNowResponse {
        success: bool,
        pushed: u64,
        pulled: u64,
        error: Option<String>,
    },
    /// Get sync status.
    SyncStatus,
    /// Sync status response.
    SyncStatusResponse {
        enabled: bool,
        device_id: Option<String>,
        device_name: Option<String>,
        relay_url: Option<String>,
        last_sync_at: Option<i64>,
        pending_changes: u64,
    },
}

/// Summary of a credential for listing (excludes password for bulk operations)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub username: String,
    pub title: Option<String>,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct IpcEnvelope {
    token: String,
    message: IpcMessage,
}

#[cfg(windows)]
const WINDOWS_IPC_NONCE_LEN: usize = 12;

#[cfg(windows)]
fn windows_ipc_cipher(auth_token: &str) -> Result<Aes256Gcm> {
    let key_bytes = hex::decode(auth_token).map_err(|e| {
        PasswordManagerError::from(DatabaseError::Ipc(format!(
            "Invalid IPC token encoding for Windows transport encryption: {}",
            e
        )))
    })?;

    if key_bytes.len() != 32 {
        return Err(PasswordManagerError::from(DatabaseError::Ipc(format!(
            "Invalid IPC token length for Windows transport encryption: expected 32 bytes, got {}",
            key_bytes.len()
        ))));
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| {
        PasswordManagerError::from(DatabaseError::Ipc(format!(
            "Failed to initialize Windows IPC transport cipher: {}",
            e
        )))
    })?;

    Ok(cipher)
}

#[cfg(windows)]
pub(super) fn encrypt_windows_ipc_frame(auth_token: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = windows_ipc_cipher(auth_token)?;
    let mut nonce_bytes = [0u8; WINDOWS_IPC_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
        PasswordManagerError::from(DatabaseError::Ipc(format!(
            "Failed to encrypt Windows IPC frame: {}",
            e
        )))
    })?;

    let mut frame = Vec::with_capacity(WINDOWS_IPC_NONCE_LEN + ciphertext.len());
    frame.extend_from_slice(&nonce_bytes);
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

#[cfg(windows)]
pub(super) fn decrypt_windows_ipc_frame(auth_token: &str, frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() <= WINDOWS_IPC_NONCE_LEN {
        return Err(PasswordManagerError::from(DatabaseError::Ipc(
            "Windows IPC frame too short".to_string(),
        )));
    }

    let cipher = windows_ipc_cipher(auth_token)?;
    let nonce = Nonce::from_slice(&frame[..WINDOWS_IPC_NONCE_LEN]);
    let ciphertext = &frame[WINDOWS_IPC_NONCE_LEN..];

    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        PasswordManagerError::from(DatabaseError::Ipc(format!(
            "Failed to decrypt Windows IPC frame: {}",
            e
        )))
    })
}

#[cfg(windows)]
/// Get the default named pipe path for Windows.
pub(super) fn windows_named_pipe_path() -> String {
    // Use a unique pipe name based on the username for multi-user support
    // Format: \\.\pipe\SentinelPass-<username>
    let username = std::env::var("USERNAME")
        .unwrap_or_else(|_| "default".to_string())
        .replace(|c: char| !c.is_alphanumeric(), "");
    format!(r"\\.\pipe\SentinelPass-{}", username)
}

/// IPC server for daemon communication
pub mod client;
pub mod server;
pub use client::IpcClient;
pub use server::IpcServer;

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

/// Read IPC auth token from disk.
pub fn load_ipc_token() -> Result<String> {
    let token_path = default_ipc_token_path();
    let token = std::fs::read_to_string(&token_path)?.trim().to_string();
    if token.is_empty() {
        return Err(PasswordManagerError::from(DatabaseError::Ipc(format!(
            "IPC token file is empty: {:?}",
            token_path
        ))));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_envelope_serialization() {
        let envelope = IpcEnvelope {
            token: "test_token_12345".to_string(),
            message: IpcMessage::GetCredential {
                domain: "example.com".to_string(),
            },
        };

        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: IpcEnvelope = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.token, envelope.token);
        match deserialized.message {
            IpcMessage::GetCredential { domain } => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_credential_summary_serialization() {
        let summary = CredentialSummary {
            username: "user@example.com".to_string(),
            title: Some("Example Account".to_string()),
            domain: "example.com".to_string(),
        };

        let serialized = serde_json::to_string(&summary).unwrap();
        let deserialized: CredentialSummary = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.username, summary.username);
        assert_eq!(deserialized.title, summary.title);
        assert_eq!(deserialized.domain, summary.domain);
    }

    #[test]
    fn test_message_types_serialize_correctly() {
        let messages = vec![
            IpcMessage::GetCredential {
                domain: "example.com".to_string(),
            },
            IpcMessage::GetExternalSecret {
                client_id: "victor".to_string(),
                domain: "anthropic".to_string(),
                field: ExternalSecretField::Password,
                purpose: Some("victor-auth".to_string()),
            },
            IpcMessage::CheckVault,
            IpcMessage::LockVault,
            IpcMessage::Shutdown,
            IpcMessage::ListDomainCredentials {
                base_domain: "example.com".to_string(),
            },
        ];

        for msg in messages {
            let serialized = serde_json::to_string(&msg).unwrap();
            let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

            // Verify round-trip
            match (&msg, &deserialized) {
                (
                    IpcMessage::GetCredential { domain: d1 },
                    IpcMessage::GetCredential { domain: d2 },
                ) => {
                    assert_eq!(d1, d2);
                }
                (
                    IpcMessage::GetExternalSecret {
                        client_id: c1,
                        domain: d1,
                        field: f1,
                        purpose: p1,
                    },
                    IpcMessage::GetExternalSecret {
                        client_id: c2,
                        domain: d2,
                        field: f2,
                        purpose: p2,
                    },
                ) => {
                    assert_eq!(c1, c2);
                    assert_eq!(d1, d2);
                    assert_eq!(f1, f2);
                    assert_eq!(p1, p2);
                }
                (
                    IpcMessage::ListDomainCredentials { base_domain: b1 },
                    IpcMessage::ListDomainCredentials { base_domain: b2 },
                ) => {
                    assert_eq!(b1, b2);
                }
                (IpcMessage::CheckVault, IpcMessage::CheckVault) => {}
                (IpcMessage::LockVault, IpcMessage::LockVault) => {}
                (IpcMessage::Shutdown, IpcMessage::Shutdown) => {}
                _ => panic!("Message type mismatch during round-trip"),
            }
        }
    }

    #[test]
    fn test_get_credential_response_serialization() {
        let response = IpcMessage::GetCredentialResponse {
            username: Some("user@example.com".to_string()),
            password: Some("password123".to_string()),
            title: Some("Example".to_string()),
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::GetCredentialResponse {
                username,
                password,
                title,
            } => {
                assert_eq!(username, Some("user@example.com".to_string()));
                assert_eq!(password, Some("password123".to_string()));
                assert_eq!(title, Some("Example".to_string()));
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_get_external_secret_response_serialization() {
        let response = IpcMessage::GetExternalSecretResponse {
            value: Some("secret-value".to_string()),
            authorized: true,
            error: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::GetExternalSecretResponse {
                value,
                authorized,
                error,
            } => {
                assert_eq!(value, Some("secret-value".to_string()));
                assert!(authorized);
                assert_eq!(error, None);
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn daemon_ipc_external_secret_lookup_requires_victor_allowlist() {
        use crate::{
            CredentialType, Entry, ExternalSecretAllowlist, ExternalSecretField, VaultManager,
        };
        use crate::daemon::DaemonVault;
        use chrono::Utc;
        use std::sync::Arc;
        use tokio::time::{sleep, Duration};

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let short_suffix = &suffix[..12];
        let vault_path = std::env::temp_dir().join(format!("sentinelpass_ipc_{short_suffix}.db"));
        let socket_path = PathBuf::from(format!("/tmp/sp-{short_suffix}.sock"));
        let allowlist_path =
            std::env::temp_dir().join(format!("sentinelpass_ipc_allowlist_{short_suffix}.json"));
        let password = b"test_password_123!";
        let auth_token = format!("test-token-{short_suffix}");

        let vault = VaultManager::create(&vault_path, password).unwrap();
        vault
            .add_entry(&Entry {
                entry_id: None,
                title: "Anthropic API".to_string(),
                username: "anthropic".to_string(),
                password: "sk-ant-test".to_string().into(),
                url: Some("anthropic".to_string()),
                notes: None,
                credential_type: CredentialType::ApiKey,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .unwrap();
        vault
            .add_entry(&Entry {
                entry_id: None,
                title: "Example Passkey".to_string(),
                username: "user@example.com".to_string(),
                password: "passkey-ref:example.com:user@example.com".to_string().into(),
                url: Some("https://example.com".to_string()),
                notes: Some("Reference only; no WebAuthn private key material".to_string()),
                credential_type: CredentialType::PasskeyReference,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .unwrap();
        drop(vault);

        let mut allowlist = ExternalSecretAllowlist::default();
        allowlist
            .allow("victor", "anthropic", ExternalSecretField::Password)
            .unwrap();
        allowlist
            .allow("victor", "example.com", ExternalSecretField::Password)
            .unwrap();
        allowlist.save_to_path(&allowlist_path).unwrap();

        let daemon_vault = Arc::new(DaemonVault::new(Some(vault_path.clone()), 300).unwrap());
        daemon_vault.unlock(password).await.unwrap();

        let server = Arc::new(IpcServer::new_with_allowlist_path(
            socket_path.clone(),
            daemon_vault,
            auth_token.clone(),
            allowlist_path.clone(),
        ));
        let server_task = tokio::spawn({
            let server = server.clone();
            async move { server.run().await }
        });

        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            assert!(
                !server_task.is_finished(),
                "IPC server task exited before creating socket"
            );
            sleep(Duration::from_millis(10)).await;
        }
        assert!(socket_path.exists(), "IPC server did not create socket");

        let client = IpcClient::new_with_token(socket_path.clone(), auth_token);
        let response = client
            .send(IpcMessage::GetExternalSecret {
                client_id: "victor".to_string(),
                domain: "anthropic".to_string(),
                field: ExternalSecretField::Password,
                purpose: Some("victor-auth".to_string()),
            })
            .await
            .unwrap();
        match response {
            IpcMessage::GetExternalSecretResponse {
                value,
                authorized: true,
                error: None,
            } => assert_eq!(value, Some("sk-ant-test".to_string())),
            other => panic!("unexpected authorized lookup response: {:?}", other),
        }

        let response = client
            .send(IpcMessage::GetExternalSecret {
                client_id: "victor".to_string(),
                domain: "anthropic".to_string(),
                field: ExternalSecretField::Username,
                purpose: Some("victor-auth".to_string()),
            })
            .await
            .unwrap();
        match response {
            IpcMessage::GetExternalSecretResponse {
                value: None,
                authorized: false,
                error: Some(error),
            } => assert!(error.contains("not authorized")),
            other => panic!("unexpected denied lookup response: {:?}", other),
        }

        let response = client
            .send(IpcMessage::GetExternalSecret {
                client_id: "victor".to_string(),
                domain: "example.com".to_string(),
                field: ExternalSecretField::Password,
                purpose: Some("victor-auth".to_string()),
            })
            .await
            .unwrap();
        match response {
            IpcMessage::GetExternalSecretResponse {
                value: None,
                authorized: true,
                error: None,
            } => {}
            other => panic!("unexpected passkey lookup response: {:?}", other),
        }

        server_task.abort();
        let _ = std::fs::remove_file(socket_path);
        let _ = std::fs::remove_file(allowlist_path);
        let _ = std::fs::remove_file(vault_path);
    }

    #[test]
    fn test_list_domain_credentials_response_serialization() {
        let credentials = vec![
            CredentialSummary {
                username: "user1@example.com".to_string(),
                title: Some("Account 1".to_string()),
                domain: "example.com".to_string(),
            },
            CredentialSummary {
                username: "user2@example.com".to_string(),
                title: Some("Account 2".to_string()),
                domain: "example.com".to_string(),
            },
        ];

        let response = IpcMessage::ListDomainCredentialsResponse {
            credentials: credentials.clone(),
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::ListDomainCredentialsResponse {
                credentials: decoded,
            } => {
                assert_eq!(decoded.len(), 2);
                assert_eq!(decoded[0].username, "user1@example.com");
                assert_eq!(decoded[1].username, "user2@example.com");
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_save_credential_response_serialization() {
        let response = IpcMessage::SaveCredentialResponse {
            success: true,
            error: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::SaveCredentialResponse { success, error } => {
                assert!(success);
                assert!(error.is_none());
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_save_credential_error_response_serialization() {
        let response = IpcMessage::SaveCredentialResponse {
            success: false,
            error: Some("Vault is locked".to_string()),
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::SaveCredentialResponse { success, error } => {
                assert!(!success);
                assert_eq!(error, Some("Vault is locked".to_string()));
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_unlock_vault_response_serialization() {
        let response = IpcMessage::UnlockVaultResponse {
            success: true,
            error: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::UnlockVaultResponse { success, error } => {
                assert!(success);
                assert!(error.is_none());
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_vault_status_response_serialization() {
        let response = IpcMessage::VaultStatusResponse { unlocked: true };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::VaultStatusResponse { unlocked } => {
                assert!(unlocked);
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_totp_response_serialization() {
        let response = IpcMessage::GetTotpCodeResponse {
            code: Some("123456".to_string()),
            seconds_remaining: Some(30),
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::GetTotpCodeResponse {
                code,
                seconds_remaining,
            } => {
                assert_eq!(code, Some("123456".to_string()));
                assert_eq!(seconds_remaining, Some(30));
            }
            _ => panic!("Wrong response type"),
        }
    }

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

    #[cfg(windows)]
    #[test]
    fn test_windows_named_pipe_path_format() {
        let pipe_path = windows_named_pipe_path();

        assert!(pipe_path.contains("\\\\.\\pipe\\"));
        assert!(pipe_path.contains("SentinelPass"));
    }

    #[test]
    fn test_save_credential_message_serialization() {
        let msg = IpcMessage::SaveCredential {
            domain: "example.com".to_string(),
            username: "user@example.com".to_string(),
            password: "secure_password".to_string(),
            url: Some("https://example.com".to_string()),
        };

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::SaveCredential {
                domain,
                username,
                password,
                url,
            } => {
                assert_eq!(domain, "example.com");
                assert_eq!(username, "user@example.com");
                assert_eq!(password, "secure_password");
                assert_eq!(url, Some("https://example.com".to_string()));
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_unlock_vault_message_serialization() {
        let msg = IpcMessage::UnlockVault {
            master_password: "test_password".to_string(),
        };

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::UnlockVault { master_password } => {
                assert_eq!(master_password, "test_password");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_unlock_vault_biometric_message_serialization() {
        let msg = IpcMessage::UnlockVaultBiometric {
            prompt_reason: Some("Authenticate to unlock".to_string()),
        };

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::UnlockVaultBiometric { prompt_reason } => {
                assert_eq!(prompt_reason, Some("Authenticate to unlock".to_string()));
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_empty_credential_list_serialization() {
        let response = IpcMessage::ListDomainCredentialsResponse {
            credentials: vec![],
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::ListDomainCredentialsResponse { credentials } => {
                assert!(credentials.is_empty());
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_credential_summary_without_title() {
        let summary = CredentialSummary {
            username: "user@example.com".to_string(),
            title: None,
            domain: "example.com".to_string(),
        };

        let serialized = serde_json::to_string(&summary).unwrap();
        let deserialized: CredentialSummary = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.username, summary.username);
        assert_eq!(deserialized.title, None);
        assert_eq!(deserialized.domain, summary.domain);
    }

    #[test]
    fn test_get_totp_code_message_serialization() {
        let msg = IpcMessage::GetTotpCode {
            domain: "example.com".to_string(),
        };

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::GetTotpCode { domain } => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_sync_status_message_serialization() {
        let msg = IpcMessage::SyncStatus;

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::SyncStatus => {}
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_sync_status_response_serialization() {
        let response = IpcMessage::SyncStatusResponse {
            enabled: true,
            device_id: Some("device-123".to_string()),
            device_name: Some("Test Device".to_string()),
            relay_url: Some("https://relay.example.com".to_string()),
            last_sync_at: Some(1700000000),
            pending_changes: 5,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            IpcMessage::SyncStatusResponse {
                enabled,
                device_id,
                device_name,
                relay_url,
                last_sync_at,
                pending_changes,
            } => {
                assert!(enabled);
                assert_eq!(device_id, Some("device-123".to_string()));
                assert_eq!(device_name, Some("Test Device".to_string()));
                assert_eq!(relay_url, Some("https://relay.example.com".to_string()));
                assert_eq!(last_sync_at, Some(1700000000));
                assert_eq!(pending_changes, 5);
            }
            _ => panic!("Wrong response type"),
        }
    }
}
