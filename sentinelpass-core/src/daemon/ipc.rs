//! IPC (Inter-Process Communication) for daemon communication
//!
//! Uses Unix domain sockets on Linux/macOS.
//! Windows uses named pipes with per-user ACLs for OS-level security,
//! plus AES-256-GCM transport encryption as defense-in-depth.
//! Loopback TCP is retained as a legacy fallback for custom `tcp://...` paths.

use crate::daemon::transport::{TransportConfig, TransportError};
use crate::daemon::DaemonVault;
use crate::external_secret_access::{ExternalSecretAllowlist, ExternalSecretField};
use crate::{get_config_dir, DatabaseError, PasswordManagerError, Result};
use crate::{AuditEventType, AuditLogger};

#[cfg(unix)]
use crate::daemon::transport::unix::UnixSocketConnection;
#[cfg(unix)]
use crate::daemon::transport::unix::UnixSocketTransport;
#[cfg(windows)]
use crate::daemon::transport::windows::WindowsNamedPipeConnection;
#[cfg(windows)]
use crate::daemon::transport::windows::WindowsNamedPipeTransport;

#[cfg(windows)]
use aes_gcm::aead::{Aead, KeyInit};
#[cfg(windows)]
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use subtle::ConstantTimeEq;
#[allow(unused_imports)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;

fn log_daemon_audit(event_type: AuditEventType, context: &str) {
    match AuditLogger::new(crate::get_audit_log_dir()) {
        Ok(logger) => {
            if let Err(e) = logger.log(event_type, context) {
                warn!("Failed to write daemon audit event: {}", e);
            }
        }
        Err(e) => warn!("Failed to initialize daemon audit logger: {}", e),
    }
}

fn log_external_secret_audit(
    client_id: Option<&str>,
    domain: &str,
    field: Option<&str>,
    purpose: Option<&str>,
    success: bool,
    context: &str,
) {
    log_daemon_audit(
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
struct IpcEnvelope {
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
fn encrypt_windows_ipc_frame(auth_token: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
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
fn decrypt_windows_ipc_frame(auth_token: &str, frame: &[u8]) -> Result<Vec<u8>> {
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
fn windows_named_pipe_path() -> String {
    // Use a unique pipe name based on the username for multi-user support
    // Format: \\.\pipe\SentinelPass-<username>
    let username = std::env::var("USERNAME")
        .unwrap_or_else(|_| "default".to_string())
        .replace(|c: char| !c.is_alphanumeric(), "");
    format!(r"\\.\pipe\SentinelPass-{}", username)
}

/// IPC server for daemon communication
#[allow(dead_code)]
pub struct IpcServer {
    socket_path: PathBuf,
    vault: Arc<DaemonVault>,
    auth_token: String,
    external_secret_allowlist_path: PathBuf,
}

impl IpcServer {
    /// Create a new IPC server
    pub fn new(socket_path: PathBuf, vault: Arc<DaemonVault>, auth_token: String) -> Self {
        Self::new_with_allowlist_path(
            socket_path,
            vault,
            auth_token,
            ExternalSecretAllowlist::default_path(),
        )
    }

    /// Create a new IPC server with an explicit external secret allowlist path.
    pub fn new_with_allowlist_path(
        socket_path: PathBuf,
        vault: Arc<DaemonVault>,
        auth_token: String,
        external_secret_allowlist_path: PathBuf,
    ) -> Self {
        Self {
            socket_path,
            vault,
            auth_token,
            external_secret_allowlist_path,
        }
    }

    /// Start the IPC server
    pub async fn run(&self) -> Result<()> {
        info!("Starting IPC server at {:?}", self.socket_path);

        // Remove existing socket if present
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to remove socket: {}",
                    e
                )))
            })?;
        }

        #[cfg(unix)]
        {
            // Use Unix domain socket transport
            let mut transport = UnixSocketTransport::new(TransportConfig {
                unix_socket_path: Some(self.socket_path.to_string_lossy().to_string()),
                ..Default::default()
            })
            .map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to create transport: {}",
                    e
                )))
            })?;

            transport.bind().map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to bind transport: {}",
                    e
                )))
            })?;

            info!("IPC server listening on {:?}", self.socket_path);

            loop {
                match transport.accept().await {
                    Ok(mut conn) => {
                        debug!("IPC client connected");

                        match conn.read_message().await {
                            Ok(buffer) => match serde_json::from_slice::<IpcEnvelope>(&buffer) {
                                Ok(envelope) => {
                                    if !bool::from(
                                        envelope.token.as_bytes().ct_eq(self.auth_token.as_bytes()),
                                    ) {
                                        warn!("Rejected IPC request with invalid token");
                                        continue;
                                    }
                                    let response = self.handle_message(envelope.message).await;
                                    match serde_json::to_vec(&response) {
                                        Ok(response_bytes) => {
                                            if let Err(e) =
                                                conn.write_message(&response_bytes).await
                                            {
                                                error!("Failed to send response: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to serialize response: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to parse IPC envelope: {}", e);
                                }
                            },
                            Err(TransportError::MessageTooLarge { size, .. }) => {
                                error!("Rejected oversized message: {} bytes", size);
                            }
                            Err(e) => {
                                error!("Failed to read message: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            // Determine if using named pipes or legacy TCP
            let path_str = self.socket_path.to_string_lossy().to_string();
            let use_tcp = path_str.starts_with("tcp://");

            if use_tcp {
                // Legacy TCP fallback for custom tcp://... paths
                use tokio::net::TcpListener;

                let addr_str = path_str.strip_prefix("tcp://").unwrap_or("127.0.0.1:35873");
                info!("IPC server listening on legacy TCP: {}", addr_str);

                let listener = TcpListener::bind(addr_str).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to bind TCP socket: {}",
                        e
                    )))
                })?;

                loop {
                    match listener.accept().await {
                        Ok((mut stream, _addr)) => {
                            debug!("IPC client connected (TCP)");

                            let mut length_buf = [0u8; 4];
                            match stream.read_exact(&mut length_buf).await {
                                Ok(_) => {
                                    let length = u32::from_be_bytes(length_buf) as usize;
                                    if length > 0 && length <= 65536 {
                                        let mut buffer = vec![0u8; length];
                                        match stream.read_exact(&mut buffer).await {
                                            Ok(_) => {
                                                match decrypt_windows_ipc_frame(
                                                    &self.auth_token,
                                                    &buffer,
                                                ) {
                                                    Ok(decrypted) => {
                                                        match serde_json::from_slice::<IpcEnvelope>(
                                                            &decrypted,
                                                        ) {
                                                            Ok(envelope) => {
                                                                if !bool::from(
                                                                    envelope
                                                                        .token
                                                                        .as_bytes()
                                                                        .ct_eq(
                                                                            self.auth_token
                                                                                .as_bytes(),
                                                                        ),
                                                                ) {
                                                                    warn!("Rejected IPC request with invalid token");
                                                                    continue;
                                                                }
                                                                let response = self
                                                                    .handle_message(
                                                                        envelope.message,
                                                                    )
                                                                    .await;
                                                                match serde_json::to_vec(&response) {
                                                                    Ok(response_bytes) => {
                                                                        match encrypt_windows_ipc_frame(
                                                                            &self.auth_token,
                                                                            &response_bytes,
                                                                        ) {
                                                                            Ok(response_frame) => {
                                                                                let response_len =
                                                                                    response_frame.len()
                                                                                        as u32;
                                                                                let _ = stream
                                                                                    .write_all(
                                                                                        &response_len
                                                                                            .to_be_bytes(),
                                                                                    )
                                                                                    .await;
                                                                                let _ = stream
                                                                                    .write_all(
                                                                                        &response_frame,
                                                                                    )
                                                                                    .await;
                                                                                let _ = stream
                                                                                    .flush()
                                                                                    .await;
                                                                            }
                                                                            Err(e) => {
                                                                                error!(
                                                                                    "Failed to encrypt IPC response frame: {}",
                                                                                    e
                                                                                );
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        error!(
                                                                            "Failed to serialize response: {}",
                                                                            e
                                                                        );
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                error!(
                                                                    "Failed to parse IPC envelope: {}",
                                                                    e
                                                                );
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            "Failed to decrypt Windows IPC frame: {}",
                                                            e
                                                        );
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                error!("Failed to read message: {}", e);
                                            }
                                        }
                                    } else {
                                        error!("Invalid message length: {}", length);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to read length: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                }
            } else {
                // Default: Use named pipes with per-user ACLs
                let transport = WindowsNamedPipeTransport::new(TransportConfig {
                    windows_pipe_path: Some(windows_named_pipe_path()),
                    ..Default::default()
                })
                .map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to create transport: {}",
                        e
                    )))
                })?;

                let pipe_name = transport.pipe_name();
                info!("IPC server listening on named pipe: {}", pipe_name);

                loop {
                    // Create the named pipe server
                    let pipe_server = transport.create_server().map_err(|e| {
                        PasswordManagerError::from(DatabaseError::Ipc(format!(
                            "Failed to create named pipe: {}",
                            e
                        )))
                    })?;

                    debug!("Named pipe created, waiting for connection");

                    // Wait for a client to connect
                    match pipe_server.connect().await {
                        Ok(_) => {
                            debug!("IPC client connected (named pipe)");

                            let mut conn = WindowsNamedPipeConnection::from_server(pipe_server);

                            // Read encrypted message
                            match conn.read_message().await {
                                Ok(buffer) => {
                                    // Decrypt the frame
                                    match decrypt_windows_ipc_frame(&self.auth_token, &buffer) {
                                        Ok(decrypted) => {
                                            match serde_json::from_slice::<IpcEnvelope>(&decrypted)
                                            {
                                                Ok(envelope) => {
                                                    if !bool::from(
                                                        envelope
                                                            .token
                                                            .as_bytes()
                                                            .ct_eq(self.auth_token.as_bytes()),
                                                    ) {
                                                        warn!("Rejected IPC request with invalid token");
                                                        let _ = conn.close();
                                                        continue;
                                                    }
                                                    let response =
                                                        self.handle_message(envelope.message).await;
                                                    match serde_json::to_vec(&response) {
                                                        Ok(response_bytes) => {
                                                            match encrypt_windows_ipc_frame(
                                                                &self.auth_token,
                                                                &response_bytes,
                                                            ) {
                                                                Ok(response_frame) => {
                                                                    if let Err(e) = conn
                                                                        .write_message(
                                                                            &response_frame,
                                                                        )
                                                                        .await
                                                                    {
                                                                        error!("Failed to send response: {}", e);
                                                                    }
                                                                }
                                                                Err(e) => {
                                                                    error!("Failed to encrypt IPC response frame: {}", e);
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            error!(
                                                                "Failed to serialize response: {}",
                                                                e
                                                            );
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("Failed to parse IPC envelope: {}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to decrypt Windows IPC frame: {}", e);
                                        }
                                    }
                                }
                                Err(TransportError::MessageTooLarge { size, .. }) => {
                                    error!("Rejected oversized message: {} bytes", size);
                                }
                                Err(e) => {
                                    error!("Failed to read message: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to accept named pipe connection: {}", e);
                        }
                    }

                    // Connection is closed when dropped
                }
            }
        }
    }

    /// Handle an IPC message
    #[allow(dead_code)]
    async fn handle_message(&self, msg: IpcMessage) -> IpcMessage {
        match msg {
            IpcMessage::GetExternalSecret {
                client_id,
                domain,
                field,
                purpose,
            } => {
                debug!(
                    "IPC: GetExternalSecret client='{}' domain='{}' field='{}'",
                    client_id,
                    domain,
                    field.as_str()
                );

                let purpose = purpose.unwrap_or_else(|| "external-secret-access".to_string());
                match ExternalSecretAllowlist::load_from_path(&self.external_secret_allowlist_path)
                {
                    Ok(allowlist) if allowlist.is_allowed(&client_id, &domain, field) => {
                        match self.vault.get_credential(&domain).await {
                            Ok(Some(cred)) => {
                                let value = match field {
                                    ExternalSecretField::Username => Some(cred.username),
                                    ExternalSecretField::Password => Some(cred.password),
                                    ExternalSecretField::Title => Some(cred.title),
                                };
                                log_external_secret_audit(
                                    Some(&client_id),
                                    &domain,
                                    Some(field.as_str()),
                                    Some(&purpose),
                                    value.is_some(),
                                    &format!(
                                        "External secret access granted for client '{}' purpose '{}'",
                                        client_id, purpose
                                    ),
                                );
                                IpcMessage::GetExternalSecretResponse {
                                    value,
                                    authorized: true,
                                    error: None,
                                }
                            }
                            Ok(None) => {
                                log_external_secret_audit(
                                    Some(&client_id),
                                    &domain,
                                    Some(field.as_str()),
                                    Some(&purpose),
                                    false,
                                    &format!(
                                        "External secret access found no credential for client '{}' purpose '{}'",
                                        client_id, purpose
                                    ),
                                );
                                IpcMessage::GetExternalSecretResponse {
                                    value: None,
                                    authorized: true,
                                    error: None,
                                }
                            }
                            Err(e) => {
                                error!("Failed to get external secret: {}", e);
                                log_external_secret_audit(
                                    Some(&client_id),
                                    &domain,
                                    Some(field.as_str()),
                                    Some(&purpose),
                                    false,
                                    &format!(
                                        "External secret access failed for client '{}' purpose '{}'",
                                        client_id, purpose
                                    ),
                                );
                                IpcMessage::GetExternalSecretResponse {
                                    value: None,
                                    authorized: true,
                                    error: Some("Credential lookup failed".to_string()),
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        log_external_secret_audit(
                            Some(&client_id),
                            &domain,
                            Some(field.as_str()),
                            Some(&purpose),
                            false,
                            &format!(
                                "External secret access denied for client '{}' purpose '{}'",
                                client_id, purpose
                            ),
                        );
                        IpcMessage::GetExternalSecretResponse {
                            value: None,
                            authorized: false,
                            error: Some(format!(
                                "Client '{}' is not authorized for {} {}",
                                client_id,
                                domain,
                                field.as_str()
                            )),
                        }
                    }
                    Err(e) => {
                        error!("Failed to load external secret allowlist: {}", e);
                        IpcMessage::GetExternalSecretResponse {
                            value: None,
                            authorized: false,
                            error: Some("Failed to load external secret allowlist".to_string()),
                        }
                    }
                }
            }
            IpcMessage::GetCredential { domain } => {
                debug!("IPC: GetCredential for domain '{}'", domain);

                match self.vault.get_credential(&domain).await {
                    Ok(Some(cred)) => {
                        log_external_secret_audit(
                            None,
                            &domain,
                            None,
                            None,
                            true,
                            "Credential secret retrieved through daemon IPC",
                        );
                        IpcMessage::GetCredentialResponse {
                            username: Some(cred.username),
                            password: Some(cred.password),
                            title: Some(cred.title),
                        }
                    }
                    Ok(None) => {
                        debug!("No credential found for domain '{}'", domain);
                        log_external_secret_audit(
                            None,
                            &domain,
                            None,
                            None,
                            false,
                            "Credential secret lookup through daemon IPC returned no match",
                        );
                        IpcMessage::GetCredentialResponse {
                            username: None,
                            password: None,
                            title: None,
                        }
                    }
                    Err(e) => {
                        error!("Failed to get credential: {}", e);
                        log_external_secret_audit(
                            None,
                            &domain,
                            None,
                            None,
                            false,
                            "Credential secret lookup through daemon IPC failed",
                        );
                        IpcMessage::GetCredentialResponse {
                            username: None,
                            password: None,
                            title: None,
                        }
                    }
                }
            }
            IpcMessage::ListDomainCredentials { base_domain } => {
                debug!(
                    "IPC: ListDomainCredentials for base domain '{}'",
                    base_domain
                );

                match self.vault.list_domain_credentials(&base_domain).await {
                    Ok(credentials) => {
                        let summaries: Vec<CredentialSummary> = credentials
                            .into_iter()
                            .map(|cred| CredentialSummary {
                                username: cred.username,
                                title: Some(cred.title),
                                domain: cred.domain,
                            })
                            .collect();
                        IpcMessage::ListDomainCredentialsResponse {
                            credentials: summaries,
                        }
                    }
                    Err(e) => {
                        error!("Failed to list domain credentials: {}", e);
                        IpcMessage::ListDomainCredentialsResponse {
                            credentials: Vec::new(),
                        }
                    }
                }
            }
            IpcMessage::GetTotpCode { domain } => {
                debug!("IPC: GetTotpCode for domain '{}'", domain);

                match self.vault.get_totp_code(&domain).await {
                    Ok(Some(code)) => IpcMessage::GetTotpCodeResponse {
                        code: Some(code.code),
                        seconds_remaining: Some(code.seconds_remaining),
                    },
                    Ok(None) => {
                        debug!("No TOTP code found for domain '{}'", domain);
                        IpcMessage::GetTotpCodeResponse {
                            code: None,
                            seconds_remaining: None,
                        }
                    }
                    Err(e) => {
                        error!("Failed to get TOTP code: {}", e);
                        IpcMessage::GetTotpCodeResponse {
                            code: None,
                            seconds_remaining: None,
                        }
                    }
                }
            }
            IpcMessage::SaveCredential {
                domain,
                username,
                password,
                url,
            } => {
                info!(
                    "IPC: SaveCredential for domain '{}', user '{}'",
                    domain, username
                );

                match self
                    .vault
                    .save_credential(&domain, &username, &password, url.as_deref())
                    .await
                {
                    Ok(_) => {
                        info!("Credential saved successfully for domain '{}'", domain);
                        IpcMessage::SaveCredentialResponse {
                            success: true,
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!("Failed to save credential: {}", e);
                        IpcMessage::SaveCredentialResponse {
                            success: false,
                            error: Some(e.to_string()),
                        }
                    }
                }
            }
            IpcMessage::UnlockVault {
                mut master_password,
            } => {
                debug!("IPC: UnlockVault");

                let unlock_result = if self.vault.is_unlocked().await {
                    Ok(())
                } else {
                    self.vault.unlock(master_password.as_bytes()).await
                };
                master_password.zeroize();

                match unlock_result {
                    Ok(_) => IpcMessage::UnlockVaultResponse {
                        success: true,
                        error: None,
                    },
                    Err(e) => {
                        warn!("Failed to unlock vault via IPC: {}", e);
                        IpcMessage::UnlockVaultResponse {
                            success: false,
                            error: Some(e.to_string()),
                        }
                    }
                }
            }
            IpcMessage::UnlockVaultBiometric { prompt_reason } => {
                debug!("IPC: UnlockVaultBiometric");
                let reason =
                    prompt_reason.unwrap_or_else(|| "Unlock SentinelPass daemon".to_string());
                match self.vault.unlock_with_biometric(&reason).await {
                    Ok(_) => {
                        log_daemon_audit(
                            AuditEventType::BiometricUnlockRequested { success: true },
                            "Daemon biometric unlock succeeded",
                        );
                        IpcMessage::UnlockVaultResponse {
                            success: true,
                            error: None,
                        }
                    }
                    Err(e) => {
                        warn!("Failed biometric unlock via IPC: {}", e);
                        log_daemon_audit(
                            AuditEventType::BiometricUnlockRequested { success: false },
                            "Daemon biometric unlock failed",
                        );
                        IpcMessage::UnlockVaultResponse {
                            success: false,
                            error: Some(e.to_string()),
                        }
                    }
                }
            }
            IpcMessage::CheckVault => {
                debug!("IPC: CheckVault");
                let unlocked = self.vault.is_unlocked().await;
                IpcMessage::VaultStatusResponse { unlocked }
            }
            IpcMessage::LockVault => {
                debug!("IPC: LockVault");
                self.vault.lock().await;
                IpcMessage::VaultStatusResponse { unlocked: false }
            }
            IpcMessage::Shutdown => {
                info!("IPC: Shutdown requested");
                IpcMessage::VaultStatusResponse { unlocked: false }
            }
            IpcMessage::SyncStatus => {
                debug!("IPC: SyncStatus");
                match self.vault.get_sync_status().await {
                    Ok(status) => IpcMessage::SyncStatusResponse {
                        enabled: status.enabled,
                        device_id: status.device_id.map(|d| d.to_string()),
                        device_name: status.device_name,
                        relay_url: status.relay_url,
                        last_sync_at: status.last_sync_at,
                        pending_changes: status.pending_changes,
                    },
                    Err(e) => {
                        error!("Failed to get sync status: {}", e);
                        IpcMessage::SyncStatusResponse {
                            enabled: false,
                            device_id: None,
                            device_name: None,
                            relay_url: None,
                            last_sync_at: None,
                            pending_changes: 0,
                        }
                    }
                }
            }
            _ => IpcMessage::VaultStatusResponse { unlocked: false },
        }
    }
}

/// IPC client for native messaging host
#[allow(dead_code)]
pub struct IpcClient {
    socket_path: PathBuf,
    auth_token: String,
}

impl IpcClient {
    /// Create a new IPC client
    pub fn new(socket_path: PathBuf) -> Result<Self> {
        let auth_token = load_ipc_token()?;
        Ok(Self::new_with_token(socket_path, auth_token))
    }

    /// Create a new IPC client with an explicit auth token.
    pub fn new_with_token(socket_path: PathBuf, auth_token: String) -> Self {
        Self {
            socket_path,
            auth_token,
        }
    }

    /// Send a message and wait for response
    #[allow(unused_variables)]
    pub async fn send(&self, msg: IpcMessage) -> Result<IpcMessage> {
        #[cfg(unix)]
        {
            // Use Unix socket transport
            let mut conn = UnixSocketConnection::connect(self.socket_path.clone())
                .await
                .map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to connect to daemon: {}",
                        e
                    )))
                })?;

            let envelope = IpcEnvelope {
                token: self.auth_token.clone(),
                message: msg,
            };
            let msg_bytes = serde_json::to_vec(&envelope).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to serialize message: {}",
                    e
                )))
            })?;

            conn.write_message(&msg_bytes).await.map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to write message: {}",
                    e
                )))
            })?;

            // Read response
            let buffer = conn.read_message().await.map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to read response: {}",
                    e
                )))
            })?;

            serde_json::from_slice::<IpcMessage>(&buffer).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to parse response: {}",
                    e
                )))
            })
        }

        #[cfg(windows)]
        {
            // Determine if using named pipes or legacy TCP
            let path_str = self.socket_path.to_string_lossy().to_string();
            let use_tcp = path_str.starts_with("tcp://");

            if use_tcp {
                // Legacy TCP fallback for custom tcp://... paths
                use tokio::net::TcpStream;

                let addr_str = path_str.strip_prefix("tcp://").unwrap_or("127.0.0.1:35873");

                // Connect to TCP socket with bounded retries
                let connect_deadline =
                    tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);
                let mut stream = loop {
                    match TcpStream::connect(addr_str).await {
                        Ok(s) => break s,
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                                if tokio::time::Instant::now() >= connect_deadline {
                                    return Err(PasswordManagerError::from(DatabaseError::Ipc(
                                        format!(
                                            "Failed to connect to daemon at {}: timed out after 3s",
                                            addr_str
                                        ),
                                    )));
                                }
                                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                continue;
                            }
                            return Err(PasswordManagerError::from(DatabaseError::Ipc(format!(
                                "Failed to connect to daemon: {}",
                                e
                            ))));
                        }
                    }
                };

                let envelope = IpcEnvelope {
                    token: self.auth_token.clone(),
                    message: msg,
                };
                let msg_bytes = serde_json::to_vec(&envelope).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to serialize message: {}",
                        e
                    )))
                })?;
                let msg_bytes = encrypt_windows_ipc_frame(&self.auth_token, &msg_bytes)?;

                let length = msg_bytes.len() as u32;

                stream.write_all(&length.to_be_bytes()).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to write length: {}",
                        e
                    )))
                })?;

                stream.write_all(&msg_bytes).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to write message: {}",
                        e
                    )))
                })?;

                stream.flush().await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to flush: {}",
                        e
                    )))
                })?;

                // Read response
                let mut length_buf = [0u8; 4];
                stream.read_exact(&mut length_buf).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to read length: {}",
                        e
                    )))
                })?;

                let response_length = u32::from_be_bytes(length_buf) as usize;

                if response_length > 65536 {
                    return Err(PasswordManagerError::from(DatabaseError::Ipc(
                        "Response too large".to_string(),
                    )));
                }

                let mut buffer = vec![0u8; response_length];
                stream.read_exact(&mut buffer).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to read response: {}",
                        e
                    )))
                })?;

                let buffer = decrypt_windows_ipc_frame(&self.auth_token, &buffer)?;

                serde_json::from_slice::<IpcMessage>(&buffer).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to parse response: {}",
                        e
                    )))
                })
            } else {
                // Default: Use named pipes
                let pipe_name = windows_named_pipe_path();
                debug!("Connecting to named pipe: {}", pipe_name);

                // Use Windows named pipe transport
                let transport = WindowsNamedPipeTransport::new(TransportConfig {
                    windows_pipe_path: Some(pipe_name),
                    ..Default::default()
                })
                .map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to create transport: {}",
                        e
                    )))
                })?;

                let mut conn = transport.connect(3000).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to connect to named pipe: {}",
                        e
                    )))
                })?;

                let envelope = IpcEnvelope {
                    token: self.auth_token.clone(),
                    message: msg,
                };
                let msg_bytes = serde_json::to_vec(&envelope).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to serialize message: {}",
                        e
                    )))
                })?;
                let msg_bytes = encrypt_windows_ipc_frame(&self.auth_token, &msg_bytes)?;

                conn.write_message(&msg_bytes).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to write message: {}",
                        e
                    )))
                })?;

                // Read response
                let buffer = conn.read_message().await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to read response: {}",
                        e
                    )))
                })?;

                let buffer = decrypt_windows_ipc_frame(&self.auth_token, &buffer)?;

                serde_json::from_slice::<IpcMessage>(&buffer).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to parse response: {}",
                        e
                    )))
                })
            }
        }
    }
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
        use chrono::Utc;
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
