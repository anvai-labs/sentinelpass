//! IPC server — handles daemon-side message dispatch.

#[cfg(windows)]
use super::{decrypt_windows_ipc_frame, encrypt_windows_ipc_frame, windows_named_pipe_path};
use super::{
    log_daemon_audit, log_external_secret_audit, CredentialSummary, IpcEnvelope, IpcMessage,
};
#[cfg(unix)]
use crate::daemon::transport::unix::UnixSocketTransport;
#[cfg(windows)]
use crate::daemon::transport::windows::{WindowsNamedPipeConnection, WindowsNamedPipeTransport};
use crate::daemon::transport::{TransportConfig, TransportError};
use crate::daemon::DaemonVault;
use crate::external_secret_access::{ExternalSecretAllowlist, ExternalSecretField};
use crate::{AuditEventType, AuditLogger};
use crate::{DatabaseError, PasswordManagerError, Result};
use std::path::PathBuf;
use std::sync::Arc;
use subtle::ConstantTimeEq;
#[allow(unused_imports)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;

#[allow(dead_code)]
pub struct IpcServer {
    socket_path: PathBuf,
    vault: Arc<DaemonVault>,
    auth_token: String,
    external_secret_allowlist_path: PathBuf,
    /// Shared audit logger — initialised once at startup so every IPC request
    /// reuses the open file handle instead of reopening it per-call.
    audit_logger: Option<Arc<AuditLogger>>,
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
        let audit_logger = match AuditLogger::new(crate::get_audit_log_dir()) {
            Ok(lg) => Some(Arc::new(lg)),
            Err(e) => {
                warn!(
                    "IpcServer: audit logger unavailable — audit events will be dropped: {}",
                    e
                );
                None
            }
        };
        Self {
            socket_path,
            vault,
            auth_token,
            external_secret_allowlist_path,
            audit_logger,
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
                                    self.audit_logger.as_deref(),
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
                                    self.audit_logger.as_deref(),
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
                                    self.audit_logger.as_deref(),
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
                            self.audit_logger.as_deref(),
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
                            self.audit_logger.as_deref(),
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
                            self.audit_logger.as_deref(),
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
                            self.audit_logger.as_deref(),
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
                            self.audit_logger.as_deref(),
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
                            self.audit_logger.as_deref(),
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
