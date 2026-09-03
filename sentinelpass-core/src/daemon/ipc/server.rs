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
use sentinelpass_protocol::Origin;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Set by the `Shutdown` IPC message; the accept loops observe it and exit.
    shutdown: Arc<AtomicBool>,
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
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Handle to observe (or trigger) server shutdown from outside the accept loop.
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
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
                                    let response = self.handle_message(envelope).await;
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

                if self.shutdown.load(Ordering::Acquire) {
                    info!("IPC: shutdown requested — stopping accept loop");
                    break;
                }
            }
        }

        let _ = std::fs::remove_file(&self.socket_path);

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
                                                                    .handle_message(envelope)
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

                    if self.shutdown.load(Ordering::Acquire) {
                        info!("IPC: shutdown requested — stopping accept loop");
                        break;
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
                                                        self.handle_message(envelope).await;
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

                    if self.shutdown.load(Ordering::Acquire) {
                        info!("IPC: shutdown requested — stopping accept loop");
                        break;
                    }

                    // Connection is closed when dropped
                }
            }

            let _ = std::fs::remove_file(&self.socket_path);
        }

        Ok(())
    }

    /// Gate for the browser-autofill surface (GetCredential, GetTotpCode,
    /// ListDomainCredentials, SaveCredential). External tools must use
    /// GetExternalSecret / SaveSecret instead.
    ///
    /// - `NativeHost` origin: allowed.
    /// - `Cli` origin: denied — a CLI-tagged client has no business on the
    ///   autofill surface.
    /// - No origin: legacy <= 0.7 hosts. Allowed with a deprecation warning
    ///   in 0.8; set SENTINELPASS_DENY_LEGACY_GET_CREDENTIAL=1 to deny now
    ///   (deny-by-default is planned for 0.9).
    fn browser_surface_allowed(&self, origin: Option<Origin>) -> bool {
        match origin {
            Some(Origin::NativeHost) => true,
            Some(Origin::Cli) => false,
            None => std::env::var("SENTINELPASS_DENY_LEGACY_GET_CREDENTIAL")
                .map(|v| v != "1")
                .unwrap_or(true),
        }
    }

    fn warn_originless_browser_surface(&self) {
        warn!(
            "Deprecated: browser-surface request without origin marker from an \
             untagged client; upgrade sentinelpass-host. This will be denied by \
             default in v0.9 (SENTINELPASS_DENY_LEGACY_GET_CREDENTIAL=1 denies now)."
        );
    }

    /// Handle an IPC envelope (auth token was already verified by the caller).
    #[allow(dead_code)]
    async fn handle_message(&self, envelope: IpcEnvelope) -> IpcMessage {
        let client_token = envelope.client_token.clone();
        // Origin is provenance labeling for the browser-surface gate below —
        // NOT authentication. The security boundary for external tools is the
        // grant + client token system.
        let origin = envelope.origin;
        match envelope.message {
            IpcMessage::GetExternalSecret {
                client_id,
                domain,
                field,
                purpose,
            } => {
                if !self.vault.is_unlocked().await {
                    return IpcMessage::GetExternalSecretResponse {
                        value: None,
                        authorized: true,
                        error: None,
                        locked: Some(true),
                    };
                }
                debug!(
                    "IPC: GetExternalSecret client='{}' domain='{}' field='{}'",
                    client_id,
                    domain,
                    field.as_str()
                );

                let purpose = purpose.unwrap_or_else(|| "external-secret-access".to_string());
                let allowlist =
                    ExternalSecretAllowlist::load_from_path(&self.external_secret_allowlist_path);
                let token_ok = match &allowlist {
                    Ok(allowlist) => {
                        allowlist.verify_client_token(&client_id, client_token.as_deref())
                    }
                    Err(_) => false,
                };
                match allowlist {
                    Ok(allowlist)
                        if token_ok && allowlist.is_allowed(&client_id, &domain, field) =>
                    {
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
                                    locked: None,
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
                                    locked: None,
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
                                    locked: None,
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
                                "Client '{}' is not authorized for {} {}: run \
                                 'sentinelpass secret allow --client-id {} --domain {} --field {}' \
                                 and set SENTINELPASS_CLIENT_TOKEN",
                                client_id,
                                domain,
                                field.as_str(),
                                client_id,
                                domain,
                                field.as_str()
                            )),
                            locked: None,
                        }
                    }
                    Err(e) => {
                        error!("Failed to load external secret allowlist: {}", e);
                        IpcMessage::GetExternalSecretResponse {
                            value: None,
                            authorized: false,
                            error: Some("Failed to load external secret allowlist".to_string()),
                            locked: None,
                        }
                    }
                }
            }
            IpcMessage::SaveSecret {
                client_id,
                domain,
                value,
                purpose,
            } => {
                let purpose_label = purpose.unwrap_or_else(|| "external-secret-write".to_string());
                if !self.vault.is_unlocked().await {
                    return IpcMessage::SaveSecretResponse {
                        success: false,
                        locked: Some(true),
                        error: Some("vault is locked".to_string()),
                    };
                }

                let allowlist =
                    ExternalSecretAllowlist::load_from_path(&self.external_secret_allowlist_path);
                let authorized = match &allowlist {
                    Ok(allowlist) => {
                        allowlist.verify_client_token(&client_id, client_token.as_deref())
                            && allowlist
                                .grants_for_client(Some(&client_id))
                                .unwrap_or_default()
                                .into_iter()
                                .any(|grant| {
                                    grant.allow_write
                                        && !grant.is_expired_at(chrono::Utc::now())
                                        && grant.domain == domain
                                })
                    }
                    Err(_) => false,
                };

                if !authorized {
                    log_daemon_audit(
                        self.audit_logger.as_deref(),
                        AuditEventType::ExternalSecretWrite {
                            client_id: Some(client_id.clone()),
                            domain: domain.clone(),
                            purpose: Some(purpose_label),
                            success: false,
                        },
                        "External secret write denied",
                    );
                    return IpcMessage::SaveSecretResponse {
                        success: false,
                        locked: None,
                        error: Some(format!(
                            "Client '{}' has no write grant for '{}': run \
                             'sentinelpass secret allow --client-id {} --domain {} --field password --write' \
                             and set SENTINELPASS_CLIENT_TOKEN",
                            client_id, domain, client_id, domain
                        )),
                    };
                }

                match self.vault.save_secret_value(&domain, &value).await {
                    Ok(()) => {
                        log_daemon_audit(
                            self.audit_logger.as_deref(),
                            AuditEventType::ExternalSecretWrite {
                                client_id: Some(client_id.clone()),
                                domain: domain.clone(),
                                purpose: Some(purpose_label),
                                success: true,
                            },
                            "External secret written via daemon IPC",
                        );
                        IpcMessage::SaveSecretResponse {
                            success: true,
                            locked: None,
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!("Failed to save external secret: {}", e);
                        IpcMessage::SaveSecretResponse {
                            success: false,
                            locked: None,
                            error: Some("Failed to save secret".to_string()),
                        }
                    }
                }
            }
            IpcMessage::DeleteSecret { client_id, domain } => {
                // Deletion is rejected until entries carry ownership metadata
                // (schema v5): a write-grant must never be able to delete a
                // human-created login.
                debug!(
                    "IPC: DeleteSecret from client '{}' for '{}' rejected (unsupported)",
                    client_id, domain
                );
                let _ = domain;
                IpcMessage::DeleteSecretResponse {
                    deleted: false,
                    locked: None,
                    error: Some(
                        "deletion is not supported for external tools; revoke the grant instead"
                            .to_string(),
                    ),
                }
            }
            IpcMessage::GetCredential { domain } => {
                debug!("IPC: GetCredential for domain '{}'", domain);

                if !self.browser_surface_allowed(origin) {
                    return IpcMessage::GetCredentialResponse {
                        username: None,
                        password: None,
                        title: None,
                        locked: None,
                    };
                }
                if origin.is_none() {
                    self.warn_originless_browser_surface();
                }

                if !self.vault.is_unlocked().await {
                    return IpcMessage::GetCredentialResponse {
                        username: None,
                        password: None,
                        title: None,
                        locked: Some(true),
                    };
                }

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
                            locked: None,
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
                            locked: None,
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
                            locked: None,
                        }
                    }
                }
            }
            IpcMessage::ListDomainCredentials { base_domain } => {
                debug!(
                    "IPC: ListDomainCredentials for base domain '{}'",
                    base_domain
                );

                if !self.browser_surface_allowed(origin) {
                    return IpcMessage::ListDomainCredentialsResponse {
                        credentials: Vec::new(),
                        locked: None,
                    };
                }
                if origin.is_none() {
                    self.warn_originless_browser_surface();
                }

                if !self.vault.is_unlocked().await {
                    return IpcMessage::ListDomainCredentialsResponse {
                        credentials: Vec::new(),
                        locked: Some(true),
                    };
                }

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
                            locked: None,
                        }
                    }
                    Err(e) => {
                        error!("Failed to list domain credentials: {}", e);
                        IpcMessage::ListDomainCredentialsResponse {
                            credentials: Vec::new(),
                            locked: None,
                        }
                    }
                }
            }
            IpcMessage::GetTotpCode { domain } => {
                debug!("IPC: GetTotpCode for domain '{}'", domain);

                if !self.browser_surface_allowed(origin) {
                    return IpcMessage::GetTotpCodeResponse {
                        code: None,
                        seconds_remaining: None,
                        locked: None,
                    };
                }
                if origin.is_none() {
                    self.warn_originless_browser_surface();
                }

                if !self.vault.is_unlocked().await {
                    return IpcMessage::GetTotpCodeResponse {
                        code: None,
                        seconds_remaining: None,
                        locked: Some(true),
                    };
                }

                match self.vault.get_totp_code(&domain).await {
                    Ok(Some(code)) => IpcMessage::GetTotpCodeResponse {
                        code: Some(code.code),
                        seconds_remaining: Some(code.seconds_remaining),
                        locked: None,
                    },
                    Ok(None) => {
                        debug!("No TOTP code found for domain '{}'", domain);
                        IpcMessage::GetTotpCodeResponse {
                            code: None,
                            seconds_remaining: None,
                            locked: None,
                        }
                    }
                    Err(e) => {
                        error!("Failed to get TOTP code: {}", e);
                        IpcMessage::GetTotpCodeResponse {
                            code: None,
                            seconds_remaining: None,
                            locked: None,
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

                if !self.browser_surface_allowed(origin) {
                    return IpcMessage::SaveCredentialResponse {
                        success: false,
                        error: Some(
                            "browser-surface request rejected: non-native origin".to_string(),
                        ),
                        locked: None,
                    };
                }
                if origin.is_none() {
                    self.warn_originless_browser_surface();
                }

                if !self.vault.is_unlocked().await {
                    return IpcMessage::SaveCredentialResponse {
                        success: false,
                        error: Some("vault is locked".to_string()),
                        locked: Some(true),
                    };
                }

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
                            locked: None,
                        }
                    }
                    Err(e) => {
                        error!("Failed to save credential: {}", e);
                        IpcMessage::SaveCredentialResponse {
                            success: false,
                            error: Some(e.to_string()),
                            locked: None,
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
                // key_epoch is vault metadata, not key material, but
                // DaemonVault drops its VaultManager on lock — 0 means
                // "unknown" (vault not currently loaded), not epoch zero.
                let key_epoch = self.vault.key_epoch().await.unwrap_or(0);
                IpcMessage::VaultStatusResponse {
                    unlocked,
                    key_epoch,
                }
            }
            IpcMessage::LockVault => {
                debug!("IPC: LockVault");
                self.vault.lock().await;
                IpcMessage::VaultStatusResponse {
                    unlocked: false,
                    key_epoch: 0,
                }
            }
            IpcMessage::Shutdown => {
                info!("IPC: Shutdown requested");
                self.shutdown.store(true, Ordering::Release);
                IpcMessage::VaultStatusResponse {
                    unlocked: false,
                    key_epoch: 0,
                }
            }
            IpcMessage::SyncNow => {
                debug!("IPC: SyncNow");
                #[cfg(feature = "sync")]
                {
                    let pending_before = self
                        .vault
                        .get_sync_status()
                        .await
                        .map(|s| s.pending_changes)
                        .unwrap_or(0);
                    match self.vault.sync_now().await {
                        Ok(status_after) => {
                            let pushed =
                                pending_before.saturating_sub(status_after.pending_changes);
                            info!("IPC: sync completed, ~{} changes pushed", pushed);
                            IpcMessage::SyncNowResponse {
                                success: true,
                                pushed,
                                pulled: 0,
                                error: None,
                            }
                        }
                        Err(e) => {
                            error!("Failed to run sync: {}", e);
                            IpcMessage::SyncNowResponse {
                                success: false,
                                pushed: 0,
                                pulled: 0,
                                error: Some(e.to_string()),
                            }
                        }
                    }
                }
                #[cfg(not(feature = "sync"))]
                IpcMessage::SyncNowResponse {
                    success: false,
                    pushed: 0,
                    pulled: 0,
                    error: Some("sync support is not compiled into this daemon".to_string()),
                }
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
            _ => IpcMessage::VaultStatusResponse {
                unlocked: false,
                key_epoch: 0,
            },
        }
    }
}
