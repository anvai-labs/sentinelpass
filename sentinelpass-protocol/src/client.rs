//! IPC client — sends messages to the daemon.

use crate::envelope::{IpcEnvelope, Origin};
use crate::error::ProtocolError;
use crate::message::IpcMessage;
use crate::service::{ServiceOutcome, VaultOp, VaultOpResult};
use crate::token::load_ipc_token;
use crate::Result;
use std::path::PathBuf;

#[cfg(windows)]
use tracing::debug;

/// IPC client for daemon communication
pub struct IpcClient {
    socket_path: PathBuf,
    auth_token: String,
    /// Per-client grant token (SENTINELPASS_CLIENT_TOKEN); sent on every
    /// request so the daemon can enforce token-scoped grants.
    client_token: Option<String>,
    /// Provenance label for this process (native host / CLI).
    origin: Option<Origin>,
    /// WBS-505: presented installation-capability secret (the native host
    /// presents its own; a general client has none).
    capability: Option<String>,
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
            client_token: None,
            origin: None,
            capability: None,
        }
    }

    /// CLI client carrying a per-client grant token for external secret access.
    pub fn new_for_cli(socket_path: PathBuf, client_token: Option<String>) -> Result<Self> {
        let auth_token = load_ipc_token()?;
        Ok(Self {
            socket_path,
            auth_token,
            client_token,
            origin: Some(Origin::Cli),
            capability: None,
        })
    }

    /// Override the per-client grant token and origin label. Intended for
    /// embedders that construct the daemon token explicitly (tests, hosts).
    pub fn with_context(mut self, client_token: Option<String>, origin: Option<Origin>) -> Self {
        self.client_token = client_token;
        self.origin = origin;
        self
    }

    /// Attach an installation-capability secret (WBS-505).
    pub fn with_capability(mut self, capability: Option<String>) -> Self {
        self.capability = capability;
        self
    }

    /// Browser native-messaging host client. Presents the installation
    /// capability when it has been provisioned (the daemon mints it on its
    /// first start; a host running before that has none and the daemon's
    /// legacy window applies).
    pub fn new_for_native_host(socket_path: PathBuf) -> Result<Self> {
        let auth_token = load_ipc_token()?;
        Ok(Self {
            socket_path,
            auth_token,
            client_token: None,
            origin: Some(Origin::NativeHost),
            capability: crate::token::load_native_host_capability(),
        })
    }

    /// Send a message and wait for response. The connection negotiates the
    /// v1 SECURED session (WBS-509/510/511) before the envelope is sent:
    /// HKDF directional keys over the auth token + session randoms, AAD-
    /// bound frames, strictly-increasing counters, and bounded reads.
    pub async fn send(&self, msg: IpcMessage) -> Result<IpcMessage> {
        let envelope = IpcEnvelope {
            token: self.auth_token.clone(),
            client_token: self.client_token.clone(),
            origin: self.origin,
            capability: self.capability.clone(),
            message: msg,
        };
        let msg_bytes = serde_json::to_vec(&envelope)
            .map_err(|e| ProtocolError::Ipc(format!("Failed to serialize message: {}", e)))?;

        // --- platform connect ---------------------------------------------
        #[cfg(unix)]
        let transport_conn = {
            crate::transport::unix::UnixSocketConnection::connect(self.socket_path.clone())
                .await
                .map_err(|e| ProtocolError::Ipc(format!("Failed to connect to daemon: {}", e)))?
        };

        #[cfg(windows)]
        let transport_conn = {
            // Named pipes only: the legacy tcp:// loopback branch was
            // removed in Phase 3 (ADR-007 migration). Honor an explicit
            // \\\\.\\pipe\\ path (tests, custom deploys); default to the
            // per-user pipe name otherwise — mirroring the server arm.
            let stored = self.socket_path.to_string_lossy().to_string();
            let pipe_name = if stored.starts_with(r"\\.\pipe\") {
                stored
            } else {
                crate::windows_frame::windows_named_pipe_path()
            };
            debug!("Connecting to named pipe: {}", pipe_name);
            crate::transport::windows::connect_named_pipe(&pipe_name, 3000)
                .await
                .map_err(|e| {
                    ProtocolError::Ipc(format!("Failed to connect to named pipe: {}", e))
                })?
        };

        // --- session negotiation + exchange ---------------------------------
        let conn = crate::connection::TransportConnection::from(transport_conn);
        let mut ipc = crate::connection::IpcConnection::connect_client(conn, &self.auth_token)
            .await
            .map_err(|e| ProtocolError::Ipc(format!("Session negotiation failed: {}", e)))?;

        ipc.send_frame(&msg_bytes)
            .await
            .map_err(|e| ProtocolError::Ipc(format!("Failed to write message: {}", e)))?;

        let buffer = ipc
            .recv_frame()
            .await
            .map_err(|e| ProtocolError::Ipc(format!("Failed to read response: {}", e)))?;

        serde_json::from_slice::<IpcMessage>(&buffer)
            .map_err(|e| ProtocolError::Ipc(format!("Failed to parse response: {}", e)))
    }

    /// One application-service call (WBS-408): send `ServiceCall { op }` and
    /// unwrap the `ServiceResult` outcome. Typed service errors surface as
    /// [`ProtocolError::Service`].
    pub async fn call_service(&self, op: VaultOp) -> Result<VaultOpResult> {
        let response = self.send(IpcMessage::ServiceCall { op }).await?;
        match response {
            IpcMessage::ServiceResult { outcome } => match outcome {
                ServiceOutcome::Ok { result } => Ok(result),
                ServiceOutcome::Err { error } => {
                    Err(ProtocolError::Service(error.code, error.message))
                }
            },
            other => Err(ProtocolError::Ipc(format!(
                "unexpected daemon response to service call: {}",
                message_kind(&other)
            ))),
        }
    }
}

/// Best-effort variant label for an unexpected response (diagnostics only;
/// never message payloads).
fn message_kind(msg: &IpcMessage) -> &'static str {
    match msg {
        IpcMessage::GetCredentialResponse { .. }
        | IpcMessage::GetExternalSecretResponse { .. }
        | IpcMessage::ListDomainCredentialsResponse { .. }
        | IpcMessage::GetTotpCodeResponse { .. }
        | IpcMessage::SaveCredentialResponse { .. }
        | IpcMessage::SaveSecretResponse { .. }
        | IpcMessage::DeleteSecretResponse { .. } => "browser-surface response",
        IpcMessage::UnlockVaultResponse { .. } => "unlock response",
        IpcMessage::VaultStatusResponse { .. } => "vault status",
        IpcMessage::SyncNowResponse { .. } => "sync-now response",
        IpcMessage::SyncStatusResponse { .. } => "sync status",
        _ => "other",
    }
}
