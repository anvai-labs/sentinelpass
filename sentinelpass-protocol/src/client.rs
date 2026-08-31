//! IPC client — sends messages to the daemon.

use crate::envelope::{IpcEnvelope, Origin};
use crate::error::ProtocolError;
use crate::message::IpcMessage;
use crate::token::load_ipc_token;
use crate::Result;
use std::path::PathBuf;
#[allow(unused_imports)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        })
    }

    /// Override the per-client grant token and origin label. Intended for
    /// embedders that construct the daemon token explicitly (tests, hosts).
    pub fn with_context(mut self, client_token: Option<String>, origin: Option<Origin>) -> Self {
        self.client_token = client_token;
        self.origin = origin;
        self
    }

    /// Browser native-messaging host client.
    pub fn new_for_native_host(socket_path: PathBuf) -> Result<Self> {
        let auth_token = load_ipc_token()?;
        Ok(Self {
            socket_path,
            auth_token,
            client_token: None,
            origin: Some(Origin::NativeHost),
        })
    }

    /// Send a message and wait for response
    #[allow(unused_variables)]
    pub async fn send(&self, msg: IpcMessage) -> Result<IpcMessage> {
        #[cfg(unix)]
        {
            // Use Unix socket transport
            let mut conn =
                crate::transport::unix::UnixSocketConnection::connect(self.socket_path.clone())
                    .await
                    .map_err(|e| {
                        ProtocolError::Ipc(format!("Failed to connect to daemon: {}", e))
                    })?;

            let envelope = IpcEnvelope {
                token: self.auth_token.clone(),
                client_token: self.client_token.clone(),
                origin: self.origin,
                message: msg,
            };
            let msg_bytes = serde_json::to_vec(&envelope)
                .map_err(|e| ProtocolError::Ipc(format!("Failed to serialize message: {}", e)))?;

            conn.write_message(&msg_bytes)
                .await
                .map_err(|e| ProtocolError::Ipc(format!("Failed to write message: {}", e)))?;

            // Read response
            let buffer = conn
                .read_message()
                .await
                .map_err(|e| ProtocolError::Ipc(format!("Failed to read response: {}", e)))?;

            serde_json::from_slice::<IpcMessage>(&buffer)
                .map_err(|e| ProtocolError::Ipc(format!("Failed to parse response: {}", e)))
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
                                    return Err(ProtocolError::Ipc(format!(
                                        "Failed to connect to daemon at {}: timed out after 3s",
                                        addr_str
                                    )));
                                }
                                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                continue;
                            }
                            return Err(ProtocolError::Ipc(format!(
                                "Failed to connect to daemon: {}",
                                e
                            )));
                        }
                    }
                };

                let envelope = IpcEnvelope {
                    token: self.auth_token.clone(),
                    client_token: self.client_token.clone(),
                    origin: self.origin,
                    message: msg,
                };
                let msg_bytes = serde_json::to_vec(&envelope).map_err(|e| {
                    ProtocolError::Ipc(format!("Failed to serialize message: {}", e))
                })?;
                let msg_bytes =
                    crate::windows_frame::encrypt_windows_ipc_frame(&self.auth_token, &msg_bytes)?;

                let length = msg_bytes.len() as u32;

                stream
                    .write_all(&length.to_be_bytes())
                    .await
                    .map_err(|e| ProtocolError::Ipc(format!("Failed to write length: {}", e)))?;

                stream
                    .write_all(&msg_bytes)
                    .await
                    .map_err(|e| ProtocolError::Ipc(format!("Failed to write message: {}", e)))?;

                stream
                    .flush()
                    .await
                    .map_err(|e| ProtocolError::Ipc(format!("Failed to flush: {}", e)))?;

                // Read response
                let mut length_buf = [0u8; 4];
                stream
                    .read_exact(&mut length_buf)
                    .await
                    .map_err(|e| ProtocolError::Ipc(format!("Failed to read length: {}", e)))?;

                let response_length = u32::from_be_bytes(length_buf) as usize;

                if response_length > 65536 {
                    return Err(ProtocolError::Ipc("Response too large".to_string()));
                }

                let mut buffer = vec![0u8; response_length];
                stream
                    .read_exact(&mut buffer)
                    .await
                    .map_err(|e| ProtocolError::Ipc(format!("Failed to read response: {}", e)))?;

                let buffer =
                    crate::windows_frame::decrypt_windows_ipc_frame(&self.auth_token, &buffer)?;

                serde_json::from_slice::<IpcMessage>(&buffer)
                    .map_err(|e| ProtocolError::Ipc(format!("Failed to parse response: {}", e)))
            } else {
                // Default: Use named pipes
                let pipe_name = crate::windows_frame::windows_named_pipe_path();
                debug!("Connecting to named pipe: {}", pipe_name);

                let mut conn = crate::transport::windows::connect_named_pipe(&pipe_name, 3000)
                    .await
                    .map_err(|e| {
                        ProtocolError::Ipc(format!("Failed to connect to named pipe: {}", e))
                    })?;

                let envelope = IpcEnvelope {
                    token: self.auth_token.clone(),
                    client_token: self.client_token.clone(),
                    origin: self.origin,
                    message: msg,
                };
                let msg_bytes = serde_json::to_vec(&envelope).map_err(|e| {
                    ProtocolError::Ipc(format!("Failed to serialize message: {}", e))
                })?;
                let msg_bytes =
                    crate::windows_frame::encrypt_windows_ipc_frame(&self.auth_token, &msg_bytes)?;

                conn.write_message(&msg_bytes)
                    .await
                    .map_err(|e| ProtocolError::Ipc(format!("Failed to write message: {}", e)))?;

                // Read response
                let buffer = conn
                    .read_message()
                    .await
                    .map_err(|e| ProtocolError::Ipc(format!("Failed to read response: {}", e)))?;

                let buffer =
                    crate::windows_frame::decrypt_windows_ipc_frame(&self.auth_token, &buffer)?;

                serde_json::from_slice::<IpcMessage>(&buffer)
                    .map_err(|e| ProtocolError::Ipc(format!("Failed to parse response: {}", e)))
            }
        }
    }
}
