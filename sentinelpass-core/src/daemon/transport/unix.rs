//! Unix domain socket transport (server-side listener).
//!
//! The connection type ([`UnixSocketConnection`], symmetric client/server)
//! lives in `sentinelpass_protocol`.

use super::{TransportConfig, TransportError, TransportResult, UnixSocketConnection};
use std::path::PathBuf;

/// Unix domain socket transport
pub struct UnixSocketTransport {
    listener: Option<tokio::net::UnixListener>,
    socket_path: PathBuf,
}

impl UnixSocketTransport {
    /// Create a new Unix socket transport
    pub fn new(config: TransportConfig) -> TransportResult<Self> {
        let socket_path: PathBuf = config
            .unix_socket_path
            .ok_or_else(|| TransportError::Other("Unix socket path not configured".to_string()))?
            .into();

        // Remove the socket file if it exists
        let _ = std::fs::remove_file(&socket_path);

        // Ensure the parent directory exists
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                TransportError::Io(std::io::Error::other(format!(
                    "Failed to create socket directory: {}",
                    e
                )))
            })?;
        }

        Ok(Self {
            listener: None,
            socket_path,
        })
    }

    /// Get the socket path
    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    /// Bind the listener to the socket path
    pub fn bind(&mut self) -> TransportResult<()> {
        // Set restrictive umask before bind to prevent brief window with default permissions
        #[cfg(unix)]
        let old_umask = unsafe { libc::umask(0o177) }; // Only owner r/w

        let listener = tokio::net::UnixListener::bind(&self.socket_path).map_err(|e| {
            #[cfg(unix)]
            unsafe {
                libc::umask(old_umask)
            };
            TransportError::ConnectionFailed(format!(
                "Failed to bind to {}: {}",
                self.socket_path.display(),
                e
            ))
        })?;

        // Restore original umask
        #[cfg(unix)]
        unsafe {
            libc::umask(old_umask)
        };

        self.listener = Some(listener);
        Ok(())
    }

    /// Accept a new connection (blocking, use in async context)
    pub async fn accept(&self) -> TransportResult<UnixSocketConnection> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| TransportError::Other("Transport not bound".to_string()))?;

        let stream = listener.accept().await.map_err(TransportError::Io)?.0;

        // Note: We rely on file system permissions (0o600) for security instead of peer credential check
        // The socket is owned by the same user who created it, and permissions restrict access

        Ok(UnixSocketConnection::from_stream(stream))
    }

    /// Check if the transport is bound
    pub fn is_bound(&self) -> bool {
        self.listener.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unix_socket_transport_bind() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_ipc_{}.sock", uuid::Uuid::new_v4()));

        let mut transport = UnixSocketTransport::new(TransportConfig {
            unix_socket_path: Some(socket_path.to_string_lossy().to_string()),
            ..Default::default()
        })
        .unwrap();

        transport.bind().unwrap();
        assert!(transport.is_bound());

        // Cleanup
        let _ = std::fs::remove_file(&socket_path);
    }
}
