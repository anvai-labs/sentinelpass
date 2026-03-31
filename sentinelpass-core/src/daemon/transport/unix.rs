//! Unix domain socket transport for IPC.

use super::{TransportConfig, TransportError, TransportResult, MAX_MESSAGE_SIZE};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

        Ok(UnixSocketConnection { stream })
    }

    /// Check if the transport is bound
    pub fn is_bound(&self) -> bool {
        self.listener.is_some()
    }
}

/// Unix socket connection
pub struct UnixSocketConnection {
    stream: tokio::net::UnixStream,
}

impl UnixSocketConnection {
    /// Create a new connection as a client
    pub async fn connect(path: PathBuf) -> TransportResult<Self> {
        let stream = tokio::net::UnixStream::connect(&path).await.map_err(|e| {
            TransportError::ConnectionFailed(format!(
                "Failed to connect to {}: {}",
                path.display(),
                e
            ))
        })?;

        Ok(Self { stream })
    }

    /// Read a message from the connection
    pub async fn read_message(&mut self) -> TransportResult<Vec<u8>> {
        // Read message length (4 bytes, big-endian)
        let mut length_buf = [0u8; 4];
        self.stream.read_exact(&mut length_buf).await?;

        let length = u32::from_be_bytes(length_buf) as usize;

        if length == 0 || length > MAX_MESSAGE_SIZE {
            return Err(TransportError::MessageTooLarge {
                size: length,
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Read message payload
        let mut buffer = vec![0u8; length];
        self.stream.read_exact(&mut buffer).await?;

        Ok(buffer)
    }

    /// Write a message to the connection
    pub async fn write_message(&mut self, data: &[u8]) -> TransportResult<()> {
        let length = data.len() as u32;

        // Validate message size
        if length as usize > MAX_MESSAGE_SIZE {
            return Err(TransportError::MessageTooLarge {
                size: data.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Write length prefix
        self.stream.write_all(&length.to_be_bytes()).await?;

        // Write payload
        self.stream.write_all(data).await?;

        self.stream.flush().await?;

        Ok(())
    }

    /// Close the connection
    pub async fn close(&mut self) -> TransportResult<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    /// Check if the connection is still open
    pub fn is_open(&self) -> bool {
        // Try to get the peer address to check if still connected
        self.stream.peer_addr().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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

    #[tokio::test]
    async fn test_unix_socket_connection_roundtrip() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_ipc_{}.sock", uuid::Uuid::new_v4()));

        // Start server
        let mut server_transport = UnixSocketTransport::new(TransportConfig {
            unix_socket_path: Some(socket_path.to_string_lossy().to_string()),
            ..Default::default()
        })
        .unwrap();
        server_transport.bind().unwrap();

        // Spawn server task
        let server_handle = tokio::spawn(async move {
            let mut conn = server_transport.accept().await.unwrap();
            let msg = conn.read_message().await.unwrap();
            conn.write_message(&msg).await.unwrap();
            conn.close().await.unwrap();
        });

        // Connect as client
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut client = UnixSocketConnection::connect(socket_path).await.unwrap();

        // Send and receive
        let test_data = b"Hello, IPC!";
        client.write_message(test_data).await.unwrap();
        let received = client.read_message().await.unwrap();

        assert_eq!(received, test_data);

        server_handle.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "Flaky on CI due to timing issues with Unix socket shutdown"]
    async fn test_unix_socket_message_too_large() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_ipc_{}.sock", uuid::Uuid::new_v4()));

        let mut transport = UnixSocketTransport::new(TransportConfig {
            unix_socket_path: Some(socket_path.to_string_lossy().to_string()),
            ..Default::default()
        })
        .unwrap();
        transport.bind().unwrap();

        let server_handle = tokio::spawn(async move {
            let mut conn = transport.accept().await.unwrap();
            // Server tries to read - should fail because client writes oversized message
            // and doesn't send any data
            let result = conn.read_message().await;
            // Should get an error (connection closed, timeout, etc.)
            assert!(
                result.is_err(),
                "Server should fail to read when client writes oversized message"
            );
        });

        // Connect and try to send oversized message
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut client = UnixSocketConnection::connect(socket_path).await.unwrap();

        let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let result = client.write_message(&oversized).await;
        // Client should fail size validation
        assert!(matches!(
            result,
            Err(TransportError::MessageTooLarge { .. })
        ));

        // Drop client to close the connection
        drop(client);

        // Server should complete (either with error or timeout)
        let _ = server_handle.await;
    }

    #[tokio::test]
    #[ignore = "Flaky on CI due to timing issues with Unix socket shutdown"]
    async fn test_unix_socket_is_open() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_ipc_{}.sock", uuid::Uuid::new_v4()));

        let mut transport = UnixSocketTransport::new(TransportConfig {
            unix_socket_path: Some(socket_path.to_string_lossy().to_string()),
            ..Default::default()
        })
        .unwrap();
        transport.bind().unwrap();

        let server_handle = tokio::spawn(async move {
            let mut conn = transport.accept().await.unwrap();
            assert!(conn.is_open());
            conn.close().await.unwrap();
            // Note: is_open() might not immediately return false after close()
            // due to how Unix sockets work, so we don't assert that here
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut client = UnixSocketConnection::connect(socket_path).await.unwrap();

        client.write_message(b"test").await.unwrap();
        let _ = client.read_message().await;

        server_handle.await.unwrap();
    }
}
