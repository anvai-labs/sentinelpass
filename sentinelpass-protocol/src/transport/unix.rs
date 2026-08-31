//! Unix domain socket connection (client side; symmetric, also used by the
//! core server's accept loop).

use super::{TransportError, TransportResult, MAX_MESSAGE_SIZE};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Unix socket connection
pub struct UnixSocketConnection {
    stream: tokio::net::UnixStream,
}

impl UnixSocketConnection {
    /// Wrap an accepted (server-side) stream.
    pub fn from_stream(stream: tokio::net::UnixStream) -> Self {
        Self { stream }
    }

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
    async fn test_unix_socket_connection_roundtrip() {
        let temp_dir = std::env::temp_dir();
        let socket_path = temp_dir.join(format!("test_ipc_{}.sock", uuid_v4()));

        // Start server
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = UnixSocketConnection::from_stream(stream);
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

    fn uuid_v4() -> String {
        // Simple unique suffix without pulling a uuid dependency
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("proto{n}", n = nanos)
    }
}
