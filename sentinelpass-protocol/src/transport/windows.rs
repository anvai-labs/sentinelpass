//! Windows named pipe connection (client side; symmetric, also used by the
//! core server's accept loop).

use super::{TransportError, TransportResult, MAX_MESSAGE_SIZE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Windows named pipe connection (can be either server or client side)
pub enum WindowsNamedPipeConnection {
    Server(tokio::net::windows::named_pipe::NamedPipeServer),
    Client(tokio::net::windows::named_pipe::NamedPipeClient),
}

impl WindowsNamedPipeConnection {
    /// Create a connection from a server-side pipe
    pub fn from_server(pipe: tokio::net::windows::named_pipe::NamedPipeServer) -> Self {
        Self::Server(pipe)
    }

    /// Create a connection from a client-side pipe
    pub fn from_client(pipe: tokio::net::windows::named_pipe::NamedPipeClient) -> Self {
        Self::Client(pipe)
    }

    /// Read a message from the connection
    pub async fn read_message(&mut self) -> TransportResult<Vec<u8>> {
        // Read message length (4 bytes, big-endian)
        let mut length_buf = [0u8; 4];
        match self {
            WindowsNamedPipeConnection::Server(p) => p.read_exact(&mut length_buf).await?,
            WindowsNamedPipeConnection::Client(p) => p.read_exact(&mut length_buf).await?,
        };

        let length = u32::from_be_bytes(length_buf) as usize;

        if length == 0 || length > MAX_MESSAGE_SIZE {
            return Err(TransportError::MessageTooLarge {
                size: length,
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Read message payload
        let mut buffer = vec![0u8; length];
        match self {
            WindowsNamedPipeConnection::Server(p) => p.read_exact(&mut buffer).await?,
            WindowsNamedPipeConnection::Client(p) => p.read_exact(&mut buffer).await?,
        };

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
        match self {
            WindowsNamedPipeConnection::Server(p) => p.write_all(&length.to_be_bytes()).await?,
            WindowsNamedPipeConnection::Client(p) => p.write_all(&length.to_be_bytes()).await?,
        };

        // Write payload
        match self {
            WindowsNamedPipeConnection::Server(p) => p.write_all(data).await?,
            WindowsNamedPipeConnection::Client(p) => p.write_all(data).await?,
        };

        // Flush
        match self {
            WindowsNamedPipeConnection::Server(p) => p.flush().await?,
            WindowsNamedPipeConnection::Client(p) => p.flush().await?,
        };

        Ok(())
    }

    /// Close the connection
    pub fn close(&mut self) -> TransportResult<()> {
        match self {
            WindowsNamedPipeConnection::Server(p) => {
                p.disconnect().map_err(TransportError::Io)?;
            }
            WindowsNamedPipeConnection::Client(_) => {
                // Client doesn't have a disconnect method - just drop it
            }
        };
        Ok(())
    }

    /// Check if the connection is still open
    pub fn is_open(&self) -> bool {
        // For named pipes, we can't easily check without I/O
        // Assume open if we haven't explicitly closed
        true
    }
}

/// Connect a named-pipe client to `pipe_name`, retrying until `timeout_ms`.
pub async fn connect_named_pipe(
    pipe_name: &str,
    timeout_ms: u64,
) -> TransportResult<WindowsNamedPipeConnection> {
    use tokio::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);

    loop {
        let client = tokio::net::windows::named_pipe::ClientOptions::new().open(pipe_name);
        match client {
            Ok(c) => return Ok(WindowsNamedPipeConnection::from_client(c)),
            Err(e) => {
                // Retry until the deadline (the daemon may not have created
                // the pipe instance yet)
                if Instant::now() >= deadline {
                    return Err(TransportError::ConnectionFailed(format!(
                        "Failed to connect to named pipe {}: {}",
                        pipe_name, e
                    )));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
