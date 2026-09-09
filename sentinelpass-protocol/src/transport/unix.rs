//! Unix domain socket connection (client side; symmetric, also used by the
//! core server's accept loop).

use super::{TransportError, TransportResult, MAX_MESSAGE_SIZE};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Validate that the socket's parent directory is a PRIVATE runtime
/// directory (WBS-507): owned by the effective UID, mode 0700, and not a
/// symlink. When `create` is set (server/default path), a missing directory
/// is created owner-only; clients never create — they refuse.
///
/// This is what removes the `/tmp` fallback in practice: ANY socket path
/// (default or custom) whose directory is not owner-only is refused by both
/// the daemon and the clients, fail-closed.
pub fn ensure_private_socket_dir(socket_path: &Path, create: bool) -> TransportResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let Some(dir) = socket_path.parent() else {
        return Err(TransportError::Other(format!(
            "socket path has no parent directory: {}",
            socket_path.display()
        )));
    };

    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(TransportError::Other(format!(
                    "refusing IPC socket directory (symlink): {}",
                    dir.display()
                )));
            }
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != unsafe { libc::geteuid() } {
                return Err(TransportError::Other(format!(
                    "refusing IPC socket directory (not owned by the current user): {}",
                    dir.display()
                )));
            }
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(TransportError::Other(format!(
                    "refusing IPC socket directory (not owner-only, mode {:o}): {} \
                     — the daemon and clients only accept sockets inside a private \
                     runtime directory (0700)",
                    mode & 0o777,
                    dir.display()
                )));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
            std::fs::create_dir_all(dir).map_err(TransportError::Io)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(TransportError::Io)?;
            Ok(())
        }
        Err(e) => Err(TransportError::Io(e)),
    }
}

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
        // WBS-507: clients refuse sockets outside a private runtime dir.
        ensure_private_socket_dir(&path, false)?;

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

    fn private_dir() -> PathBuf {
        // tempfile dirs can be 0755 on some platforms; make the fixture a
        // valid private runtime dir explicitly.
        let dir = tempfile::TempDir::new().unwrap().keep();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    #[tokio::test]
    async fn test_unix_socket_connection_roundtrip() {
        let dir = private_dir();
        let socket_path = dir.join(format!("test_ipc_{}.sock", uuid_v4()));

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

    /// WBS-507 negative: a client refuses a socket whose directory is not
    /// owner-only (e.g. a world-traversable /tmp-style directory).
    #[tokio::test]
    async fn client_refuses_socket_in_loose_directory() {
        let outer = tempfile::TempDir::new().unwrap();
        let loose = outer.path().join("loose");
        std::fs::create_dir_all(&loose).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let socket_path = loose.join("sock");

        let err = match UnixSocketConnection::connect(socket_path).await {
            Err(err) => err,
            Ok(_) => panic!("loose socket dir must be refused"),
        };
        assert!(
            err.to_string().contains("owner-only"),
            "refusal must name the policy: {err}"
        );
    }

    /// WBS-507 positive: a client accepts a socket in a 0700 directory.
    #[tokio::test]
    async fn client_accepts_socket_in_private_directory() {
        let dir = private_dir();
        let socket_path = dir.join("sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        tokio::spawn(async move {
            let listener = listener;
            // Accept one connection and drop it; presence check is the point.
            let _ = listener.accept().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client = UnixSocketConnection::connect(socket_path).await;
        assert!(client.is_ok(), "private-dir socket must be accepted");
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
