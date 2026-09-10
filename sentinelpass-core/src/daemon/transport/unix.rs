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

        // NOTE: the parent directory is NOT created here — `bind` creates it
        // owner-only (0700) or refuses a pre-existing non-private directory
        // (WBS-507).

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
        // WBS-507: the socket must live in a PRIVATE runtime directory —
        // owned by the effective UID and mode 0700. The default location is
        // created on demand; ANY custom location that is not owner-only is
        // REFUSED (this is what retires the /tmp fallback in practice).
        sentinelpass_protocol::transport::unix::ensure_private_socket_dir(&self.socket_path, true)?;

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

    /// Accept a new connection (blocking, use in async context).
    ///
    /// WBS-507: platform peer-credential check — the connecting process's
    /// effective UID must equal ours. The owner-only directory is the first
    /// gate; this is the second, kernel-verified one (a process that cannot
    /// create files in the directory cannot connect either way, but the
    /// peer check also covers directories whose permissions were loosened
    /// after bind).
    pub async fn accept(&self) -> TransportResult<UnixSocketConnection> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| TransportError::Other("Transport not bound".to_string()))?;

        let (stream, _addr) = listener.accept().await.map_err(TransportError::Io)?;

        use std::os::fd::AsRawFd;
        match peer_uid(stream.as_raw_fd()) {
            Some(uid) if uid == unsafe { libc::geteuid() } => {}
            Some(uid) => {
                return Err(TransportError::ConnectionFailed(format!(
                    "refused IPC connection from foreign peer UID {}",
                    uid
                )));
            }
            None => {
                return Err(TransportError::ConnectionFailed(
                    "refused IPC connection: peer credentials unavailable".to_string(),
                ));
            }
        }

        Ok(UnixSocketConnection::from_stream(stream))
    }

    /// Check if the transport is bound
    pub fn is_bound(&self) -> bool {
        self.listener.is_some()
    }
}

/// Peer effective UID via the platform socket credential API:
/// `SO_PEERCRED` on Linux, `getpeereid()` on macOS/*BSD.
#[cfg(unix)]
fn peer_uid(fd: std::os::fd::RawFd) -> Option<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut ucred = libc::ucred {
            pid: 0,
            gid: 0,
            uid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ok = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut ucred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if ok == 0 {
            Some(ucred.uid)
        } else {
            None
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let ok = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if ok == 0 {
            Some(uid)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unix_socket_transport_bind() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        // tempfile dirs can be 0755 on some platforms; the socket's parent
        // must be owner-only, as in production runtime dirs. (Short names:
        // macOS sun_path is 104 bytes.)
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let socket_path = temp_dir.path().join("t.sock");

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

    /// WBS-507: bind REFUSES a socket whose directory is not owner-only
    /// (the /tmp-fallback kill switch). tempfile's parent here is 0700 but
    /// the nested "loose" directory is deliberately 0755.
    #[tokio::test]
    async fn bind_refuses_loose_socket_directory() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let loose = temp_dir.path().join("loose");
        std::fs::create_dir_all(&loose).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let socket_path = loose.join("test.sock");

        let mut transport = UnixSocketTransport::new(TransportConfig {
            unix_socket_path: Some(socket_path.to_string_lossy().to_string()),
            ..Default::default()
        })
        .unwrap();

        let err = transport.bind().expect_err("loose dir must be refused");
        assert!(
            err.to_string().contains("owner-only"),
            "refusal must name the policy: {err}"
        );
    }

    /// WBS-507: bind CREATES the default runtime directory owner-only.
    #[tokio::test]
    async fn bind_creates_owner_only_runtime_directory() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let runtime = temp_dir.path().join("r");
        let socket_path = runtime.join("t.sock");

        let mut transport = UnixSocketTransport::new(TransportConfig {
            unix_socket_path: Some(socket_path.to_string_lossy().to_string()),
            ..Default::default()
        })
        .unwrap();

        transport.bind().unwrap();
        let mode = std::fs::metadata(&runtime).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "runtime dir must be created 0700");

        // Cleanup
        let _ = std::fs::remove_file(&socket_path);
    }

    /// Peer-credential check passes for a same-process (same-euid) client.
    #[tokio::test]
    async fn same_euid_peer_passes_peer_check() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let socket_path = temp_dir.path().join("peer.sock");
        let mut transport = UnixSocketTransport::new(TransportConfig {
            unix_socket_path: Some(socket_path.to_string_lossy().to_string()),
            ..Default::default()
        })
        .unwrap();
        transport.bind().unwrap();

        let mut client = sentinelpass_protocol::UnixSocketConnection::connect(socket_path.clone())
            .await
            .unwrap();
        let conn = transport.accept().await.expect("same-euid peer accepted");
        // Exchange a frame to prove the connection is live.
        client.write_message(b"ping").await.unwrap();
        let mut conn = conn;
        let msg = conn.read_message().await.unwrap();
        assert_eq!(msg, b"ping");
        let _ = std::fs::remove_file(&socket_path);
    }
}
