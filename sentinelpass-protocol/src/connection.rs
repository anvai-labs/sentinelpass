//! Connection-level session negotiation, deadlines, and framing
//! (WBS-509/510/511). Wraps a platform transport connection and speaks
//! either the v1 SECURED session protocol (default) or the legacy PLAIN
//! envelope protocol (server-accepted migration window, removed in 1.0).

use crate::session::{self, SessionCrypto, SESSION_READ_DEADLINE};
use crate::transport::{TransportError, TransportResult};

/// A connected transport (either platform).
pub enum TransportConnection {
    #[cfg(unix)]
    Unix(crate::transport::unix::UnixSocketConnection),
    #[cfg(windows)]
    Windows(crate::transport::windows::WindowsNamedPipeConnection),
}

#[cfg(unix)]
impl From<crate::transport::unix::UnixSocketConnection> for TransportConnection {
    fn from(conn: crate::transport::unix::UnixSocketConnection) -> Self {
        Self::Unix(conn)
    }
}

#[cfg(windows)]
impl From<crate::transport::windows::WindowsNamedPipeConnection> for TransportConnection {
    fn from(conn: crate::transport::windows::WindowsNamedPipeConnection) -> Self {
        Self::Windows(conn)
    }
}

impl TransportConnection {
    async fn read_frame(&mut self) -> TransportResult<Vec<u8>> {
        match self {
            #[cfg(unix)]
            TransportConnection::Unix(conn) => conn.read_message().await,
            #[cfg(windows)]
            TransportConnection::Windows(conn) => conn.read_message().await,
        }
    }

    async fn write_frame(&mut self, data: &[u8]) -> TransportResult<()> {
        match self {
            #[cfg(unix)]
            TransportConnection::Unix(conn) => conn.write_message(data).await,
            #[cfg(windows)]
            TransportConnection::Windows(conn) => conn.write_message(data).await,
        }
    }
}

/// One negotiated IPC connection.
pub enum IpcConnection {
    /// v1 session: every envelope frame is sealed (WBS-509/510).
    Secured {
        conn: Box<TransportConnection>,
        crypto: SessionCrypto,
    },
    /// Legacy plaintext envelopes — migration window only, server-side
    /// accepted and announced (ADR-007; removed in 1.0).
    Plain { conn: Box<TransportConnection> },
}

impl IpcConnection {
    /// Client-side negotiation (WBS-509): send SessionHello, read
    /// SessionAccept, derive the directional session keys.
    pub async fn connect_client(
        mut conn: TransportConnection,
        token: &str,
    ) -> TransportResult<Self> {
        let (hello, client_random) = session::new_hello();
        let hello_bytes = serde_json::to_vec(&hello)
            .map_err(|e| TransportError::Other(format!("hello encode: {e}")))?;
        tokio::time::timeout(SESSION_READ_DEADLINE, conn.write_frame(&hello_bytes))
            .await
            .map_err(|_| TransportError::Timeout)??;

        let reply = tokio::time::timeout(SESSION_READ_DEADLINE, conn.read_frame())
            .await
            .map_err(|_| TransportError::Timeout)??;
        let accept = session::parse_accept(&reply)?;
        let server_random = session::server_random_of(&accept)?;
        let (c2s, s2c) = session::derive_directional_keys(token, &client_random, &server_random)?;
        Ok(IpcConnection::Secured {
            conn: Box::new(conn),
            crypto: SessionCrypto::client(c2s, s2c),
        })
    }

    /// Server-side negotiation: peek the first frame. A SessionHello →
    /// SECURED (reply SessionAccept, derive keys). Anything else → the
    /// legacy PLAIN envelope protocol; the first frame is handed back to
    /// the caller for normal processing.
    pub async fn accept_server(
        mut conn: TransportConnection,
        token: &str,
    ) -> TransportResult<(Self, Option<Vec<u8>>)> {
        let first = tokio::time::timeout(SESSION_READ_DEADLINE, conn.read_frame())
            .await
            .map_err(|_| TransportError::Timeout)??;

        if session::is_session_hello(&first) {
            let hello = session::parse_hello(&first)?;
            let client_random = session::client_random_of(&hello)?;
            let (accept, server_random) = session::new_accept();
            let accept_bytes = serde_json::to_vec(&accept)
                .map_err(|e| TransportError::Other(format!("accept encode: {e}")))?;
            tokio::time::timeout(SESSION_READ_DEADLINE, conn.write_frame(&accept_bytes))
                .await
                .map_err(|_| TransportError::Timeout)??;
            let (c2s, s2c) =
                session::derive_directional_keys(token, &client_random, &server_random)?;
            Ok((
                IpcConnection::Secured {
                    conn: Box::new(conn),
                    crypto: SessionCrypto::server(c2s, s2c),
                },
                None,
            ))
        } else {
            // Legacy plaintext client (migration window; announced once per
            // connection so operators can find stragglers).
            tracing::warn!(
                "accepted LEGACY plaintext IPC connection (no session handshake) — \
                 upgrade the client; the plaintext window is removed in 1.0"
            );
            Ok((
                IpcConnection::Plain {
                    conn: Box::new(conn),
                },
                Some(first),
            ))
        }
    }

    /// Send one envelope frame (sealed in secured mode), write-bounded by
    /// the session deadline (WBS-511).
    pub async fn send_frame(&mut self, envelope_bytes: &[u8]) -> TransportResult<()> {
        match self {
            IpcConnection::Secured { conn, crypto } => {
                let sealed = crypto.seal(envelope_bytes)?;
                tokio::time::timeout(SESSION_READ_DEADLINE, conn.write_frame(&sealed))
                    .await
                    .map_err(|_| TransportError::Timeout)??;
                Ok(())
            }
            IpcConnection::Plain { conn } => {
                tokio::time::timeout(SESSION_READ_DEADLINE, conn.write_frame(envelope_bytes))
                    .await
                    .map_err(|_| TransportError::Timeout)??;
                Ok(())
            }
        }
    }

    /// Receive one envelope frame (opened in secured mode), bounded by the
    /// read deadline (WBS-511).
    pub async fn recv_frame(&mut self) -> TransportResult<Vec<u8>> {
        let raw = tokio::time::timeout(SESSION_READ_DEADLINE, self.read_raw())
            .await
            .map_err(|_| TransportError::Timeout)??;
        match self {
            IpcConnection::Secured { crypto, .. } => crypto.open(&raw),
            IpcConnection::Plain { .. } => Ok(raw),
        }
    }

    async fn read_raw(&mut self) -> TransportResult<Vec<u8>> {
        match self {
            IpcConnection::Secured { conn, .. } => conn.read_frame().await,
            IpcConnection::Plain { conn } => conn.read_frame().await,
        }
    }
}
