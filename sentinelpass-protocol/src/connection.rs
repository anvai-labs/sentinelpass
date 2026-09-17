//! Connection-level session negotiation, deadlines, and framing
//! (WBS-509/510/511). Wraps a platform transport connection and speaks
//! either the v1 SECURED session protocol (default) or — only when the
//! operator explicitly re-opens the migration window with
//! `SENTINELPASS_ALLOW_PLAIN_IPC=1` — the legacy PLAIN envelope protocol
//! (WBS-911 F3: previously accepted UNCONDITIONALLY; the documented
//! "removed in 1.0" claim now holds by default).

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

/// Whether the operator re-opened the legacy PLAIN-session migration
/// window. Same exact-value pattern as the daemon's other announced legacy
/// windows (`SENTINELPASS_ALLOW_SELF_ASSERTED_ORIGIN` /
/// `SENTINELPASS_ALLOW_LEGACY_ORIGINLESS`): only the literal `1` opts in
/// (WBS-911 F3).
fn plain_ipc_window_enabled() -> bool {
    std::env::var("SENTINELPASS_ALLOW_PLAIN_IPC")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// One negotiated IPC connection.
pub enum IpcConnection {
    /// v1 session: every envelope frame is sealed (WBS-509/510).
    Secured {
        conn: Box<TransportConnection>,
        crypto: SessionCrypto,
    },
    /// Legacy plaintext envelopes — migration window only, accepted
    /// server-side ONLY while `SENTINELPASS_ALLOW_PLAIN_IPC=1` is set and
    /// announced per connection (ADR-007; WBS-911 F3). Refused otherwise.
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
    /// legacy PLAIN envelope protocol, ONLY while the operator has re-opened
    /// the migration window with `SENTINELPASS_ALLOW_PLAIN_IPC=1` (WBS-911
    /// F3: the bearer-token envelope crosses the socket in cleartext, so the
    /// default is refuse); the first frame is handed back to the caller for
    /// normal processing.
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
        } else if plain_ipc_window_enabled() {
            // Legacy plaintext client (migration window; announced once per
            // connection so operators can find stragglers).
            tracing::warn!(
                "accepted LEGACY plaintext IPC connection (no session handshake) via \
                 SENTINELPASS_ALLOW_PLAIN_IPC=1 — the bearer envelope crosses the \
                 socket unencrypted; upgrade the client; the plaintext window is \
                 removed in 1.0"
            );
            Ok((
                IpcConnection::Plain {
                    conn: Box::new(conn),
                },
                Some(first),
            ))
        } else {
            Err(TransportError::Other(
                "refused LEGACY plaintext IPC session (no session handshake): the \
                 envelope bearer token would cross the socket in cleartext. Upgrade \
                 the client to a SECURED-session build; operators can temporarily \
                 re-open the migration window with SENTINELPASS_ALLOW_PLAIN_IPC=1 \
                 (removed in 1.0)"
                    .to_string(),
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::transport::unix::UnixSocketConnection;

    /// Env is process-global: every env-touching test holds this lock for
    /// its whole body (same pattern as the daemon gate tests).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn set_env(key: &str, value: Option<&str>) {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    /// A connected loopback pair: `.0` plays the daemon side, `.1` the
    /// client (an unnamed socket pair — no filesystem, no runtime-dir
    /// policy involved).
    fn socket_pair() -> (TransportConnection, TransportConnection) {
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        (
            TransportConnection::Unix(UnixSocketConnection::from_stream(a)),
            TransportConnection::Unix(UnixSocketConnection::from_stream(b)),
        )
    }

    const TOKEN: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// WBS-911 F3 (the fix): a first frame that is not a SessionHello is
    /// REFUSED by default — the plaintext window is closed, as documented
    /// ("removed in 1.0").
    // ENV_LOCK is process-global and must span the whole async body (same
    // discipline as the daemon gate tests); the guard is never shared
    // across a real concurrency boundary here.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn plain_first_frame_is_refused_by_default() {
        let _env = ENV_LOCK.lock().unwrap();
        set_env("SENTINELPASS_ALLOW_PLAIN_IPC", None);

        let (server_conn, mut client) = socket_pair();
        client
            .write_frame(br#"{"token":"t","message":"CheckVault"}"#)
            .await
            .unwrap();

        let err = match IpcConnection::accept_server(server_conn, TOKEN).await {
            Err(err) => err,
            Ok(_) => panic!("plaintext session must be refused without the opt-in"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("SENTINELPASS_ALLOW_PLAIN_IPC"),
            "refusal must name the escape hatch: {msg}"
        );
        assert!(
            msg.contains("plaintext"),
            "refusal must name the policy: {msg}"
        );
    }

    /// Only the exact value "1" opts in (same discipline as the other
    /// legacy windows).
    // ENV_LOCK is process-global and must span the whole async body (same
    // discipline as the daemon gate tests); the guard is never shared
    // across a real concurrency boundary here.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn plain_first_frame_refused_for_non_canonical_env_value() {
        let _env = ENV_LOCK.lock().unwrap();
        set_env("SENTINELPASS_ALLOW_PLAIN_IPC", Some("yes"));

        let (server_conn, mut client) = socket_pair();
        client
            .write_frame(br#"{"token":"t","message":"CheckVault"}"#)
            .await
            .unwrap();

        assert!(IpcConnection::accept_server(server_conn, TOKEN)
            .await
            .is_err());
        set_env("SENTINELPASS_ALLOW_PLAIN_IPC", None);
    }

    /// Opted-in operators get the legacy behavior: Plain session, first
    /// frame handed back, and the session carries plaintext both ways.
    // ENV_LOCK is process-global and must span the whole async body (same
    // discipline as the daemon gate tests); the guard is never shared
    // across a real concurrency boundary here.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn plain_first_frame_is_accepted_with_explicit_opt_in() {
        let _env = ENV_LOCK.lock().unwrap();
        set_env("SENTINELPASS_ALLOW_PLAIN_IPC", Some("1"));

        let (server_conn, mut client) = socket_pair();
        let first_frame = br#"{"token":"t","message":"CheckVault"}"#;
        client.write_frame(first_frame).await.unwrap();

        let (mut ipc, first) = IpcConnection::accept_server(server_conn, TOKEN)
            .await
            .expect("opted-in plaintext session must be accepted");
        assert_eq!(first.as_deref(), Some(&first_frame[..]));

        // The Plain session round-trips UNSEALED frames.
        let reply = br#"{"token":"t","message":"VaultStatusResponse"}"#;
        ipc.send_frame(reply).await.unwrap();
        assert_eq!(client.read_frame().await.unwrap(), reply.to_vec());

        set_env("SENTINELPASS_ALLOW_PLAIN_IPC", None);
    }

    /// The default SECURED path is untouched by the gate: hello in, accept
    /// out, sealed envelopes in both directions.
    // ENV_LOCK is process-global and must span the whole async body (same
    // discipline as the daemon gate tests); the guard is never shared
    // across a real concurrency boundary here.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn secured_negotiation_still_works_by_default() {
        let _env = ENV_LOCK.lock().unwrap();
        set_env("SENTINELPASS_ALLOW_PLAIN_IPC", None);

        let (server_conn, client_conn) = socket_pair();
        let server =
            tokio::spawn(async move { IpcConnection::accept_server(server_conn, TOKEN).await });
        let client = IpcConnection::connect_client(client_conn, TOKEN)
            .await
            .expect("secured negotiation must succeed");

        let (ipc, first) = server.await.unwrap().unwrap();
        assert_eq!(first, None, "the secured path hands back no first frame");
        assert!(matches!(ipc, IpcConnection::Secured { .. }));
        assert!(matches!(client, IpcConnection::Secured { .. }));
    }
}
