//! Transport abstraction for IPC communication.
//!
//! Shared wire types (framing limits, errors, config, connection types) live
//! in [`sentinelpass_protocol`]; this module keeps the server-side transports
//! (Unix socket listener, Windows named-pipe/TCP servers) and re-exports the
//! shared types so existing paths keep working.

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
pub use sentinelpass_protocol::UnixSocketConnection;
#[cfg(windows)]
pub use sentinelpass_protocol::WindowsNamedPipeConnection;
pub use sentinelpass_protocol::{
    TransportConfig, TransportError, TransportResult, MAX_MESSAGE_SIZE,
};

use crate::DatabaseError;

/// SP-2 / ADR-015: server-owned trusted peer context — one per accepted
/// connection, constructed ONLY by the platform accept path from
/// kernel-derived values, threaded through dispatch as a parameter
/// (never deserialized from any wire, never shared across connections).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerContext {
    /// SP-0 step-up connection identity (approvals bind to it).
    pub connection_id: u128,
    /// Peer effective UID (kernel-verified; equals daemon euid on the
    /// Unix accept path by the WBS-507 refusal).
    pub uid: u32,
    pub gid: Option<u32>,
    /// Linux only (`SO_PEERCRED` carries the connecting pid); `None`
    /// elsewhere or when the kernel could not attribute it. SP-3's
    /// executable policy will resolve `/proc/<pid>/exe` from it.
    pub pid: Option<u32>,
}

impl PeerContext {
    /// Redacted provenance token for audit context lines — digits, colons
    /// and fixed labels only; nothing client-supplied rides in it.
    /// The `unknown()` marker renders the explicit `peer=unknown` token
    /// (never a root-lookalike `peer=uid:0`).
    pub fn provenance_token(&self) -> String {
        if self.is_unknown() {
            return Self::UNKNOWN_TOKEN.to_string();
        }
        format!(
            "peer=uid:{}{}{}",
            self.uid,
            self.gid.map(|g| format!(":gid:{g}")).unwrap_or_default(),
            self.pid.map(|p| format!(":pid:{p}")).unwrap_or_default(),
        )
    }

    /// The "no peer context available" shape: uid 0 with no gid/pid.
    /// Windows named pipes use this (no portable credential query);
    /// it renders as the explicit unknown marker, not as root.
    pub fn unknown(connection_id: u128) -> Self {
        Self {
            connection_id,
            uid: 0,
            gid: None,
            pid: None,
        }
    }

    pub fn is_unknown(&self) -> bool {
        self.uid == 0 && self.gid.is_none() && self.pid.is_none()
    }

    /// The "no peer context" degradation marker.
    pub const UNKNOWN_TOKEN: &'static str = "peer=unknown";
}

impl From<TransportError> for DatabaseError {
    fn from(err: TransportError) -> Self {
        DatabaseError::Ipc(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_transport_config_defaults() {
        let config = TransportConfig::default();
        assert!(config.unix_socket_path.is_none());
        assert!(config.windows_pipe_path.is_none());
        assert!(config.auth_token.is_none());
    }

    #[test]
    fn test_max_message_size() {
        assert_eq!(MAX_MESSAGE_SIZE, 65536);
    }

    #[test]
    fn test_transport_error_display() {
        let err = TransportError::ConnectionFailed("test".to_string());
        assert_eq!(err.to_string(), "Connection failed: test");

        let err = TransportError::MessageTooLarge {
            size: 100000,
            max: 65536,
        };
        assert_eq!(
            err.to_string(),
            "Message too large: 100000 bytes (max: 65536 bytes)"
        );
    }

    #[test]
    fn test_transport_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "test");
        let transport_err: TransportError = io_err.into();
        assert!(matches!(transport_err, TransportError::Io(_)));
    }

    #[test]
    fn test_transport_error_conversion() {
        let transport_err = TransportError::Io(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));
        let db_err: DatabaseError = transport_err.into();
        assert!(matches!(db_err, DatabaseError::Ipc(_)));
    }
}
