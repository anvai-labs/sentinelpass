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
