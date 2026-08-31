//! Wire framing and platform connection types for IPC clients.
//!
//! Server-side transports (listeners) live in `sentinelpass-core`; this
//! module holds everything a client needs plus the shared connection types.

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

use std::io;

/// Maximum message size for IPC (64KB)
pub const MAX_MESSAGE_SIZE: usize = 65536;

/// Result type for transport operations
pub type TransportResult<T> = Result<T, TransportError>;

/// Transport-specific errors
#[derive(Debug)]
pub enum TransportError {
    ConnectionFailed(String),
    Io(io::Error),
    MessageTooLarge { size: usize, max: usize },
    InvalidFormat(String),
    Encryption(String),
    Decryption(String),
    Closed,
    Timeout,
    Other(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::MessageTooLarge { size, max } => {
                write!(f, "Message too large: {} bytes (max: {} bytes)", size, max)
            }
            Self::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            Self::Encryption(msg) => write!(f, "Encryption failed: {}", msg),
            Self::Decryption(msg) => write!(f, "Decryption failed: {}", msg),
            Self::Closed => write!(f, "Transport closed"),
            Self::Timeout => write!(f, "Timeout"),
            Self::Other(msg) => write!(f, "Other: {}", msg),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for TransportError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Transport configuration
#[derive(Debug, Clone, Default)]
pub struct TransportConfig {
    /// Path for Unix domain socket
    pub unix_socket_path: Option<String>,

    /// Path for Windows named pipe
    pub windows_pipe_path: Option<String>,

    /// TCP address for fallback (Windows only)
    pub tcp_fallback_addr: Option<String>,

    /// Authentication token for encrypted transports
    pub auth_token: Option<String>,
}

impl TransportConfig {
    /// Create a new transport configuration with defaults for the current platform
    pub fn for_current_platform() -> Self {
        #[cfg(unix)]
        {
            let runtime_dir =
                std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
            Self {
                unix_socket_path: Some(format!("{}/sentinelpass.sock", runtime_dir)),
                ..Default::default()
            }
        }

        #[cfg(windows)]
        {
            Self {
                windows_pipe_path: Some(r"\\.\pipe\SentinelPass".to_string()),
                tcp_fallback_addr: Some("127.0.0.1:35873".to_string()),
                ..Default::default()
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            Self::default()
        }
    }

    /// Set the authentication token
    pub fn with_auth_token(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    /// Set the Unix socket path
    pub fn with_unix_socket(mut self, path: String) -> Self {
        self.unix_socket_path = Some(path);
        self
    }

    /// Set the Windows named pipe path
    pub fn with_windows_pipe(mut self, path: String) -> Self {
        self.windows_pipe_path = Some(path);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_config_defaults() {
        let config = TransportConfig::default();
        assert!(config.unix_socket_path.is_none());
        assert!(config.windows_pipe_path.is_none());
        assert!(config.auth_token.is_none());
    }

    #[test]
    fn test_transport_config_builder() {
        let config = TransportConfig::default()
            .with_auth_token("test_token".to_string())
            .with_unix_socket("/tmp/test.sock".to_string());

        assert_eq!(config.auth_token, Some("test_token".to_string()));
        assert_eq!(config.unix_socket_path, Some("/tmp/test.sock".to_string()));
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
}
