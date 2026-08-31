//! Windows named pipe transport (server-side).
//!
//! The connection type ([`WindowsNamedPipeConnection`], symmetric
//! client/server) and client connect logic live in `sentinelpass_protocol`.

pub use sentinelpass_protocol::transport::windows::connect_named_pipe;
pub use sentinelpass_protocol::WindowsNamedPipeConnection;

use super::{TransportConfig, TransportError, TransportResult};

/// Windows named pipe transport
pub struct WindowsNamedPipeTransport {
    pipe_name: String,
}

impl WindowsNamedPipeTransport {
    /// Create a new Windows named pipe transport
    pub fn new(config: TransportConfig) -> TransportResult<Self> {
        let pipe_name = config
            .windows_pipe_path
            .or_else(|| {
                // Default to named pipe
                Some(r"\\.\pipe\SentinelPass".to_string())
            })
            .ok_or_else(|| TransportError::Other("Windows pipe path not configured".to_string()))?;

        Ok(Self { pipe_name })
    }

    /// Get the pipe name
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Create a new named pipe server instance
    pub fn create_server(
        &self,
    ) -> TransportResult<tokio::net::windows::named_pipe::NamedPipeServer> {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(false)
            .create(&self.pipe_name)
            .map_err(|e| {
                TransportError::ConnectionFailed(format!(
                    "Failed to create named pipe {}: {}",
                    self.pipe_name, e
                ))
            })
    }

    /// Connect as a client (with timeout)
    pub async fn connect(&self, timeout_ms: u64) -> TransportResult<WindowsNamedPipeConnection> {
        connect_named_pipe(&self.pipe_name, timeout_ms).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_named_pipe_transport_creation() {
        let transport = WindowsNamedPipeTransport::new(TransportConfig {
            windows_pipe_path: Some(r"\\.\pipe\SentinelPass-Test".to_string()),
            ..Default::default()
        });

        assert!(transport.is_ok());
        let transport = transport.unwrap();
        assert_eq!(transport.pipe_name(), r"\\.\pipe\SentinelPass-Test");
    }

    #[test]
    fn test_windows_named_pipe_transport_default() {
        let transport = WindowsNamedPipeTransport::new(TransportConfig::default()).unwrap();
        assert_eq!(transport.pipe_name(), r"\\.\pipe\SentinelPass");
    }

    #[test]
    fn test_transport_config_for_windows() {
        let _config = TransportConfig::for_current_platform();
        // On Windows, this should have a pipe path
        // But this test runs on all platforms, so we just verify it doesn't panic
    }
}
