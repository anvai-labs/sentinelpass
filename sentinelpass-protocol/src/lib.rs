//! SentinelPass IPC protocol contract.
//!
//! This crate is the narrow, stable surface that daemon clients embed:
//! message types, the authentication envelope, wire framing (length-prefixed
//! frames, 64 KiB cap), platform transports (client side), token file
//! management, and [`IpcClient`].
//!
//! Stability rules:
//! - Every wire type must deserialize old payloads (serde defaults for new
//!   fields; unknown fields are ignored by serde).
//! - Framing and Windows AES-256-GCM frame format never change byte layout.
//!
//! Server-side types (listeners, the request dispatcher) intentionally live
//! in `sentinelpass-core`, not here.

pub mod client;
pub mod envelope;
pub mod error;
pub mod message;
pub mod paths;
pub mod token;
pub mod transport;
#[cfg(windows)]
pub mod windows_frame;

pub use client::IpcClient;
pub use envelope::IpcEnvelope;
pub use error::ProtocolError;
pub use message::{CredentialSummary, ExternalSecretField, IpcMessage};
pub use paths::{default_ipc_socket_path, default_ipc_token_path, get_config_dir};
pub use token::{load_ipc_token, load_or_create_ipc_token};
#[cfg(unix)]
pub use transport::unix::UnixSocketConnection;
#[cfg(windows)]
pub use transport::windows::WindowsNamedPipeConnection;
pub use transport::{TransportConfig, TransportError, TransportResult, MAX_MESSAGE_SIZE};
#[cfg(windows)]
pub use windows_frame::{
    decrypt_windows_ipc_frame, encrypt_windows_ipc_frame, windows_named_pipe_path,
};

pub type Result<T> = std::result::Result<T, ProtocolError>;
