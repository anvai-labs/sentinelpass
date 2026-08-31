//! Protocol-level errors.

use thiserror::Error;

/// Errors returned by protocol operations (client I/O, token management,
/// frame crypto).
#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("IPC error: {0}")]
    Ipc(String),
}
