//! Daemon module for background service and native messaging.

pub mod autolock;
pub mod ipc;
pub mod native_messaging;
pub mod service;
pub mod transport;
pub mod vault_state;

pub use ipc::{
    default_ipc_socket_path, default_ipc_token_path, load_ipc_token, load_or_create_ipc_token,
    IpcClient, IpcMessage, IpcServer,
};
pub use native_messaging::{NativeMessage, NativeMessagingHost};
pub use service::{LiveVaultService, VaultApplicationService};
pub use transport::TransportConfig;
pub use vault_state::{CredentialResponse, DaemonVault, TotpCodeResponse, VaultState};
