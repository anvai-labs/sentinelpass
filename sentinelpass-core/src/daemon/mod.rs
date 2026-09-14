//! Daemon module for background service and native messaging.

pub mod autolock;
pub mod capabilities;
pub mod ipc;
pub mod maintenance;
pub mod native_messaging;
pub mod service;
pub mod site_permissions;
pub mod transport;
pub mod vault_state;

pub use capabilities::{
    default_store_path, ensure_native_host_capability, load_native_host_capability,
    InstallationCapabilities, NATIVE_HOST_AUDIENCE,
};
pub use ipc::{
    default_ipc_socket_path, default_ipc_token_path, load_ipc_token, load_or_create_ipc_token,
    IpcClient, IpcMessage, IpcServer,
};
pub use maintenance::{maintenance_lock_path, try_acquire, MaintenanceLockGuard};
pub use native_messaging::{NativeMessage, NativeMessagingHost};
pub use service::{LiveVaultService, VaultApplicationService};
pub use transport::TransportConfig;
pub use vault_state::{CredentialResponse, DaemonVault, TotpCodeResponse, VaultState};
