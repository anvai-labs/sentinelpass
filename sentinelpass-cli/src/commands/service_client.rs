//! Vault backend selection for CLI commands (WBS-502, ADR-007).
//!
//! Every vault-touching CLI command goes through ONE of two backends that
//! implement the SAME application-service contract (`VaultOp`):
//!
//! - [`Backend::Daemon`] (default): the running daemon executes the op via
//!   application-service IPC — the daemon is the sole live DEK owner and
//!   vault writer.
//! - [`Backend::Direct`] (compatibility window, FLAGGED): the CLI opens the
//!   vault directly and executes the op in-process via the same
//!   `LiveVaultService`. Only reachable with
//!   `SENTINELPASS_ALLOW_DIRECT_VAULT=1` set, always announces itself on
//!   stderr, and takes the exclusive maintenance lock (refusing while a
//!   daemon owns the vault), so it can never race the daemon. This is the
//!   temporary migration window of ADR-007; it is removed once official
//!   clients no longer ship direct-write paths.

use anyhow::{anyhow, Result};
use sentinelpass_core::daemon::service::{LiveVaultService, VaultApplicationService};
use sentinelpass_core::daemon::{default_ipc_socket_path, IpcClient, IpcMessage};
use sentinelpass_core::VaultManager;
use sentinelpass_protocol::service::{VaultOp, VaultOpResult};
use std::path::PathBuf;

/// Environment variable enabling the FLAGGED direct-write compatibility
/// path (ADR-007 migration window; removed in 1.0).
pub const DIRECT_VAULT_ENV: &str = "SENTINELPASS_ALLOW_DIRECT_VAULT";

/// Is the FLAGGED direct-write compatibility path explicitly enabled?
pub fn direct_vault_compat_enabled() -> bool {
    std::env::var(DIRECT_VAULT_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// One vault backend.
pub enum Backend {
    Daemon(IpcClient),
    /// Direct in-process access — compatibility window only. Holds the
    /// exclusive maintenance lock for as long as it lives.
    Direct {
        _lock: sentinelpass_core::daemon::MaintenanceLockGuard,
        vault: VaultManager,
    },
}

impl Backend {
    /// Probe for a reachable daemon. `Ok(None)` = no reachable daemon (the
    /// caller decides between the compat path and an error).
    pub async fn probe() -> Result<Option<IpcClient>> {
        let client = match IpcClient::new_for_cli(default_ipc_socket_path(), None) {
            Ok(client) => client,
            Err(_) => return Ok(None), // no IPC token yet / daemon never configured
        };
        match client.send(IpcMessage::CheckVault).await {
            Ok(IpcMessage::VaultStatusResponse { .. }) => Ok(Some(client)),
            Ok(_) => Ok(Some(client)),
            Err(_) => Ok(None),
        }
    }

    /// Acquire the direct-write compatibility backend: FLAGGED, exclusive.
    ///
    /// Takes the maintenance lock, so this refuses while a daemon owns the
    /// vault — the lock, not a reachability probe, is the authority
    /// boundary (WBS-503).
    pub fn direct_compat(vault_path: &PathBuf, master_password: &[u8]) -> Result<Backend> {
        eprintln!(
            "WARNING: {DIRECT_VAULT_ENV}=1 — DIRECT vault access (compatibility window): \
             this process opens and writes the vault itself, bypassing daemon authority \
             (ADR-007). This mode is temporary and announced on every use."
        );
        let lock = sentinelpass_core::daemon::try_acquire(vault_path)?;
        let vault = crate::open_vault_with_password(vault_path, master_password)?;
        Ok(Backend::Direct { _lock: lock, vault })
    }

    /// Execute one application-service op against this backend.
    pub fn call(&self, op: VaultOp) -> Result<VaultOpResult> {
        match self {
            Backend::Daemon(client) => {
                // block_on accepts borrowed futures: the client is
                // runtime-agnostic (no stored runtime handles).
                let result = crate::run_async(client.call_service(op))??;
                Ok(result)
            }
            Backend::Direct { vault, .. } => {
                let service = LiveVaultService::new(vault);
                service.execute(&op).map_err(|e| anyhow!(e.to_string()))
            }
        }
    }

    /// Ensure the backend can serve ops: for the daemon backend, unlock it
    /// with `master_password` when locked. Direct backends are constructed
    /// unlocked.
    pub fn ensure_unlocked(&self, master_password: &str) -> Result<()> {
        match self {
            Backend::Direct { .. } => Ok(()),
            Backend::Daemon(client) => {
                let master_password = master_password.to_string();
                let outcome = crate::run_async(async {
                    let status = client.send(IpcMessage::CheckVault).await.ok()?;
                    if let IpcMessage::VaultStatusResponse {
                        unlocked: false, ..
                    } = &status
                    {
                        return client
                            .send(IpcMessage::UnlockVault {
                                master_password: master_password.clone(),
                            })
                            .await
                            .ok();
                    }
                    match status {
                        IpcMessage::VaultStatusResponse { unlocked: true, .. } => {
                            Some(IpcMessage::UnlockVaultResponse {
                                success: true,
                                error: None,
                            })
                        }
                        _ => None,
                    }
                })?;
                match outcome {
                    Some(IpcMessage::UnlockVaultResponse { success: true, .. }) => Ok(()),
                    Some(IpcMessage::UnlockVaultResponse {
                        success: false,
                        error,
                    }) => Err(anyhow!(
                        "daemon unlock failed: {}",
                        error.unwrap_or_else(|| "unknown error".to_string())
                    )),
                    _ => Err(anyhow!("unexpected daemon response while unlocking")),
                }
            }
        }
    }

    /// Whether the daemon currently reports the vault unlocked. Direct
    /// backends are always unlocked (they were opened with the password).
    pub fn is_unlocked(&self) -> Result<bool> {
        match self {
            Backend::Direct { .. } => Ok(true),
            Backend::Daemon(client) => {
                let unlocked = crate::run_async(async {
                    match client.send(IpcMessage::CheckVault).await {
                        Ok(IpcMessage::VaultStatusResponse { unlocked, .. }) => unlocked,
                        _ => false,
                    }
                })?;
                Ok(unlocked)
            }
        }
    }
}

/// Resolve the backend for a command that needs an UNLOCKED vault:
/// - prefer the daemon (prompting for the master password only when the
///   daemon is locked);
/// - custom `--vault` paths are never served by the daemon (it owns the
///   DEFAULT vault) — they go straight to the compat decision;
/// - fall back to the FLAGGED compat path only when the env var is set;
/// - otherwise fail with actionable guidance.
pub fn connect(
    vault_path: &PathBuf,
    prompt_master_password: impl Fn() -> Result<String>,
) -> Result<Backend> {
    let default_vault = sentinelpass_core::get_default_vault_path();
    if vault_path != &default_vault {
        // The daemon owns exactly the default vault; a custom path can only
        // be served by the flagged compat path.
        if direct_vault_compat_enabled() {
            let password = prompt_master_password()?;
            return Backend::direct_compat(vault_path, password.as_bytes());
        }
        anyhow::bail!(
            "No reachable SentinelPass daemon serves a custom vault path (the daemon owns \
             the default vault). Start the daemon for the default vault, drop the \
             --vault override, or set {DIRECT_VAULT_ENV}=1 (flagged compatibility mode)."
        );
    }

    let probed = crate::run_async(Backend::probe())??;
    match probed {
        Some(client) => {
            let backend = Backend::Daemon(client);
            let locked = !backend.is_unlocked()?;
            if locked {
                let password = prompt_master_password()?;
                backend.ensure_unlocked(&password)?;
            }
            Ok(backend)
        }
        None => {
            if direct_vault_compat_enabled() {
                let password = prompt_master_password()?;
                Backend::direct_compat(vault_path, password.as_bytes())
            } else {
                Err(anyhow!(
                    "No reachable SentinelPass daemon. Start it with `sentinelpass-daemon` \
                     (or launch the desktop app), then retry.\n\
                     If this machine cannot run the daemon, set {DIRECT_VAULT_ENV}=1 to \
                     operate on the vault directly (flagged compatibility mode)."
                ))
            }
        }
    }
}

/// Pull a `Report(Value)` payload out of a service result.
pub fn expect_report(result: VaultOpResult) -> Result<serde_json::Value> {
    match result {
        VaultOpResult::Report(value) => Ok(value),
        other => Err(anyhow!("expected a report result, got {other:?}")),
    }
}
