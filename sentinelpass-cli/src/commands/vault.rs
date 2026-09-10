use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::daemon::ipc::{default_ipc_socket_path, IpcClient, IpcMessage};
use sentinelpass_core::VaultManager;
use std::path::{Path, PathBuf};
use tracing::error;

/// Best-effort daemon reachability probe: attempts a real IPC round trip
/// (`CheckVault`) rather than checking whether the socket path exists.
///
/// Socket-file existence is not a reliable signal cross-platform — on
/// Windows the default transport is a named pipe, which `Path::exists()`
/// does not detect — and even on Unix a stale socket file can outlive its
/// daemon. `None` means "no reachable daemon" (covers: no IPC token yet,
/// connection refused, any other transport error); `Some((unlocked,
/// key_epoch))` means a daemon answered.
async fn probe_daemon() -> Option<(bool, i64)> {
    let client = IpcClient::new_for_cli(default_ipc_socket_path(), None).ok()?;
    match client.send(IpcMessage::CheckVault).await.ok()? {
        IpcMessage::VaultStatusResponse {
            unlocked,
            key_epoch,
        } => Some((unlocked, key_epoch)),
        _ => None,
    }
}

pub fn handle_init(vault_path: PathBuf, dev: bool) -> Result<()> {
    println!("Initializing new SentinelPass vault...");
    if dev {
        println!("Running in development mode (in-memory database)");
    }

    // Check if vault already exists
    if !dev && vault_path.exists() {
        anyhow::bail!("Vault already exists at: {:?}", vault_path);
    }

    let password = crate::prompt_master_password(true)?;

    // WBS-503: creation is an exclusive offline operation — refuse while a
    // live daemon (or any maintenance process) owns the vault location.
    crate::with_maintenance_lock(&vault_path, || {
        // Create vault
        let vault = VaultManager::create(&vault_path, password.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to create vault: {}", e))?;

        println!("✓ Vault created successfully at: {:?}", vault_path);
        println!("✓ Your vault is now unlocked and ready to use");
        println!();
        println!("Next steps:");
        println!("  sentinelpass add --title 'GitHub' --username 'user@example.com'");
        println!("  sentinelpass list");

        // Vault is dropped here, which locks it
        drop(vault);
        Ok(())
    })
}

pub fn handle_unlock(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!(
            "No vault found at: {:?}\nUse 'sentinelpass init' to create a new vault",
            vault_path
        );
    }
    require_default_vault(&vault_path)?;

    // WBS-502: unlock means unlocking the DAEMON — the daemon owns the only
    // live DEK. The CLI no longer opens the vault locally at all.
    use crate::commands::service_client as sc;
    let password = prompt_password("Enter master password: ")?;
    match crate::run_async(sc::Backend::probe())?? {
        Some(client) => {
            let backend = sc::Backend::Daemon(client);
            let already = backend.is_unlocked()?;
            backend.ensure_unlocked(&password)?;
            if already {
                // Stage-3 review F4: an already-unlocked daemon accepts any
                // password — say so instead of a false validation success.
                println!("Daemon was already unlocked; the password was not verified.");
            } else {
                println!("✓ Daemon unlocked. The vault stays unlocked until auto-lock; `sentinelpass lock` locks it early.");
            }
        }
        None => anyhow::bail!(
            "No reachable SentinelPass daemon. Start it with `sentinelpass-daemon` \
             (or launch the desktop app), then retry."
        ),
    }
    Ok(())
}

/// Unlock/lock target the DAEMON's vault — the default one. A custom
/// `--vault` path is never daemon-served (stage-3 review F5).
fn require_default_vault(vault_path: &Path) -> Result<()> {
    if vault_path != sentinelpass_core::get_default_vault_path() {
        anyhow::bail!(
            "The daemon serves only the default vault; unlock/lock with a custom \
             --vault path is not supported. Drop the --vault override."
        );
    }
    Ok(())
}

pub fn handle_lock() -> Result<()> {
    use crate::commands::service_client as sc;
    match crate::run_async(sc::Backend::probe())?? {
        Some(_) => {
            // The service surface has no dedicated lock op (LockVault is a
            // legacy message); send it directly.
            let lock_client = sentinelpass_core::daemon::IpcClient::new_for_cli(
                sentinelpass_core::daemon::default_ipc_socket_path(),
                None,
            )?;
            crate::run_async(lock_client.send(sentinelpass_core::daemon::IpcMessage::LockVault))??;
            println!("✓ Daemon locked.");
        }
        None => anyhow::bail!(
            "No reachable SentinelPass daemon — the vault is not live anywhere. \
             Start the daemon to use it."
        ),
    }
    Ok(())
}

pub fn handle_biometric_status(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    // Read-only metadata (no DEK, no writes): served locally so the command
    // works even while the daemon is locked or stopped.
    let configured = VaultManager::is_biometric_unlock_enabled(&vault_path)?;
    let method_name = sentinelpass_core::BiometricManager::get_method_name();
    let available = sentinelpass_core::BiometricManager::is_available();
    let enrolled = sentinelpass_core::BiometricManager::is_enrolled();

    println!("Biometric method: {}", method_name);
    println!("Available: {}", if available { "yes" } else { "no" });
    println!("Enrolled: {}", if enrolled { "yes" } else { "no" });
    println!(
        "Configured for vault: {}",
        if configured { "yes" } else { "no" }
    );
    Ok(())
}

pub fn handle_biometric_enable(vault_path: PathBuf, master_password: Option<&str>) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    use crate::commands::service_client as sc;
    // Prompt at most ONCE (stage-3 review F2): the same password both
    // unlocks the daemon (if locked) and is validated by the enable op.
    let password = match master_password {
        Some(value) => value.to_string(),
        None => prompt_password("Enter master password: ")?,
    };
    let backend = sc::connect(&vault_path, || Ok(password.clone()))?;
    backend.call(sentinelpass_protocol::service::VaultOp::BiometricEnable {
        master_password: password.into(),
    })?;
    println!("Biometric unlock enabled for this vault.");
    Ok(())
}

pub fn handle_biometric_disable(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    use crate::commands::service_client as sc;
    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    backend.call(sentinelpass_protocol::service::VaultOp::BiometricDisable)?;
    println!("Biometric unlock disabled for this vault.");
    Ok(())
}

pub fn handle_unlock_biometric(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }
    require_default_vault(&vault_path)?;

    // WBS-502: biometric unlock means unlocking the DAEMON (it owns the only
    // live DEK); the platform prompt runs in the daemon process.
    use crate::commands::service_client as sc;
    let client = match crate::run_async(sc::Backend::probe())?? {
        Some(client) => client,
        None => anyhow::bail!(
            "No reachable SentinelPass daemon. Start it with `sentinelpass-daemon` \
             (or launch the desktop app), then retry."
        ),
    };
    let response = crate::run_async(client.send(
        sentinelpass_core::daemon::IpcMessage::UnlockVaultBiometric {
            prompt_reason: Some("Unlock SentinelPass vault".to_string()),
        },
    ))??;
    match response {
        sentinelpass_core::daemon::IpcMessage::UnlockVaultResponse { success: true, .. } => {
            println!("✓ Daemon unlocked via biometric authentication");
            Ok(())
        }
        sentinelpass_core::daemon::IpcMessage::UnlockVaultResponse {
            success: false,
            error,
        } => {
            error!(
                "Failed biometric unlock: {}",
                error.as_deref().unwrap_or("unknown error")
            );
            anyhow::bail!(
                "Biometric unlock failed: {}",
                error.as_deref().unwrap_or("unknown error")
            );
        }
        other => anyhow::bail!("unexpected daemon response: {other:?}"),
    }
}

/// Rotate the vault master password (ADR-002). Re-wraps the DEK under a new
/// master key; entry ciphertexts are untouched. WBS-503: rotation is an
/// exclusive offline operation — it takes the maintenance lock, refusing
/// while a live daemon owns the vault (stronger and race-free versus the
/// old reachability probe).
pub fn handle_passwd(vault_path: PathBuf) -> Result<()> {
    crate::with_maintenance_lock(&vault_path, || {
        let current = prompt_password("Current master password: ")?;
        let new_password = prompt_password("New master password (min 12 characters): ")?;
        let confirm = prompt_password("Confirm new master password: ")?;
        if new_password != confirm {
            anyhow::bail!("New passwords do not match");
        }
        if new_password.len() < 12 {
            anyhow::bail!("New master password must be at least 12 characters");
        }

        let mut vault = VaultManager::open(&vault_path, current.as_bytes()).map_err(|e| {
            anyhow::anyhow!("Current password incorrect or vault unavailable: {}", e)
        })?;

        let new_epoch = vault
            .change_master_password(current.as_bytes(), new_password.as_bytes())
            .map_err(|e| anyhow::anyhow!("Rotation failed: {}", e))?;

        println!(
            "✓ Master password rotated (key epoch {}). Entry data was not re-encrypted — \
             the data encryption key is unchanged; only its wrapper was re-keyed.",
            new_epoch
        );
        println!("Note: biometric unlock keeps working; paired sync devices must re-pair.");
        Ok(())
    })
}

/// Show vault metadata without requiring a master password: schema
/// version and master-password key epoch (ADR-002) are plaintext columns,
/// never the DEK. Also reports daemon reachability/unlock state (and its
/// own view of the epoch) on a best-effort basis, since an embedder or a
/// second device otherwise has no way to learn a rotation happened.
pub fn handle_status(vault_path: PathBuf) -> Result<()> {
    println!("Vault: {}", vault_path.display());

    if !vault_path.exists() {
        println!("  status: no vault at this path");
        return Ok(());
    }

    match VaultManager::inspect_metadata(&vault_path) {
        Ok(info) => {
            println!("  schema version: {}", info.schema_version);
            println!("  key epoch:      {}", info.key_epoch);
        }
        Err(e) => {
            println!("  metadata:       unavailable ({})", e);
        }
    }

    match crate::run_async(probe_daemon()).ok().flatten() {
        Some((unlocked, key_epoch)) => {
            println!(
                "  daemon:         reachable, {} (epoch {})",
                if unlocked { "unlocked" } else { "locked" },
                key_epoch
            );
        }
        None => println!("  daemon:         not reachable"),
    }

    Ok(())
}
