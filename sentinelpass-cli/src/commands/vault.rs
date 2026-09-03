use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::VaultManager;
use std::path::PathBuf;
use tracing::error;

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
}

pub fn handle_unlock(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!(
            "No vault found at: {:?}\nUse 'sentinelpass init' to create a new vault",
            vault_path
        );
    }

    let password = prompt_password("Enter master password: ")?;

    match crate::open_vault_with_password(&vault_path, password.as_bytes()) {
        Ok(vault) => {
            println!("✓ Vault unlocked successfully");
            drop(vault);
        }
        Err(e) => {
            error!("Failed to unlock vault: {}", e);
            return Err(e);
        }
    }
    Ok(())
}

pub fn handle_lock() -> Result<()> {
    println!("Vault locks automatically when the process exits.");
    println!("The vault is only kept in memory during operations.");
    Ok(())
}

pub fn handle_biometric_status(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

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

    let master_password = match master_password {
        Some(value) => value.to_string(),
        None => prompt_password("Enter master password: ")?,
    };
    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;
    vault.enable_biometric_unlock(master_password.as_bytes())?;
    println!("Biometric unlock enabled for this vault.");
    Ok(())
}

pub fn handle_biometric_disable(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = prompt_password("Enter master password: ")?;
    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;
    vault.disable_biometric_unlock()?;
    println!("Biometric unlock disabled for this vault.");
    Ok(())
}

pub fn handle_unlock_biometric(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let reason = "Unlock SentinelPass vault";
    match VaultManager::open_with_biometric(&vault_path, reason) {
        Ok(vault) => {
            println!("✓ Vault unlocked successfully via biometric authentication");
            drop(vault);
        }
        Err(e) => {
            error!("Failed biometric unlock: {}", e);
            anyhow::bail!("Biometric unlock failed: {}", e);
        }
    }
    Ok(())
}

/// Rotate the vault master password (ADR-002). Re-wraps the DEK under a new
/// master key; entry ciphertexts are untouched. Refuses while a daemon may
/// hold an unlocked copy of the vault.
pub fn handle_passwd(vault_path: PathBuf) -> Result<()> {
    let socket = sentinelpass_core::daemon::ipc::default_ipc_socket_path();
    if socket.exists() {
        anyhow::bail!(
            "A SentinelPass daemon appears to be running ({}). Quit it first — \
             rotation while a daemon holds the vault is rejected in this release.",
            socket.display()
        );
    }

    let current = prompt_password("Current master password: ")?;
    let new_password = prompt_password("New master password (min 12 characters): ")?;
    let confirm = prompt_password("Confirm new master password: ")?;
    if new_password != confirm {
        anyhow::bail!("New passwords do not match");
    }
    if new_password.len() < 12 {
        anyhow::bail!("New master password must be at least 12 characters");
    }

    let mut vault = VaultManager::open(&vault_path, current.as_bytes())
        .map_err(|e| anyhow::anyhow!("Current password incorrect or vault unavailable: {}", e))?;

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
}
