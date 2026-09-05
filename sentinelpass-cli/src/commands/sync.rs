use anyhow::Result;
use base64::Engine;
use sentinelpass_core::VaultManager;
use std::path::PathBuf;

pub fn handle(vault_path: PathBuf, cmd: &crate::SyncCommands) -> Result<()> {
    let allow_missing_vault = matches!(cmd, crate::SyncCommands::PairJoin { .. });
    if !vault_path.exists() && !allow_missing_vault {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    match cmd {
        crate::SyncCommands::Init {
            ref relay_url,
            ref device_name,
        } => {
            let master_password = crate::prompt_master_password(false)?;
            let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

            // Check if sync is already initialized
            let status = vault.get_sync_status()?;
            if status.enabled {
                anyhow::bail!(
                    "Sync is already initialized for this vault.\n\
                     Device: {} ({})\n\
                     Relay: {}",
                    status.device_name.unwrap_or_default(),
                    status.device_id.map(|d| d.to_string()).unwrap_or_default(),
                    status.relay_url.unwrap_or_default()
                );
            }

            let device_name = device_name.clone().unwrap_or_else(|| {
                hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".to_string())
            });

            // Generate device identity
            let identity = sentinelpass_core::sync::device::DeviceIdentity::generate(&device_name);
            let device_id = identity.device_id;
            let vault_id = uuid::Uuid::new_v4();

            // Save config and device identity
            vault.init_sync(relay_url, &device_name, vault_id, &identity)?;

            println!("Sync initialized successfully!");
            println!("  Device name: {}", device_name);
            println!("  Device ID:   {}", device_id);
            println!("  Vault ID:    {}", vault_id);
            println!("  Relay URL:   {}", relay_url);
            println!();
            println!("WARNING: sync is EXPERIMENTAL and not approved for production");
            println!("credentials (see docs/SYNC.md). The sync protocol is being");
            println!("redesigned in v2; v1 data will require re-bootstrap.");
            println!();
            println!("Next: register this device with the relay server:");
            println!("  sentinelpass sync now");
        }

        crate::SyncCommands::Now => {
            let master_password = crate::prompt_master_password(false)?;
            let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

            let status = vault.get_sync_status()?;
            if !status.enabled {
                anyhow::bail!("Sync is not initialized. Use 'sentinelpass sync init' first.");
            }

            let status = crate::run_async(vault.sync_now())??;
            println!("Sync completed.");
            if let Some(ts) = status.last_sync_at {
                let dt = chrono::DateTime::from_timestamp(ts, 0)
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| ts.to_string());
                println!("Last synced: {}", dt);
            }
            println!("Pending changes: {}", status.pending_changes);
        }

        crate::SyncCommands::Status => {
            let master_password = crate::prompt_master_password(false)?;
            let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

            let status = vault.get_sync_status()?;

            println!();
            println!("Sync Status");
            println!("===========");
            println!(
                "  Enabled:         {}",
                if status.enabled { "yes" } else { "no" }
            );
            if let Some(device_id) = status.device_id {
                println!("  Device ID:       {}", device_id);
            }
            if let Some(ref name) = status.device_name {
                println!("  Device name:     {}", name);
            }
            if let Some(ref url) = status.relay_url {
                println!("  Relay URL:       {}", url);
            }
            if let Some(ts) = status.last_sync_at {
                let dt = chrono::DateTime::from_timestamp(ts, 0)
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| ts.to_string());
                println!("  Last synced:     {}", dt);
            } else {
                println!("  Last synced:     never");
            }
            println!("  Pending changes: {}", status.pending_changes);
            println!();
        }

        crate::SyncCommands::DeviceList => {
            let master_password = crate::prompt_master_password(false)?;
            let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

            let status = vault.get_sync_status()?;
            if !status.enabled {
                anyhow::bail!("Sync is not initialized. Use 'sentinelpass sync init' first.");
            }

            let devices = vault.list_sync_devices()?;

            if devices.is_empty() {
                println!("No devices registered yet.");
                println!(
                    "This device: {} ({})",
                    status.device_name.unwrap_or_default(),
                    status.device_id.map(|d| d.to_string()).unwrap_or_default()
                );
            } else {
                println!();
                println!("{:<38} {:<20} {:<10} Status", "Device ID", "Name", "Type");
                println!("{}", "-".repeat(80));
                for device in &devices {
                    let status_str = if device.revoked { "revoked" } else { "active" };
                    println!(
                        "{:<38} {:<20} {:<10} {}",
                        device.device_id, device.device_name, device.device_type, status_str
                    );
                }
                println!();
            }
        }

        crate::SyncCommands::DeviceRevoke { ref device_id } => {
            let master_password = crate::prompt_master_password(false)?;
            let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

            let status = vault.get_sync_status()?;
            if !status.enabled {
                anyhow::bail!("Sync is not initialized.");
            }

            // Confirm
            print!("Revoke device {}? [y/N]: ", device_id);
            use std::io::Write;
            std::io::stdout().flush()?;
            let mut confirmation = String::new();
            std::io::stdin().read_line(&mut confirmation)?;
            if !confirmation.trim().to_lowercase().starts_with('y') {
                println!("Revocation cancelled");
                return Ok(());
            }

            // Mark locally as revoked
            vault.revoke_sync_device(device_id)?;

            println!("Device {} marked as revoked locally.", device_id);
            println!("Run 'sentinelpass sync now' to propagate to the relay server.");
        }

        crate::SyncCommands::PairStart => {
            let master_password = crate::prompt_master_password(false)?;
            let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

            let status = vault.get_sync_status()?;
            if !status.enabled {
                anyhow::bail!("Sync is not initialized. Use 'sentinelpass sync init' first.");
            }

            let relay_url = status
                .relay_url
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Sync relay URL is missing"))?;
            let device_identity = vault
                .load_sync_device_identity()?
                .ok_or_else(|| anyhow::anyhow!("Sync device identity is missing"))?;
            let bootstrap = vault.export_pairing_bootstrap()?;

            let code = sentinelpass_core::sync::pairing::generate_pairing_code();
            let salt = sentinelpass_core::sync::pairing::generate_pairing_salt();
            let pairing_key = sentinelpass_core::sync::pairing::derive_pairing_key(&code, &salt)?;
            let registration_proof = sentinelpass_core::sync::pairing::derive_registration_proof(
                &pairing_key,
                &bootstrap.vault_id,
            )?;
            let encrypted_bootstrap =
                sentinelpass_core::sync::pairing::encrypt_bootstrap(&pairing_key, &bootstrap)?;

            let sentinelpass_core::sync::device::DeviceIdentity {
                device_id,
                signing_key,
                ..
            } = device_identity;
            let client = sentinelpass_core::sync::client::SyncClient::new(
                &relay_url,
                device_id,
                signing_key,
            )?;
            crate::run_async(client.upload_bootstrap_with_proof(
                &code,
                &encrypted_bootstrap,
                &salt,
                Some(&registration_proof),
            ))??;

            let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);

            println!();
            println!("Pairing Code: {}", code);
            println!();
            println!("Share this code with the new device. It expires in 5 minutes.");
            println!("On the new device, run:");
            println!(
                "  sentinelpass sync pair-join --relay-url {} --code {} --salt {}",
                relay_url, code, salt_b64
            );
            println!();
            println!("Pairing bootstrap uploaded to relay.");
        }

        crate::SyncCommands::PairJoin {
            ref relay_url,
            ref code,
            ref salt,
        } => {
            if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
                anyhow::bail!("Pairing code must be exactly 6 digits");
            }

            let salt_bytes = base64::engine::general_purpose::STANDARD
                .decode(salt)
                .map_err(|e| anyhow::anyhow!("Invalid pairing salt: {}", e))?;
            if salt_bytes.len() != 16 {
                anyhow::bail!("Pairing salt must decode to 16 bytes");
            }

            let master_password = crate::prompt_master_password(false)?;
            let mut vault = if vault_path.exists() {
                crate::open_vault_with_password(&vault_path, master_password.as_bytes())?
            } else {
                VaultManager::create(&vault_path, master_password.as_bytes())
                    .map_err(|e| anyhow::anyhow!("Failed to create local vault: {}", e))?
            };

            let status = vault.get_sync_status()?;
            if status.enabled {
                anyhow::bail!(
                    "Sync is already initialized for this vault. Disable it first before pair-join."
                );
            }

            let tmp_identity = sentinelpass_core::sync::device::DeviceIdentity::generate(
                "pair-join-bootstrap-fetch",
            );
            let fetch_client = sentinelpass_core::sync::client::SyncClient::new(
                relay_url,
                tmp_identity.device_id,
                tmp_identity.signing_key,
            )?;
            let (encrypted_bootstrap, relay_salt) =
                crate::run_async(fetch_client.fetch_bootstrap(code))??;
            if relay_salt != salt_bytes {
                anyhow::bail!(
                    "Pairing salt mismatch (relay returned different salt than provided)"
                );
            }

            let pairing_key =
                sentinelpass_core::sync::pairing::derive_pairing_key(code, &relay_salt)?;
            let bootstrap = sentinelpass_core::sync::pairing::decrypt_bootstrap(
                &pairing_key,
                &encrypted_bootstrap,
            )?;

            if relay_url.trim_end_matches('/') != bootstrap.relay_url.trim_end_matches('/') {
                anyhow::bail!(
                    "Relay URL mismatch: fetched bootstrap is bound to {}",
                    bootstrap.relay_url
                );
            }

            let registration_proof = sentinelpass_core::sync::pairing::derive_registration_proof(
                &pairing_key,
                &bootstrap.vault_id,
            )?;

            vault.import_pairing_bootstrap(master_password.as_bytes(), &bootstrap)?;

            let device_name = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            let identity = sentinelpass_core::sync::device::DeviceIdentity::generate(&device_name);
            let public_key = identity.public_key_bytes();
            let register_client = sentinelpass_core::sync::client::SyncClient::new(
                &bootstrap.relay_url,
                identity.device_id,
                identity.signing_key.clone(),
            )?;
            crate::run_async(register_client.register_device_with_pairing(
                &device_name,
                sentinelpass_core::sync::device::DeviceIdentity::current_device_type(),
                &public_key,
                &bootstrap.vault_id,
                Some(code.as_str()),
                Some(&registration_proof),
            ))??;

            vault.init_sync(
                &bootstrap.relay_url,
                &device_name,
                bootstrap.vault_id,
                &identity,
            )?;

            println!("Pair-join completed: this device is now registered for sync.");
            println!("  Device name: {}", device_name);
            println!("  Device ID:   {}", identity.device_id);
            println!("  Vault ID:    {}", bootstrap.vault_id);
            println!("  Relay URL:   {}", bootstrap.relay_url);
            println!();
            println!("Next: run 'sentinelpass sync now' once sync transport is fully implemented.");
        }

        crate::SyncCommands::Disable => {
            let master_password = crate::prompt_master_password(false)?;
            let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

            let status = vault.get_sync_status()?;
            if !status.enabled {
                println!("Sync is already disabled.");
                return Ok(());
            }

            print!("Disable sync? This will not delete remote data. [y/N]: ");
            use std::io::Write;
            std::io::stdout().flush()?;
            let mut confirmation = String::new();
            std::io::stdin().read_line(&mut confirmation)?;
            if !confirmation.trim().to_lowercase().starts_with('y') {
                println!("Cancelled");
                return Ok(());
            }

            vault.disable_sync()?;

            println!("Sync disabled. Device identity and vault ID are preserved.");
            println!("Use 'sentinelpass sync init' to re-enable.");
        }
    }

    Ok(())
}
