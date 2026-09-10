use crate::commands::service_client as sc;
use anyhow::Result;
use sentinelpass_core::VaultManager;
use sentinelpass_protocol::service::VaultOp;
use sentinelpass_protocol::service::VaultOpResult;
use std::path::PathBuf;

pub fn handle(vault_path: PathBuf, cmd: &crate::SyncCommands) -> Result<()> {
    let allow_missing_vault = matches!(cmd, crate::SyncCommands::PairJoin { .. });
    if !vault_path.exists() && !allow_missing_vault {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    // Pairing flows are EXCLUSIVE offline operations (stage-2 review F1):
    // pair-start opens and reads the vault directly, and pair-join CREATES a
    // local vault on a fresh machine — creation the epoch guard cannot
    // protect (there is no vault/epoch yet). They must hold the exclusive
    // maintenance lock so a live daemon (or a concurrent create) cannot own
    // or race the vault while they run.
    if matches!(
        cmd,
        crate::SyncCommands::PairStart | crate::SyncCommands::PairJoin { .. }
    ) {
        let guard = sentinelpass_core::daemon::try_acquire(&vault_path)?;
        let result = handle_pairing(vault_path, cmd);
        drop(guard);
        return result;
    }

    match cmd {
        crate::SyncCommands::Init {
            ref relay_url,
            ref device_name,
        } => {
            let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

            let result = backend.call(VaultOp::SyncInit {
                relay_url: relay_url.clone(),
                device_name: device_name.clone(),
            })?;

            let value = sc::expect_report(result)?;
            println!("Sync initialized successfully!");
            println!(
                "  Device name: {}",
                device_name.clone().unwrap_or_else(hostname_of)
            );
            println!(
                "  Device ID:   {}",
                value["device_id"].as_str().unwrap_or("?")
            );
            println!(
                "  Vault ID:    {}",
                value["vault_id"].as_str().unwrap_or("?")
            );
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
            let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

            // SyncNow is daemon-async (relay HTTP); the result is the
            // post-sync status.
            let status = match backend.call(VaultOp::SyncNow)? {
                VaultOpResult::SyncStatus(status) => status,
                other => anyhow::bail!("unexpected response: {other:?}"),
            };
            println!("Sync completed.");
            if let Some(ts) = status.last_sync_at {
                let dt = chrono::DateTime::from_timestamp(ts, 0)
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| ts.to_string());
                println!("Last synced: {}", dt);
            }
            println!("Pending changes: {}", status.pending_changes);
            if status.conflicts > 0 {
                println!(
                    "Conflicts awaiting resolution: {} (see 'sync conflict-list')",
                    status.conflicts
                );
            }
        }

        crate::SyncCommands::Status => {
            let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

            let status = match backend.call(VaultOp::SyncStatus)? {
                VaultOpResult::SyncStatus(status) => status,
                other => anyhow::bail!("unexpected response: {other:?}"),
            };

            println!();
            println!("Sync Status");
            println!("===========");
            println!(
                "  Enabled:         {}",
                if status.enabled { "yes" } else { "no" }
            );
            if let Some(ref device_id) = status.device_id {
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
            if status.conflicts > 0 {
                println!(
                    "  Conflicts awaiting resolution: {} (see 'sync conflict-list')",
                    status.conflicts
                );
            }
            println!();
        }

        crate::SyncCommands::DeviceList => {
            let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

            let devices = match backend.call(VaultOp::SyncDeviceList)? {
                VaultOpResult::SyncDevices(devices) => devices,
                other => anyhow::bail!("unexpected response: {other:?}"),
            };

            if devices.is_empty() {
                println!("No devices registered yet.");
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
            let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

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

            backend.call(VaultOp::SyncDeviceRevoke {
                device_id: device_id.clone(),
            })?;

            println!("Device {} marked as revoked locally.", device_id);
            println!("Run 'sentinelpass sync now' to propagate to the relay server.");
        }

        crate::SyncCommands::ConflictList => {
            let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
            let report = match backend.call(VaultOp::SyncConflictList)? {
                VaultOpResult::Report(value) => value,
                other => anyhow::bail!("unexpected response: {other:?}"),
            };
            let rows = report.as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!("No sync conflicts awaiting resolution.");
                return Ok(());
            }
            println!();
            println!(
                "{:<38} {:<12} {:>7} {:<10} Tombstone",
                "Object ID", "Type", "Remote", "Origin"
            );
            println!("{}", "-".repeat(96));
            for row in &rows {
                let origin = row["origin_device_id"].as_str().unwrap_or("?");
                let short = if origin.len() > 8 {
                    origin[..8].to_string()
                } else {
                    origin.to_string()
                };
                println!(
                    "{:<38} {:<12} {:>7} {:<10} {}",
                    row["object_id"].as_str().unwrap_or("?"),
                    row["object_type"].as_str().unwrap_or("?"),
                    row["remote_version"].as_i64().unwrap_or(0),
                    short,
                    row["is_tombstone"].as_bool().unwrap_or(false),
                );
            }
            println!();
            println!(
                "Resolve with: sentinelpass sync conflict-resolve --object-id <ID> [--take-remote]"
            );
        }

        crate::SyncCommands::ConflictResolve {
            ref object_id,
            ref take_remote,
        } => {
            let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
            backend.call(VaultOp::SyncConflictResolve {
                object_id: object_id.clone(),
                take_remote: *take_remote,
            })?;
            if *take_remote {
                println!("Conflict resolved: the peer's version was applied.");
            } else {
                println!(
                    "Conflict resolved: the local edit was kept and will sync on the next run."
                );
            }
        }

        crate::SyncCommands::DeadLetterList => {
            let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
            let report = match backend.call(VaultOp::SyncDeadLetterList)? {
                VaultOpResult::Report(value) => value,
                other => anyhow::bail!("unexpected response: {other:?}"),
            };
            let rows = report.as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!("No dead-lettered sync mutations.");
                return Ok(());
            }
            println!();
            println!(
                "{:<16} {:<38} {:<12} Reason",
                "Server Seq", "Object ID", "Type"
            );
            println!("{}", "-".repeat(100));
            for row in &rows {
                println!(
                    "{:<16} {:<38} {:<12} {}",
                    row["server_sequence"].as_i64().unwrap_or(0),
                    row["object_id"].as_str().unwrap_or("?"),
                    row["object_type"].as_str().unwrap_or("?"),
                    row["reason"].as_str().unwrap_or("?"),
                );
            }
            println!();
            println!("Purge with: sentinelpass sync dead-letter-purge --server-sequence <SEQ>");
        }

        crate::SyncCommands::DeadLetterPurge {
            ref server_sequence,
            ref all,
        } => {
            if !*all && server_sequence.is_none() {
                anyhow::bail!("Specify --server-sequence <SEQ> or --all");
            }
            let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
            let report = match backend.call(VaultOp::SyncDeadLetterPurge {
                server_sequence: *server_sequence,
            })? {
                VaultOpResult::Report(value) => value,
                other => anyhow::bail!("unexpected response: {other:?}"),
            };
            let purged = report["purged"].as_i64().unwrap_or(0);
            println!("Purged {purged} dead-lettered mutation(s).");
        }

        crate::SyncCommands::Disable => {
            let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

            print!("Disable sync? This will not delete remote data. [y/N]: ");
            use std::io::Write;
            std::io::stdout().flush()?;
            let mut confirmation = String::new();
            std::io::stdin().read_line(&mut confirmation)?;
            if !confirmation.trim().to_lowercase().starts_with('y') {
                println!("Cancelled");
                return Ok(());
            }

            backend.call(VaultOp::SyncDisable)?;

            println!("Sync disabled. Device identity and vault ID are preserved.");
            println!("Use 'sentinelpass sync init' to re-enable.");
        }

        // Intercepted above and handled by handle_pairing under the
        // maintenance lock.
        crate::SyncCommands::PairStart | crate::SyncCommands::PairJoin { .. } => {
            unreachable!("pairing commands are handled under the maintenance lock")
        }
    }

    Ok(())
}

fn hostname_of() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Pairing flows, run while HOLDING the exclusive maintenance lock. These
/// are the only sync flows still executed in-process: pair-join CREATES a
/// local vault (onboarding — daemon-async dispatch cannot create vaults on
/// the live surface), and both require relay network plus vault access that
/// must be exclusive.
fn handle_pairing(vault_path: PathBuf, cmd: &crate::SyncCommands) -> Result<()> {
    match cmd {
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

            // WBS-615: the secret is 256 bits — the QR payload IS the
            // secret. The bootstrap encrypts under HKDF(secret); the relay
            // stores only Argon2id(secret).
            let secret = sentinelpass_core::sync::pairing::generate_pairing_secret();
            let secret_b64 = sentinelpass_core::sync::pairing::pairing_secret_to_b64(&secret);
            let pairing_key = sentinelpass_core::sync::pairing::derive_pairing_key_v2(&secret)?;
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
            crate::run_async(client.upload_bootstrap_v2(
                &secret_b64,
                &encrypted_bootstrap,
                &registration_proof,
            ))??;

            let transcript = sentinelpass_core::sync::pairing::transcript_digits(&secret);

            println!();
            println!("Pairing secret (scan as QR or copy):");
            println!("  {secret_b64}");
            println!();
            println!("Transcript (must match on the joining device): {transcript}");
            println!("Expires in 5 minutes. On the new device, run:");
            println!("  sentinelpass sync pair-join --relay-url {relay_url}");
            println!("and paste the secret when prompted.");
            println!();
            println!("Pairing bootstrap uploaded to relay.");
        }

        crate::SyncCommands::PairJoin { ref relay_url } => {
            // WBS-615/616: the pairing secret is PROMPTED (never a
            // command-line argument) and the bootstrap is retrieved in a
            // POST body after proving knowledge of the secret.
            let secret_b64 =
                rpassword::prompt_password("Pairing secret (paste from the originating device): ")?;
            let secret = sentinelpass_core::sync::pairing::pairing_secret_from_b64(&secret_b64)
                .map_err(|e| anyhow::anyhow!("invalid pairing secret: {e}"))?;
            let transcript = sentinelpass_core::sync::pairing::transcript_digits(&secret);
            println!("Transcript on this device: {transcript}");
            print!("Does this match the originating device's transcript? [y/N]: ");
            use std::io::Write;
            std::io::stdout().flush()?;
            let mut confirmation = String::new();
            std::io::stdin().read_line(&mut confirmation)?;
            if !confirmation.trim().to_lowercase().starts_with('y') {
                anyhow::bail!(
                    "Transcripts do not match — refusing to pair (the secret may be \
                     wrong or mistyped)"
                );
            }

            let master_password = crate::prompt_master_password(false)?;
            let mut vault = if vault_path.exists() {
                crate::open_vault_with_password(&vault_path, master_password.as_bytes())?
            } else {
                VaultManager::create(&vault_path, master_password.as_bytes())
                    .map_err(|e| anyhow::anyhow!("Failed to create local vault: {e}"))?
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
            let (encrypted_bootstrap, registration_proof) =
                crate::run_async(fetch_client.retrieve_bootstrap_v2(&secret_b64))??;

            let pairing_key = sentinelpass_core::sync::pairing::derive_pairing_key_v2(&secret)?;
            let bootstrap = sentinelpass_core::sync::pairing::decrypt_bootstrap(
                &pairing_key,
                &encrypted_bootstrap,
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "Bootstrap decryption failed ({e}) — the secret may be wrong or the \
                     bootstrap expired"
                )
            })?;

            if relay_url.trim_end_matches('/') != bootstrap.relay_url.trim_end_matches('/') {
                anyhow::bail!(
                    "Relay URL mismatch: fetched bootstrap is bound to {}",
                    bootstrap.relay_url
                );
            }

            vault.import_pairing_bootstrap(master_password.as_bytes(), &bootstrap)?;

            let device_name = hostname_of();
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
                Some(&secret_b64),
                Some(&registration_proof),
            ))??;

            vault.init_sync(
                &bootstrap.relay_url,
                &device_name,
                bootstrap.vault_id,
                &identity,
            )?;

            println!("Pair-join completed: this device is now registered for sync.");
            println!("  Device name: {device_name}");
            println!("  Device ID:   {}", identity.device_id);
            println!("  Vault ID:    {}", bootstrap.vault_id);
            println!("  Relay URL:   {}", bootstrap.relay_url);
        }

        _ => unreachable!("handle_pairing is only called for pairing commands"),
    }

    Ok(())
}
