//! Recovery key management (WBS-310/311/312): setup with verified
//! re-entry, and access recovery without the old master password.

use anyhow::{Context, Result};
use sentinelpass_core::vault::recovery::{parse_recovery_key, RecoveryKey};
use sentinelpass_core::VaultManager;
use std::io::IsTerminal;
use std::path::PathBuf;

/// `sentinelpass recovery setup`: generate a 256-bit recovery key, display
/// it once, require the user to re-enter it (checksum-validated — every
/// single-character transcription error is caught), and only then create
/// the recovery slot. SR-RECOVERY-002: an unverified key is never persisted.
pub fn handle_setup(vault_path: PathBuf) -> Result<()> {
    // Terminal checks FIRST (review finding): setup displays the key on
    // stdout AND reads it back on stdin — both must be a real terminal
    // before we burn a password prompt and a full Argon2id unlock.
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "recovery setup requires an interactive terminal (the key must be shown \
             once and re-entered for verification)"
        );
    }

    let master_password = crate::prompt_master_password(false)?;
    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

    let key = RecoveryKey::generate()?;
    let display = key.to_display_string();

    println!("Recovery key (shown ONCE — store it somewhere safe, e.g. a printed");
    println!("copy or a separate password manager):");
    println!();
    println!("    {}", *display);
    println!();
    println!("This key cannot be recovered or regenerated. If it is lost AND your");
    println!("master password is lost, the vault is permanently unreadable.");
    println!();

    // Verified re-entry: loop until the user re-enters a checksum-valid key
    // that decodes to the SAME bytes (identity check, not just checksum).
    // No-echo input like every other secret in this CLI (rpassword) — the
    // key must not land in terminal scrollback.
    loop {
        let entry = rpassword::prompt_password("Re-enter the recovery key to confirm: ")
            .context("reading recovery key confirmation")?;
        let entry = entry.trim();

        use subtle::ConstantTimeEq;
        match parse_recovery_key(entry) {
            Ok(retyped) if bool::from(retyped.as_bytes().ct_eq(key.as_bytes())) => break,
            Ok(_) => {
                println!(
                    "That is a VALID key, but not the one shown. Try again (or Ctrl-C to abort)."
                );
            }
            Err(e) => {
                println!("Could not parse that key: {e}");
                println!("Check each character against what was shown; dashes optional.");
            }
        }
    }

    vault.create_recovery_slot(&key)?;
    println!("Recovery slot created and verified.");
    println!("Vault remains fully usable; the key works even if the master password is lost.");
    Ok(())
}

/// `sentinelpass recovery recover`: regain access WITHOUT the old master
/// password using the recovery key, establishing a new master password.
/// All prior slots (including the lost password slot) are revoked and the
/// crypto epoch advances (ADR-004 rev 4: local revocation).
pub fn handle_recover(vault_path: PathBuf) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("recovery requires an interactive terminal");
    }

    // No-echo input: the recovery key is a secret (rpassword, like the
    // master password prompts) — echoed input would leave it in scrollback.
    let entry = rpassword::prompt_password("Recovery key: ").context("reading recovery key")?;
    let key = parse_recovery_key(entry.trim())
        .context("that recovery key does not parse — check the characters (dashes optional)")?;

    let new_password = crate::prompt_master_password(true)?;
    // Zeroize-on-drop via the prompt's own handling; recover_access applies
    // its own length policy and stages/verifies the new wrap before commit.
    VaultManager::recover_access(&vault_path, &key, new_password.as_bytes())?;

    println!("Access recovered: a new master password is active and all previous");
    println!("unlock slots were revoked. If you use biometric unlock or sync,");
    println!("re-enable them with the new password.");
    println!();
    println!("IMPORTANT: the recovery slot was revoked with everything else — run");
    println!("`sentinelpass recovery setup` now to create a new recovery key, or the");
    println!("next lost password is unrecoverable.");
    Ok(())
}

/// `sentinelpass recovery status`: whether a usable recovery slot exists
/// (no secrets displayed).
pub fn handle_status(vault_path: PathBuf) -> Result<()> {
    let master_password = crate::prompt_master_password(false)?;
    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;
    let slots = vault.list_key_slots()?;
    let usable_recovery = slots
        .iter()
        .any(|s| s.usable && s.slot_type == sentinelpass_core::vault::SlotType::Recovery);
    let usable_count = slots.iter().filter(|s| s.usable).count();
    println!(
        "Recovery slot: {}",
        if usable_recovery {
            "CONFIGURED (usable)"
        } else {
            "NOT configured — a lost master password means a lost vault"
        }
    );
    println!("Usable key slots: {usable_count} (password/recovery/platform)");
    Ok(())
}

#[derive(clap::Subcommand)]
pub enum RecoveryCommands {
    /// Generate a recovery key, verify it by re-entry, and create the slot
    Setup,
    /// Regain access without the master password using the recovery key
    Recover,
    /// Show whether a usable recovery slot exists
    Status,
}
