//! Portable authenticated backup commands (WBS-416/417, ADR-008):
//! `backup create`, `backup verify`, `backup restore`.

use anyhow::{Context, Result};
use clap::Subcommand;
use sentinelpass_core::vault::backup_ops::{BackupManifest, RestoreOptions};
use sentinelpass_core::VaultManager;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum BackupCommands {
    /// Create an authenticated, portable backup bundle (one file).
    Create {
        /// Output bundle path (must not exist)
        output: PathBuf,
    },
    /// Verify a backup bundle: format, bounds, digest, and manifest MAC.
    /// With --deep, also runs the full staged validation chain (identity,
    /// slots, schema migration, full decrypt) without touching any vault.
    Verify {
        /// Bundle file to verify
        bundle: PathBuf,
        /// Run the full staged validation chain (slower: full KDF + decrypt)
        #[arg(long)]
        deep: bool,
    },
    /// Restore a backup bundle, replacing the vault at the vault path.
    /// The pre-restore state is retained at <vault>.pre-restore.
    Restore {
        /// Bundle file to restore
        bundle: PathBuf,
        /// Acknowledge that the existing vault/file at the target is
        /// replaced (required whenever one exists)
        #[arg(long)]
        allow_replace: bool,
        /// Acknowledge the epoch high-water re-baseline for an
        /// older-epoch (or rewritten-key-material) bundle (ADR-004 rev 4)
        #[arg(long)]
        allow_epoch_rewind: bool,
        /// Acknowledge proceeding while live sync is enabled: the
        /// restored vault comes back with sync disabled; re-pairing is
        /// required (ADR-008)
        #[arg(long)]
        disable_sync: bool,
    },
}

/// `sentinelpass backup create <OUTPUT>`
pub fn handle_backup_create(vault_path: PathBuf, output: PathBuf) -> Result<()> {
    let master_password = crate::prompt_master_password(false)?;
    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

    let summary = vault
        .create_backup(&output)
        .context("backup creation failed")?;
    println!("Backup created: {}", summary.output.display());
    println!("  backup_id:    {}", summary.backup_id);
    println!("  vault_uuid:   {}", summary.vault_uuid);
    println!("  key epoch:    {}", summary.epoch);
    println!("  snapshot:     {} bytes", summary.snapshot_bytes);
    println!("Keep this bundle somewhere safe and separate from this machine.");
    Ok(())
}

/// `sentinelpass backup verify [--deep] <BUNDLE>`
pub fn handle_backup_verify(bundle: PathBuf, deep: bool) -> Result<()> {
    let master_password = crate::prompt_master_password(false)?;
    let manifest: BackupManifest =
        VaultManager::verify_bundle_file(&bundle, master_password.as_bytes(), deep)
            .context("bundle verification FAILED (fail closed)")?;

    println!("Bundle verified: {}", bundle.display());
    println!("  backup_id:            {}", manifest.backup_id);
    println!("  created_at:           {}", manifest.created_at);
    println!("  app_version:          {}", manifest.app_version);
    println!("  vault_uuid:           {}", manifest.vault_uuid);
    println!("  key epoch:            {}", manifest.epoch);
    println!("  schema version:       {}", manifest.schema_version);
    println!("  vault format version: {}", manifest.vault_format_version);
    println!(
        "  entries:              {} (+{} tombstoned)",
        manifest.entry_count, manifest.tombstone_count
    );
    println!("  usable key slots:     {}", manifest.slots.len());
    if deep {
        println!("  deep validation:      identity, slots, schema, full decrypt — all passed");
    }
    Ok(())
}

/// `sentinelpass backup restore <BUNDLE> [--allow-replace] [--allow-epoch-rewind] [--disable-sync]`
#[allow(clippy::too_many_arguments)]
pub fn handle_backup_restore(
    vault_path: PathBuf,
    bundle: PathBuf,
    allow_replace: bool,
    allow_epoch_rewind: bool,
    disable_sync: bool,
) -> Result<()> {
    let master_password = crate::prompt_master_password(false)?;
    let opts = RestoreOptions {
        allow_replace,
        allow_epoch_rewind,
        disable_sync,
    };

    println!(
        "Restoring {} onto {} — this REPLACES the vault at that path.",
        bundle.display(),
        vault_path.display()
    );
    if !allow_replace {
        println!("  (no --allow-replace: the restore will refuse if any vault/file exists there)");
    }
    if !allow_epoch_rewind {
        println!("  (no --allow-epoch-rewind: older-epoch bundles will be refused)");
    }

    let report = VaultManager::restore_bundle(&vault_path, &bundle, master_password.as_bytes(), &opts)
        .context("restore FAILED (fail closed — the live vault was not modified unless a post-swap step is named in the error)")?;

    println!("Restore verified and complete.");
    println!("  backup_id:            {}", report.bundle_backup_id);
    println!("  vault_uuid:           {}", report.vault_uuid);
    println!(
        "  key epoch:            {} -> {}",
        report
            .from_epoch
            .map(|e| e.to_string())
            .unwrap_or_else(|| "none".into()),
        report.to_epoch
    );
    println!("  entries:              {}", report.entries);
    if report.epoch_rewound {
        println!("  epoch high-water:     re-baselined (acknowledged rollback restore)");
    }
    if report.sync_disabled {
        println!("  sync:                 DISABLED — re-pairing required (restored lineage is never reused)");
    }
    match &report.pre_restore_snapshot {
        Some(path) => {
            println!("  pre-restore snapshot: retained at {}", path.display());
            println!("  Keep it until you are satisfied with the restored vault.");
        }
        None => println!("  pre-restore snapshot: none (the target was empty)"),
    }
    println!("Restart the daemon/desktop app before continuing to use this vault.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::BackupCommands;
    use clap::Parser;
    use std::path::PathBuf;

    /// The restore subcommand parses all three acknowledgment flags.
    #[test]
    fn parses_backup_restore_with_all_acknowledgment_flags() {
        let cli = crate::Cli::try_parse_from([
            "sentinelpass",
            "--vault",
            "/tmp/v.db",
            "backup",
            "restore",
            "/tmp/b.spbackup",
            "--allow-replace",
            "--allow-epoch-rewind",
            "--disable-sync",
        ])
        .unwrap();
        let crate::Commands::Backup(BackupCommands::Restore {
            bundle,
            allow_replace,
            allow_epoch_rewind,
            disable_sync,
        }) = cli.command
        else {
            panic!("expected backup restore subcommand");
        };
        assert_eq!(bundle, PathBuf::from("/tmp/b.spbackup"));
        assert!(allow_replace);
        assert!(allow_epoch_rewind);
        assert!(disable_sync);
    }

    /// Flags default to FALSE (fail closed): a bare restore command
    /// carries no acknowledgment.
    #[test]
    fn backup_restore_flags_default_to_unacknowledged() {
        let cli =
            crate::Cli::try_parse_from(["sentinelpass", "backup", "restore", "/tmp/b.spbackup"])
                .unwrap();
        let crate::Commands::Backup(BackupCommands::Restore {
            allow_replace,
            allow_epoch_rewind,
            disable_sync,
            ..
        }) = cli.command
        else {
            panic!("expected backup restore");
        };
        assert!(!allow_replace);
        assert!(!allow_epoch_rewind);
        assert!(!disable_sync);
    }

    /// `backup create` parses with its output path; `verify --deep`
    /// toggles the deep flag.
    #[test]
    fn parses_backup_create_and_deep_verify() {
        let cli =
            crate::Cli::try_parse_from(["sentinelpass", "backup", "create", "/tmp/out.spbackup"])
                .unwrap();
        let crate::Commands::Backup(BackupCommands::Create { output }) = cli.command else {
            panic!("expected backup create");
        };
        assert_eq!(output, PathBuf::from("/tmp/out.spbackup"));

        let cli = crate::Cli::try_parse_from([
            "sentinelpass",
            "backup",
            "verify",
            "--deep",
            "/tmp/b.spbackup",
        ])
        .unwrap();
        let crate::Commands::Backup(BackupCommands::Verify { bundle, deep }) = cli.command else {
            panic!("expected backup verify");
        };
        assert!(deep);
        assert_eq!(bundle, PathBuf::from("/tmp/b.spbackup"));
    }
}
