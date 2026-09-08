//! Audit trail verification CLI (WBS-415).

use anyhow::Result;
use rpassword::prompt_password;
use std::path::PathBuf;

/// `sentinelpass audit-verify`: unlock the vault, derive the audit chain
/// key from the DEK, walk every retained audit file, and report the first
/// broken record (tamper / deletion / reorder). Exits non-zero on a failed
/// verification.
pub fn handle_audit_verify(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = prompt_password("Enter master password: ")?;
    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

    let report = vault.verify_audit_trail()?;
    println!("{}", report);

    if report.is_ok() {
        println!("✓ Audit chain verified");
        Ok(())
    } else {
        anyhow::bail!("Audit chain verification FAILED — the audit trail has been tampered with, truncated, or corrupted");
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    /// The `audit-verify` subcommand parses with no arguments.
    #[test]
    fn parses_audit_verify_subcommand() {
        let cli = crate::Cli::try_parse_from(["sentinelpass", "audit-verify"]).unwrap();
        assert!(matches!(cli.command, crate::Commands::AuditVerify));
    }
}
