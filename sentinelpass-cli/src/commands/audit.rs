//! Audit trail verification CLI (WBS-415).

use crate::commands::service_client as sc;
use anyhow::Result;
use sentinelpass_protocol::service::VaultOp;
use std::path::PathBuf;

/// `sentinelpass audit-verify`: verify the audit hash chain through the
/// daemon service boundary (the chain keys are DEK-derived, so the daemon
/// derives them while unlocked). Exits non-zero on a failed verification.
pub fn handle_audit_verify(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    let value = sc::expect_report(backend.call(VaultOp::AuditVerify)?)?;
    let ok = value["ok"].as_bool().unwrap_or(false);
    let report_text = value["report"]
        .as_str()
        .unwrap_or("audit verification report unavailable");
    println!("{report_text}");

    if ok {
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
