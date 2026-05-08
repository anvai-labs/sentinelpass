use anyhow::Result;
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use rpassword::prompt_password;
use sentinelpass_core::{
    crypto::{analyze_password, generate_password, PasswordGeneratorConfig},
    daemon::ipc::{default_ipc_socket_path, IpcClient, IpcMessage},
    export_to_csv, export_to_json, export_to_keepass_xml, import_from_csv, import_from_json,
    import_from_keepass_xml, parse_otpauth_uri, CredentialType, Entry as VaultEntry, EntrySummary,
    ExternalSecretAllowlist, ExternalSecretField, SshAgentClient, SshKeyImporter, TotpAlgorithm,
    VaultManager,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

/// SentinelPass CLI - A secure, local-first password manager
#[derive(Parser)]
#[command(name = "sentinelpass")]
#[command(author = "VJ Singh <singhvjd@gmail.com>")]
#[command(version = "0.1.0")]
#[command(about = "Secure, local-first password manager with browser autofill", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Custom vault path (overrides default)
    #[arg(short, long, global = true)]
    vault: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new password vault
    Init {
        /// Enable development mode (in-memory database)
        #[arg(long)]
        dev: bool,
    },

    /// Unlock the vault
    Unlock,

    /// Lock the vault
    Lock,

    /// Show biometric unlock status for this vault
    BiometricStatus,

    /// Enable biometric unlock for this vault
    BiometricEnable {
        /// Master password (prompted securely if omitted)
        #[arg(long)]
        master_password: Option<String>,
    },

    /// Disable biometric unlock for this vault
    BiometricDisable,

    /// Unlock vault using biometric authentication
    UnlockBiometric,

    /// Check whether SSH agent integration is available
    SshAgentStatus,

    /// Retrieve a single secret field through the unlocked daemon
    SecretGet {
        /// Domain or service key used to look up the credential
        #[arg(long)]
        domain: String,

        /// Field to print
        #[arg(long, value_enum, default_value_t = SecretField::Password)]
        field: SecretField,

        /// If the daemon is locked, request biometric unlock before lookup
        #[arg(long)]
        biometric_unlock: bool,

        /// Local tool client id to enforce external-secret allowlist authorization
        #[arg(long)]
        client_id: Option<String>,

        /// Purpose label recorded in daemon audit context
        #[arg(long)]
        purpose: Option<String>,

        /// Output format
        #[arg(long, value_enum, default_value_t = SecretOutputFormat::Plain)]
        output: SecretOutputFormat,

        /// Prompt shown by the OS biometric dialog
        #[arg(long, default_value = "Unlock SentinelPass to retrieve a secret")]
        prompt_reason: String,
    },

    /// Manage least-privilege external secret access for local tools
    Secret {
        #[command(subcommand)]
        command: SecretCommands,
    },

    /// Add a private key file to SSH agent
    SshAgentAdd {
        /// Path to private key file
        key_path: PathBuf,
    },

    /// Add a stored vault SSH key to SSH agent without writing it to disk
    SshAgentAddStored {
        /// SSH key ID stored in vault
        id: i64,
    },

    /// Remove all identities from SSH agent
    SshAgentClear,

    /// Add an SSH private key to the vault
    SshKeyAdd {
        /// Display name for the key in vault
        #[arg(long)]
        name: String,

        /// Path to private key file
        #[arg(long)]
        private_key_file: PathBuf,

        /// Path to public key file (defaults to <private_key_file>.pub)
        #[arg(long)]
        public_key_file: Option<PathBuf>,

        /// Optional comment override
        #[arg(long)]
        comment: Option<String>,
    },

    /// List SSH keys stored in vault
    SshKeyList,

    /// Get SSH key details by ID
    SshKeyGet {
        /// SSH key ID
        id: i64,

        /// Also print decrypted private key
        #[arg(long)]
        show_private: bool,
    },

    /// Delete SSH key by ID
    SshKeyDelete {
        /// SSH key ID
        id: i64,

        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },

    /// Add a new credential entry
    Add {
        /// Title for the entry
        #[arg(long)]
        title: String,

        /// Username
        #[arg(long)]
        username: String,

        /// Password (will prompt if not provided)
        #[arg(long)]
        password: Option<String>,

        /// Credential type for this entry
        #[arg(long, value_enum, default_value_t = CliCredentialType::Password)]
        credential_type: CliCredentialType,

        /// URL
        #[arg(long)]
        url: Option<String>,

        /// Notes
        #[arg(long)]
        notes: Option<String>,

        /// Mark as favorite
        #[arg(long)]
        favorite: bool,
    },

    /// List all entries
    List {
        /// Show passwords in plain text
        #[arg(long)]
        show_passwords: bool,
    },

    /// Get a specific entry
    Get {
        /// Entry ID
        id: i64,
    },

    /// Search entries
    Search {
        /// Search query
        query: String,
    },

    /// Delete an entry
    Delete {
        /// Entry ID
        id: i64,

        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },

    /// Edit an existing entry
    Edit {
        /// Entry ID
        #[arg(long)]
        id: i64,

        /// New title
        #[arg(long)]
        title: Option<String>,

        /// New username
        #[arg(long)]
        username: Option<String>,

        /// New password (will prompt if --new-password flag is set without value)
        #[arg(long)]
        password: Option<String>,

        /// Prompt for a new password
        #[arg(long)]
        new_password: bool,

        /// New URL
        #[arg(long)]
        url: Option<String>,

        /// New notes
        #[arg(long)]
        notes: Option<String>,

        /// Toggle favorite status
        #[arg(long)]
        favorite: Option<bool>,
    },

    /// Add or update a TOTP secret for an entry
    TotpAdd {
        /// Entry ID to attach TOTP to
        #[arg(long)]
        entry_id: i64,

        /// Base32 secret (prompted securely if omitted)
        #[arg(long)]
        secret: Option<String>,

        /// otpauth:// URI from QR provisioning payload
        #[arg(long)]
        otpauth_uri: Option<String>,

        /// HMAC algorithm override (sha1 or sha256)
        #[arg(long)]
        algorithm: Option<String>,

        /// TOTP digits override (6 or 8)
        #[arg(long)]
        digits: Option<u8>,

        /// TOTP period override in seconds
        #[arg(long)]
        period: Option<u32>,

        /// Optional issuer label
        #[arg(long)]
        issuer: Option<String>,

        /// Optional account label
        #[arg(long)]
        account: Option<String>,
    },

    /// Generate current TOTP code for an entry
    TotpCode {
        /// Entry ID with configured TOTP
        #[arg(long)]
        entry_id: i64,
    },

    /// Remove TOTP secret for an entry
    TotpRemove {
        /// Entry ID with configured TOTP
        #[arg(long)]
        entry_id: i64,

        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },

    /// Generate a secure random password
    Generate {
        /// Password length (default: 16)
        #[arg(short, long, default_value = "16")]
        length: usize,

        /// Include lowercase letters (default: true)
        #[arg(long, default_value = "true")]
        lowercase: bool,

        /// Include uppercase letters (default: true)
        #[arg(long, default_value = "true")]
        uppercase: bool,

        /// Include digits (default: true)
        #[arg(long, default_value = "true")]
        digits: bool,

        /// Include symbols (default: true)
        #[arg(long, default_value = "true")]
        symbols: bool,

        /// Exclude ambiguous characters like l, 1, I, O, 0
        #[arg(long, default_value = "true")]
        exclude_ambiguous: bool,

        /// Number of passwords to generate
        #[arg(short, long, default_value = "1")]
        count: usize,
    },

    /// Check password strength
    Check {
        /// Password to check (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Show vault password health report
    Health {
        /// Show detailed report for all entries
        #[arg(long)]
        detailed: bool,

        /// Show only weak/reused passwords
        #[arg(long)]
        only_issues: bool,
    },

    /// Export vault to file
    Export {
        /// Output file path
        output: PathBuf,

        /// Export format (json or csv)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Import entries from file
    Import {
        /// Input file path
        input: PathBuf,

        /// Import format (json, csv, or keepass)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Export entries to KeePass XML format
    KeePassExport {
        /// Output file path
        output: PathBuf,
    },

    /// Import entries from KeePass XML format
    KeePassImport {
        /// Input file path
        input: PathBuf,
    },

    /// Sync subcommands for encrypted cloud sync
    #[command(subcommand)]
    Sync(SyncCommands),
}

#[derive(Subcommand)]
enum SecretCommands {
    /// Allow a local tool to retrieve one field for one domain/service
    Allow {
        /// Local tool client id, for example `victor`
        client_id: String,

        /// Domain or service key the client may access
        #[arg(long)]
        domain: String,

        /// Field the client may retrieve
        #[arg(long, value_enum, default_value_t = SecretField::Password)]
        field: SecretField,
    },

    /// Retrieve a single authorized secret field through the unlocked daemon
    Get {
        /// Local tool client id, for example `victor`
        #[arg(long)]
        client_id: String,

        /// Domain or service key used to look up the credential
        #[arg(long)]
        domain: String,

        /// Field to print
        #[arg(long, value_enum, default_value_t = SecretField::Password)]
        field: SecretField,

        /// Purpose label recorded in daemon audit context
        #[arg(long)]
        purpose: Option<String>,

        /// Output format
        #[arg(long, value_enum, default_value_t = SecretOutputFormat::Plain)]
        output: SecretOutputFormat,

        /// If the daemon is locked, request biometric unlock before lookup
        #[arg(long)]
        biometric_unlock: bool,

        /// Prompt shown by the OS biometric dialog
        #[arg(long, default_value = "Unlock SentinelPass to retrieve a secret")]
        prompt_reason: String,
    },
}

#[derive(Subcommand)]
enum SyncCommands {
    /// Initialize sync for this vault (generates device identity, sets relay URL)
    Init {
        /// Relay server URL
        #[arg(long)]
        relay_url: String,

        /// Device name (defaults to hostname)
        #[arg(long)]
        device_name: Option<String>,
    },

    /// Trigger a sync cycle now (push pending changes, pull remote changes)
    Now,

    /// Show sync status (enabled, device info, pending changes)
    Status,

    /// List all devices in this vault's sync group
    DeviceList,

    /// Revoke a device from the sync group
    DeviceRevoke {
        /// Device ID to revoke
        device_id: String,
    },

    /// Start pairing (existing device generates code for new device)
    PairStart,

    /// Join sync from a new device using a pairing code
    PairJoin {
        /// Relay server URL
        #[arg(long)]
        relay_url: String,

        /// 6-digit pairing code
        #[arg(long)]
        code: String,

        /// Pairing salt (base64) printed by `pair-start`
        #[arg(long)]
        salt: String,
    },

    /// Disable sync for this vault
    Disable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum SecretField {
    Username,
    Password,
    Title,
}

impl SecretField {
    fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::Title => "title",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum SecretOutputFormat {
    Plain,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum CliCredentialType {
    Password,
    ApiKey,
}

impl From<CliCredentialType> for CredentialType {
    fn from(value: CliCredentialType) -> Self {
        match value {
            CliCredentialType::Password => Self::Password,
            CliCredentialType::ApiKey => Self::ApiKey,
        }
    }
}

fn credential_type_label(credential_type: CredentialType) -> &'static str {
    match credential_type {
        CredentialType::Password => "password",
        CredentialType::ApiKey => "api_key",
        CredentialType::PasskeyReference => "passkey_reference",
    }
}

fn secret_value_label(credential_type: CredentialType) -> &'static str {
    match credential_type {
        CredentialType::Password => "Password",
        CredentialType::ApiKey => "API key",
        CredentialType::PasskeyReference => "Reference",
    }
}

impl From<SecretField> for ExternalSecretField {
    fn from(field: SecretField) -> Self {
        match field {
            SecretField::Username => Self::Username,
            SecretField::Password => Self::Password,
            SecretField::Title => Self::Title,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SecretLookupResult {
    domain: String,
    field: SecretField,
    client_id: Option<String>,
    purpose: Option<String>,
    value: String,
}

fn render_secret_lookup(result: &SecretLookupResult, output: SecretOutputFormat) -> Result<String> {
    match output {
        SecretOutputFormat::Plain => Ok(result.value.clone()),
        SecretOutputFormat::Json => serde_json::to_string(&serde_json::json!({
            "domain": &result.domain,
            "field": result.field.as_str(),
            "client_id": &result.client_id,
            "purpose": &result.purpose,
            "value": &result.value,
        }))
        .map_err(|e| anyhow::anyhow!("Failed to render secret lookup JSON: {}", e)),
    }
}

fn get_vault_path(cli: &Cli, dev: bool) -> PathBuf {
    if let Some(ref path) = cli.vault {
        path.clone()
    } else if dev {
        PathBuf::from(":memory:")
    } else {
        sentinelpass_core::get_default_vault_path()
    }
}

fn prompt_master_password(confirm: bool) -> Result<String> {
    let password = prompt_password("Enter master password: ")?;
    if confirm {
        let confirm_password = prompt_password("Confirm master password: ")?;
        if password != confirm_password {
            anyhow::bail!("Passwords do not match");
        }
    }
    Ok(password)
}

fn open_vault_with_password(vault_path: &PathBuf, master_password: &[u8]) -> Result<VaultManager> {
    match VaultManager::open(vault_path, master_password) {
        Ok(vault) => Ok(vault),
        Err(sentinelpass_core::PasswordManagerError::LockedOut(remaining_seconds)) => {
            anyhow::bail!(
                "Vault is temporarily locked after failed attempts. Try again in {} seconds.",
                remaining_seconds
            );
        }
        Err(e) => Err(anyhow::anyhow!("Failed to unlock vault: {}", e)),
    }
}

fn run_async<T>(future: impl std::future::Future<Output = T>) -> Result<T> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    Ok(runtime.block_on(future))
}

async fn unlock_daemon_with_biometric_if_requested(
    client: &IpcClient,
    biometric_unlock: bool,
    prompt_reason: &str,
) -> Result<()> {
    let status = client.send(IpcMessage::CheckVault).await?;
    let unlocked = matches!(status, IpcMessage::VaultStatusResponse { unlocked: true });

    if unlocked {
        return Ok(());
    }

    if !biometric_unlock {
        anyhow::bail!(
            "SentinelPass daemon is locked. Unlock the vault first or pass --biometric-unlock."
        );
    }

    match client
        .send(IpcMessage::UnlockVaultBiometric {
            prompt_reason: Some(prompt_reason.to_string()),
        })
        .await?
    {
        IpcMessage::UnlockVaultResponse { success: true, .. } => Ok(()),
        IpcMessage::UnlockVaultResponse {
            success: false,
            error,
        } => {
            let detail = error.unwrap_or_else(|| "unknown error".to_string());
            anyhow::bail!("Biometric unlock failed: {}", detail)
        }
        _ => anyhow::bail!("Unexpected daemon response during biometric unlock"),
    }
}

async fn get_secret_from_daemon(
    domain: String,
    field: SecretField,
    biometric_unlock: bool,
    prompt_reason: String,
    client_id: Option<String>,
    purpose: Option<String>,
) -> Result<SecretLookupResult> {
    let client = IpcClient::new(default_ipc_socket_path())?;
    unlock_daemon_with_biometric_if_requested(&client, biometric_unlock, &prompt_reason).await?;
    let lookup_domain = domain.clone();
    let lookup_client_id = client_id.clone();
    let lookup_purpose = purpose.clone();

    if let Some(client_id) = client_id {
        return match client
            .send(IpcMessage::GetExternalSecret {
                client_id,
                domain,
                field: field.into(),
                purpose,
            })
            .await?
        {
            IpcMessage::GetExternalSecretResponse {
                value,
                authorized: true,
                error: None,
            } => value
                .map(|value| SecretLookupResult {
                    domain: lookup_domain,
                    field,
                    client_id: lookup_client_id,
                    purpose: lookup_purpose,
                    value,
                })
                .ok_or_else(|| anyhow::anyhow!("Requested secret field is not available")),
            IpcMessage::GetExternalSecretResponse {
                authorized: false,
                error,
                ..
            } => {
                let detail = error.unwrap_or_else(|| "external secret access denied".to_string());
                anyhow::bail!("{}", detail)
            }
            IpcMessage::GetExternalSecretResponse {
                error: Some(error), ..
            } => anyhow::bail!("{}", error),
            _ => anyhow::bail!("Unexpected daemon response during external secret lookup"),
        };
    }

    match client.send(IpcMessage::GetCredential { domain }).await? {
        IpcMessage::GetCredentialResponse {
            username,
            password,
            title,
        } => {
            let value = match field {
                SecretField::Username => username,
                SecretField::Password => password,
                SecretField::Title => title,
            };

            value
                .map(|value| SecretLookupResult {
                    domain: lookup_domain,
                    field,
                    client_id: lookup_client_id,
                    purpose: lookup_purpose,
                    value,
                })
                .ok_or_else(|| anyhow::anyhow!("Requested secret field is not available"))
        }
        _ => anyhow::bail!("Unexpected daemon response during secret lookup"),
    }
}

fn allow_external_secret(
    client_id: String,
    domain: String,
    field: SecretField,
) -> Result<sentinelpass_core::ExternalSecretGrant> {
    ExternalSecretAllowlist::allow_default(&client_id, &domain, field.into())
        .map_err(|e| anyhow::anyhow!("Failed to update external secret allowlist: {}", e))
}

fn default_public_key_path(
    private_key_path: &Path,
    explicit_public_key: Option<&PathBuf>,
) -> PathBuf {
    explicit_public_key.cloned().unwrap_or_else(|| {
        let path_str = private_key_path.to_string_lossy();
        PathBuf::from(format!("{}.pub", path_str))
    })
}

fn extract_public_key_comment(public_key_line: &str) -> Option<String> {
    let mut parts = public_key_line.split_whitespace();
    let _key_type = parts.next()?;
    let _key_data = parts.next()?;
    let comment = parts.collect::<Vec<_>>().join(" ");
    if comment.is_empty() {
        None
    } else {
        Some(comment)
    }
}

fn compute_ssh_fingerprint(public_key_line: &str) -> Result<String> {
    let mut parts = public_key_line.split_whitespace();
    let _key_type = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid public key format: missing key type"))?;
    let key_data_b64 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid public key format: missing key data"))?;

    let key_data = base64::engine::general_purpose::STANDARD
        .decode(key_data_b64)
        .map_err(|e| anyhow::anyhow!("Invalid base64 in public key: {}", e))?;
    let digest = Sha256::digest(&key_data);
    let fingerprint_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);

    Ok(format!("SHA256:{}", fingerprint_b64))
}

fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN) // Reduce noise in CLI
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { dev } => {
            println!("Initializing new SentinelPass vault...");
            if dev {
                println!("Running in development mode (in-memory database)");
            }

            let vault_path = get_vault_path(&cli, dev);

            // Check if vault already exists
            if !dev && vault_path.exists() {
                anyhow::bail!("Vault already exists at: {:?}", vault_path);
            }

            let password = prompt_master_password(true)?;

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
        }

        Commands::SecretGet {
            domain,
            field,
            biometric_unlock,
            client_id,
            purpose,
            output,
            prompt_reason,
        } => {
            let result = run_async(get_secret_from_daemon(
                domain,
                field,
                biometric_unlock,
                prompt_reason,
                client_id,
                purpose,
            ))??;
            println!("{}", render_secret_lookup(&result, output)?);
        }

        Commands::Secret { command } => match command {
            SecretCommands::Allow {
                client_id,
                domain,
                field,
            } => {
                let grant = allow_external_secret(client_id, domain, field)?;
                println!(
                    "Allowed client '{}' to retrieve {} for {}",
                    grant.client_id,
                    grant.field.as_str(),
                    grant.domain
                );
            }
            SecretCommands::Get {
                client_id,
                domain,
                field,
                purpose,
                output,
                biometric_unlock,
                prompt_reason,
            } => {
                let result = run_async(get_secret_from_daemon(
                    domain,
                    field,
                    biometric_unlock,
                    prompt_reason,
                    Some(client_id),
                    purpose,
                ))??;
                println!("{}", render_secret_lookup(&result, output)?);
            }
        },

        Commands::Unlock => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!(
                    "No vault found at: {:?}\nUse 'sentinelpass init' to create a new vault",
                    vault_path
                );
            }

            let password = prompt_password("Enter master password: ")?;

            match open_vault_with_password(&vault_path, password.as_bytes()) {
                Ok(vault) => {
                    println!("✓ Vault unlocked successfully");
                    drop(vault);
                }
                Err(e) => {
                    error!("Failed to unlock vault: {}", e);
                    return Err(e);
                }
            }
        }

        Commands::Lock => {
            println!("Vault locks automatically when the process exits.");
            println!("The vault is only kept in memory during operations.");
        }

        Commands::BiometricStatus => {
            let vault_path = get_vault_path(&cli, false);
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
        }

        Commands::BiometricEnable {
            ref master_password,
        } => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = match master_password {
                Some(value) => value.to_string(),
                None => prompt_password("Enter master password: ")?,
            };
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            vault.enable_biometric_unlock(master_password.as_bytes())?;
            println!("Biometric unlock enabled for this vault.");
        }

        Commands::BiometricDisable => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            vault.disable_biometric_unlock()?;
            println!("Biometric unlock disabled for this vault.");
        }

        Commands::UnlockBiometric => {
            let vault_path = get_vault_path(&cli, false);
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
        }

        Commands::SshAgentStatus => {
            let client = SshAgentClient::new()?;
            let available = client.is_available();
            println!(
                "SSH agent available: {}",
                if available { "yes" } else { "no" }
            );
            if !available {
                println!(
                    "Hint: ensure `ssh-add` is installed and your SSH agent service is running."
                );
            }
        }

        Commands::SshAgentAdd { ref key_path } => {
            let client = SshAgentClient::new()?;
            client
                .add_identity(key_path)
                .map_err(|e| anyhow::anyhow!("Failed to add key to SSH agent: {}", e))?;
            println!("Added SSH key to agent: {}", key_path.display());
        }

        Commands::SshAgentAddStored { id } => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            let mut private_key = vault.export_ssh_private_key(id)?;

            let client = SshAgentClient::new()?;
            let add_result = client
                .add_identity_from_pem(&private_key)
                .map_err(|e| anyhow::anyhow!("Failed to add stored SSH key to agent: {}", e));
            private_key.clear();
            add_result?;

            println!("Added stored SSH key {} to agent.", id);
        }

        Commands::SshAgentClear => {
            let client = SshAgentClient::new()?;
            client
                .remove_all_identities()
                .map_err(|e| anyhow::anyhow!("Failed to clear SSH agent identities: {}", e))?;
            println!("Cleared all SSH agent identities.");
        }

        Commands::SshKeyAdd {
            ref name,
            ref private_key_file,
            ref public_key_file,
            ref comment,
        } => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let public_key_path =
                default_public_key_path(private_key_file, public_key_file.as_ref());
            if !private_key_file.exists() {
                anyhow::bail!("Private key file not found: {}", private_key_file.display());
            }
            if !public_key_path.exists() {
                anyhow::bail!("Public key file not found: {}", public_key_path.display());
            }

            let private_key = std::fs::read_to_string(private_key_file).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to read private key file {}: {}",
                    private_key_file.display(),
                    e
                )
            })?;
            let (public_key, key_type) = SshKeyImporter::import_public_key(&public_key_path)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to read public key file {}: {}",
                        public_key_path.display(),
                        e
                    )
                })?;

            let key_comment = comment
                .clone()
                .or_else(|| extract_public_key_comment(&public_key));
            let fingerprint = compute_ssh_fingerprint(&public_key)?;

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            let key_id = vault.add_ssh_key_plaintext(
                name.to_string(),
                key_comment,
                key_type,
                None,
                public_key,
                private_key,
                fingerprint,
            )?;

            println!("SSH key added with ID: {}", key_id);
        }

        Commands::SshKeyList => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            let keys = vault.list_ssh_keys()?;

            if keys.is_empty() {
                println!("No SSH keys found in vault.");
            } else {
                println!();
                println!("{:<5} {:<24} {:<18} Fingerprint", "ID", "Name", "Type");
                println!("{}", "-".repeat(96));
                for key in keys {
                    println!(
                        "{:<5} {:<24} {:<18} {}",
                        key.key_id, key.name, key.key_type, key.fingerprint
                    );
                }
                println!();
            }
        }

        Commands::SshKeyGet { id, show_private } => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            let key = vault.get_ssh_key(id)?;

            println!();
            println!("ID: {}", id);
            println!("Name: {}", key.name);
            if let Some(comment) = key.comment {
                println!("Comment: {}", comment);
            }
            println!("Type: {}", key.key_type);
            println!("Fingerprint: {}", key.fingerprint);
            println!("Public key: {}", key.public_key);

            if show_private {
                let private_key = vault.export_ssh_private_key(id)?;
                println!();
                println!("Private key:");
                println!("{}", private_key);
            }
            println!();
        }

        Commands::SshKeyDelete { id, force } => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            if !force {
                print!("Delete SSH key {}? [y/N]: ", id);
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut confirmation = String::new();
                std::io::stdin().read_line(&mut confirmation)?;
                if !confirmation.trim().to_lowercase().starts_with('y') {
                    println!("Delete cancelled");
                    return Ok(());
                }
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            vault.delete_ssh_key(id)?;
            println!("Deleted SSH key {}", id);
        }

        Commands::Add {
            ref title,
            ref username,
            ref password,
            credential_type,
            ref url,
            ref notes,
            favorite,
        } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let credential_type = CredentialType::from(credential_type);
            let password_str = match password {
                Some(p) => p.to_string(),
                None => prompt_password(format!(
                    "Enter {} for entry: ",
                    secret_value_label(credential_type)
                ))?,
            };

            let master_password = prompt_password("Enter master password to unlock vault: ")?;

            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

            let entry = VaultEntry {
                entry_id: None,
                title: title.to_string(),
                username: username.to_string(),
                password: password_str,
                url: url.clone(),
                notes: notes.clone(),
                credential_type,
                created_at: chrono::Utc::now(),
                modified_at: chrono::Utc::now(),
                favorite,
            };

            match vault.add_entry(&entry) {
                Ok(entry_id) => {
                    println!("✓ Entry created with ID: {}", entry_id);
                }
                Err(e) => {
                    error!("Failed to add entry: {}", e);
                    anyhow::bail!("Failed to add entry: {}", e);
                }
            }
        }

        Commands::List { show_passwords } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;

            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

            match vault.list_entries() {
                Ok(entries) => {
                    if entries.is_empty() {
                        println!("No entries found. Add one with 'sentinelpass add'");
                    } else {
                        println!();
                        println!(
                            "{:<5} {:<16} {:<30} {:<30} Fav",
                            "ID", "Type", "Title", "Username"
                        );
                        println!("{}", "-".repeat(96));
                        for entry in &entries {
                            let fav = if entry.favorite { "⭐" } else { "" };
                            println!(
                                "{:<5} {:<16} {:<30} {:<30} {}",
                                entry.entry_id,
                                credential_type_label(entry.credential_type),
                                entry.title,
                                entry.username,
                                fav
                            );
                        }
                        println!();
                        println!("Total: {} entries", entries.len());

                        if show_passwords {
                            println!();
                            println!(
                                "WARNING: Showing passwords (be careful of shoulder surfing!)"
                            );
                            println!();
                            for summary in &entries {
                                if let Ok(entry) = vault.get_entry(summary.entry_id) {
                                    println!("--- ID {} ---", summary.entry_id);
                                    println!(
                                        "{}: {}",
                                        secret_value_label(entry.credential_type),
                                        entry.password
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to list entries: {}", e);
                    anyhow::bail!("Failed to list entries: {}", e);
                }
            }
        }

        Commands::Get { id } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;

            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

            match vault.get_entry(id) {
                Ok(entry) => {
                    println!();
                    println!("Title: {}", entry.title);
                    println!("Type: {}", credential_type_label(entry.credential_type));
                    println!("Username: {}", entry.username);
                    println!(
                        "{}: {}",
                        secret_value_label(entry.credential_type),
                        entry.password
                    );
                    if let Some(url) = entry.url {
                        println!("URL: {}", url);
                    }
                    if let Some(notes) = entry.notes {
                        println!("Notes: {}", notes);
                    }
                    println!(
                        "Created: {}",
                        entry.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                    if entry.favorite {
                        println!("⭐ Favorite");
                    }
                    println!();
                }
                Err(e) => {
                    error!("Failed to get entry: {}", e);
                    anyhow::bail!(
                        "Entry {} not found. Use 'sentinelpass list' to see all entries",
                        id
                    );
                }
            }
        }

        Commands::Search { ref query } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;

            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

            match vault.list_entries() {
                Ok(entries) => {
                    let query_lower = query.to_lowercase();
                    let filtered: Vec<EntrySummary> = entries
                        .into_iter()
                        .filter(|e| {
                            e.title.to_lowercase().contains(&query_lower)
                                || e.username.to_lowercase().contains(&query_lower)
                        })
                        .collect();

                    if filtered.is_empty() {
                        println!("No entries found matching '{}'", query);
                    } else {
                        println!();
                        println!("Found {} entries matching '{}':", filtered.len(), query);
                        println!();
                        println!(
                            "{:<5} {:<16} {:<30} {:<30}",
                            "ID", "Type", "Title", "Username"
                        );
                        println!("{}", "-".repeat(88));
                        for entry in filtered {
                            println!(
                                "{:<5} {:<16} {:<30} {:<30}",
                                entry.entry_id,
                                credential_type_label(entry.credential_type),
                                entry.title,
                                entry.username
                            );
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to search entries: {}", e);
                    anyhow::bail!("Failed to search entries: {}", e);
                }
            }
        }

        Commands::Delete { id, force } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let master_password_bytes = master_password.as_bytes();

            let vault = open_vault_with_password(&vault_path, master_password_bytes)?;

            // Get entry details for confirmation
            let entry = vault.get_entry(id)?;

            if !force {
                println!("Entry to delete:");
                println!("  Title: {}", entry.title);
                println!("  Username: {}", entry.username);
                println!();
                print!("Are you sure you want to delete this entry? [y/N]: ");
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut confirmation = String::new();
                std::io::stdin().read_line(&mut confirmation)?;
                if !confirmation.trim().to_lowercase().starts_with('y') {
                    println!("Delete cancelled");
                    return Ok(());
                }
            }

            vault.delete_entry(id)?;
            println!("Entry deleted successfully");
        }

        Commands::Edit {
            id,
            ref title,
            ref username,
            ref password,
            new_password,
            ref url,
            ref notes,
            favorite,
        } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let master_password_bytes = master_password.as_bytes();

            let vault = open_vault_with_password(&vault_path, master_password_bytes)?;

            // Get existing entry
            let existing_entry = vault.get_entry(id)?;

            // Determine new values (use existing if not provided)
            let new_title = title
                .as_ref()
                .map(|x| x.as_str())
                .unwrap_or_else(|| existing_entry.title.as_str())
                .to_string();
            let new_username = username
                .as_ref()
                .map(|x| x.as_str())
                .unwrap_or_else(|| existing_entry.username.as_str())
                .to_string();

            // Handle password
            let new_password = if new_password {
                prompt_password("Enter new password: ")?
            } else {
                password
                    .as_ref()
                    .map(|x| x.as_str())
                    .unwrap_or_else(|| existing_entry.password.as_str())
                    .to_string()
            };

            let new_url = url.clone().or_else(|| existing_entry.url.clone());
            let new_notes = notes.clone().or_else(|| existing_entry.notes.clone());
            let new_favorite = favorite.unwrap_or(existing_entry.favorite);

            // Create updated entry
            use chrono::Utc;
            let updated_entry = VaultEntry {
                entry_id: Some(id),
                title: new_title,
                username: new_username,
                password: new_password,
                url: new_url,
                notes: new_notes,
                credential_type: existing_entry.credential_type,
                created_at: existing_entry.created_at,
                modified_at: Utc::now(),
                favorite: new_favorite,
            };

            vault.update_entry(id, &updated_entry)?;
            println!("Entry updated successfully");
        }

        Commands::TotpAdd {
            entry_id,
            ref secret,
            ref otpauth_uri,
            ref algorithm,
            digits,
            period,
            ref issuer,
            ref account,
        } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let (uri_secret, uri_algorithm, uri_digits, uri_period, uri_issuer, uri_account) =
                if let Some(uri) = otpauth_uri.as_ref() {
                    let parsed = parse_otpauth_uri(uri).map_err(|e| anyhow::anyhow!("{}", e))?;
                    (
                        Some(parsed.secret_base32),
                        Some(parsed.algorithm),
                        Some(parsed.digits),
                        Some(parsed.period),
                        parsed.issuer,
                        parsed.account_name,
                    )
                } else {
                    (None, None, None, None, None, None)
                };

            let secret_value = match (secret.as_ref(), uri_secret.as_ref()) {
                (Some(value), _) => value.to_string(),
                (None, Some(value)) => value.to_string(),
                (None, None) => prompt_password("Enter TOTP secret (base32): ")?,
            };

            let algorithm = match algorithm {
                Some(value) => value
                    .parse::<TotpAlgorithm>()
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
                None => uri_algorithm.unwrap_or(TotpAlgorithm::Sha1),
            };

            let digits = digits.or(uri_digits).unwrap_or(6);
            let period = period.or(uri_period).unwrap_or(30);
            let issuer_value = issuer.clone().or(uri_issuer);
            let account_value = account.clone().or(uri_account);

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

            let totp_id = vault.add_totp_secret(
                entry_id,
                &secret_value,
                algorithm,
                digits,
                period,
                issuer_value.as_deref(),
                account_value.as_deref(),
            )?;

            println!("TOTP secret saved (id: {}) for entry {}", totp_id, entry_id);
        }

        Commands::TotpCode { entry_id } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

            let code = vault.generate_totp_code(entry_id)?;
            println!("TOTP code: {}", code.code);
            println!("Valid for: {} seconds", code.seconds_remaining);
        }

        Commands::TotpRemove { entry_id, force } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            if !force {
                print!("Remove TOTP secret for entry {}? [y/N]: ", entry_id);
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut confirmation = String::new();
                std::io::stdin().read_line(&mut confirmation)?;
                if !confirmation.trim().to_lowercase().starts_with('y') {
                    println!("Removal cancelled");
                    return Ok(());
                }
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            vault.remove_totp_secret(entry_id)?;
            println!("TOTP secret removed for entry {}", entry_id);
        }

        Commands::Generate {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
            exclude_ambiguous,
            count,
        } => {
            let config = PasswordGeneratorConfig {
                length,
                include_lowercase: lowercase,
                include_uppercase: uppercase,
                include_digits: digits,
                include_symbols: symbols,
                exclude_ambiguous,
            };

            // Validate config
            if let Err(e) = config.validate() {
                anyhow::bail!("Invalid password generator configuration: {}", e);
            }

            println!();
            println!("Generated passwords:");
            println!();

            for i in 0..count {
                let password = generate_password(&config)?;
                println!("  {}: {}", i + 1, password);
            }

            println!();
        }

        Commands::Check { password } => {
            let password = password
                .map(Ok)
                .unwrap_or_else(|| prompt_password("Enter password to check: "))?;

            let analysis = analyze_password(&password)?;

            println!();
            println!("Password Analysis");
            println!("================");
            println!();

            // Print strength with color
            let color = analysis.strength.color_code();
            let reset = "\x1b[0m";
            println!(
                "Strength:  {}{}{}",
                color,
                analysis.strength.as_str(),
                reset
            );
            println!("Score:     {}/5", analysis.strength.score());
            println!();

            println!("Details:");
            println!("  Length:       {} characters", analysis.length);
            println!("  Entropy:      {:.2} bits", analysis.entropy_bits);
            println!("  Crack time:   {}", analysis.crack_time_human());
            println!();

            println!("Character types:");
            println!(
                "  Lowercase:    {}",
                if analysis.has_lowercase { "✓" } else { "✗" }
            );
            println!(
                "  Uppercase:    {}",
                if analysis.has_uppercase { "✓" } else { "✗" }
            );
            println!(
                "  Digits:       {}",
                if analysis.has_digits { "✓" } else { "✗" }
            );
            println!(
                "  Symbols:      {}",
                if analysis.has_symbols { "✓" } else { "✗" }
            );
            println!();

            if !analysis.warnings.is_empty() {
                println!("Warnings:");
                for warning in &analysis.warnings {
                    println!("  ⚠ {}", warning);
                }
                println!();
            }

            if !analysis.suggestions.is_empty() {
                println!("Suggestions:");
                for suggestion in &analysis.suggestions {
                    println!("  → {}", suggestion);
                }
                println!();
            }
        }

        Commands::Health {
            detailed,
            only_issues,
        } => {
            use sentinelpass_core::crypto::health::HealthScore;

            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let master_password_bytes = master_password.as_bytes();

            let vault = open_vault_with_password(&vault_path, master_password_bytes)?;

            // Get health summary
            let summary = vault.get_vault_health_summary()?;

            println!();
            println!("Vault Password Health Report");
            println!("===========================");
            println!();

            // Print overall score with color
            let score_color = if summary.overall_score >= 80 {
                "\x1b[32m" // green
            } else if summary.overall_score >= 60 {
                "\x1b[33m" // yellow
            } else if summary.overall_score >= 40 {
                "\x1b[31m" // red
            } else {
                "\x1b[35m" // magenta (critical)
            };
            let reset = "\x1b[0m";
            println!(
                "Overall Health Score: {}{}{}/100",
                score_color, summary.overall_score, reset
            );
            println!();

            println!("Summary:");
            println!("  Total passwords:     {}", summary.total_passwords);
            println!("  Unique passwords:    {}", summary.unique_count);
            println!("  Reused passwords:    {}", summary.reused_count);
            println!("  Weak passwords:      {}", summary.weak_count);
            println!("  Compromised:         {}", summary.compromised_count);
            println!();

            // Print strength distribution
            println!("Strength Distribution:");
            println!("  Excellent:  {}", summary.strength_distribution.excellent);
            println!("  Strong:     {}", summary.strength_distribution.strong);
            println!("  Good:       {}", summary.strength_distribution.good);
            println!("  Fair:       {}", summary.strength_distribution.fair);
            println!("  Weak:       {}", summary.strength_distribution.weak);
            println!("  Critical:   {}", summary.strength_distribution.critical);
            println!();

            // Print weak passwords if any
            if !summary.weak_passwords.is_empty() {
                println!("⚠ Weak Passwords:");
                for weak in &summary.weak_passwords {
                    println!("  • {} ({})", weak.title, weak.username);
                    println!("    Reason: {}", weak.reason);
                }
                println!();
            }

            // Detailed report if requested
            if detailed {
                let health_report = vault.get_password_health_report()?;
                println!("Detailed Password Report:");
                println!("========================");
                println!();

                for entry in &health_report {
                    if only_issues && entry.score >= HealthScore::Good {
                        continue;
                    }

                    let score_color = match entry.score {
                        HealthScore::Critical => "\x1b[35m",  // magenta
                        HealthScore::Weak => "\x1b[31m",      // red
                        HealthScore::Fair => "\x1b[33m",      // yellow
                        HealthScore::Good => "\x1b[32m",      // green
                        HealthScore::Strong => "\x1b[36m",    // cyan
                        HealthScore::Excellent => "\x1b[34m", // blue
                    };
                    let reset = "\x1b[0m";

                    println!("{}{}{}", score_color, entry.score.label(), reset);
                    println!("  Title:    {}", entry.title);
                    println!("  Username: {}", entry.username);
                    println!("  Score:    {}/5", entry.score.score());
                    println!("  Strength: {}/5", entry.strength.score);
                    println!("  Entropy:  {:.1} bits", entry.strength.entropy_bits);

                    if entry.is_compromised {
                        println!("  ⚠ COMPROMISED (found in data breaches)");
                    }
                    if entry.is_reused {
                        println!("  ⚠ REUSED across {} sites", entry.reuse_count);
                    }
                    println!();
                }
            }

            // Print recommendations
            if summary.compromised_count > 0 {
                println!("Recommendations:");
                println!(
                    "  • {} compromised password(s) should be changed immediately",
                    summary.compromised_count
                );
            }
            if summary.weak_count > 0 {
                println!(
                    "  • {} weak password(s) should be strengthened",
                    summary.weak_count
                );
            }
            if summary.reused_count > 0 {
                println!(
                    "  • {} reused password(s) - use unique passwords for each site",
                    summary.reused_count
                );
            }
            if summary.overall_score >= 80 {
                println!("  ✓ Your vault is in good shape!");
            }
            println!();
        }

        Commands::Export {
            ref output,
            ref format,
        } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let master_password_bytes = master_password.as_bytes();

            let vault = open_vault_with_password(&vault_path, master_password_bytes)?;

            match format.as_str() {
                "json" => {
                    export_to_json(&vault, output)?;
                    println!(
                        "Exported {} entries to {}",
                        vault.list_entries()?.len(),
                        output.display()
                    );
                }
                "csv" => {
                    export_to_csv(&vault, output)?;
                    println!(
                        "Exported {} entries to {}",
                        vault.list_entries()?.len(),
                        output.display()
                    );
                }
                _ => anyhow::bail!("Unsupported format: {}. Use 'json' or 'csv'", format),
            }
        }

        Commands::Import {
            ref input,
            ref format,
        } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let master_password_bytes = master_password.as_bytes();

            let mut vault = open_vault_with_password(&vault_path, master_password_bytes)?;

            match format.as_str() {
                "json" => {
                    let count = import_from_json(&mut vault, input)?;
                    println!("Imported {} entries from {}", count, input.display());
                }
                "csv" => {
                    let count = import_from_csv(&mut vault, input)?;
                    println!("Imported {} entries from {}", count, input.display());
                }
                "keepass" => {
                    let count = import_from_keepass_xml(&mut vault, input)?;
                    println!("Imported {} entries from {}", count, input.display());
                    println!("Note: Groups/tags have been preserved in the notes field.");
                }
                _ => anyhow::bail!(
                    "Unsupported format: {}. Use 'json', 'csv', or 'keepass'",
                    format
                ),
            }
        }

        Commands::KeePassImport { ref input } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let master_password_bytes = master_password.as_bytes();

            let mut vault = open_vault_with_password(&vault_path, master_password_bytes)?;

            let count = import_from_keepass_xml(&mut vault, input)?;
            println!("Imported {} entries from {}", count, input.display());
            println!("Note: Groups/tags have been preserved in the notes field.");
        }

        Commands::KeePassExport { ref output } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let master_password_bytes = master_password.as_bytes();

            let vault = open_vault_with_password(&vault_path, master_password_bytes)?;

            export_to_keepass_xml(&vault, output)?;
            println!("Exported vault entries to {}", output.display());
            println!("Note: This file contains unencrypted passwords. Handle with care!");
        }

        Commands::Sync(ref sync_cmd) => {
            handle_sync_command(&cli, sync_cmd)?;
        }
    }

    Ok(())
}

fn handle_sync_command(cli: &Cli, cmd: &SyncCommands) -> Result<()> {
    let vault_path = get_vault_path(cli, false);
    let allow_missing_vault = matches!(cmd, SyncCommands::PairJoin { .. });
    if !vault_path.exists() && !allow_missing_vault {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    match cmd {
        SyncCommands::Init {
            ref relay_url,
            ref device_name,
        } => {
            let master_password = prompt_master_password(false)?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

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
            println!("Next: register this device with the relay server:");
            println!("  sentinelpass sync now");
        }

        SyncCommands::Now => {
            let master_password = prompt_master_password(false)?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

            let status = vault.get_sync_status()?;
            if !status.enabled {
                anyhow::bail!("Sync is not initialized. Use 'sentinelpass sync init' first.");
            }

            let status = run_async(vault.sync_now())??;
            println!("Sync completed.");
            if let Some(ts) = status.last_sync_at {
                let dt = chrono::DateTime::from_timestamp(ts, 0)
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| ts.to_string());
                println!("Last synced: {}", dt);
            }
            println!("Pending changes: {}", status.pending_changes);
        }

        SyncCommands::Status => {
            let master_password = prompt_master_password(false)?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

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

        SyncCommands::DeviceList => {
            let master_password = prompt_master_password(false)?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

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

        SyncCommands::DeviceRevoke { ref device_id } => {
            let master_password = prompt_master_password(false)?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

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

        SyncCommands::PairStart => {
            let master_password = prompt_master_password(false)?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

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
            run_async(client.upload_bootstrap_with_proof(
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

        SyncCommands::PairJoin {
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

            let master_password = prompt_master_password(false)?;
            let mut vault = if vault_path.exists() {
                open_vault_with_password(&vault_path, master_password.as_bytes())?
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
            let (encrypted_bootstrap, relay_salt) = run_async(fetch_client.fetch_bootstrap(code))??;
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
            run_async(register_client.register_device_with_pairing(
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

        SyncCommands::Disable => {
            let master_password = prompt_master_password(false)?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_authorized_secret_get_contract_for_victor() {
        let cli = Cli::try_parse_from([
            "sentinelpass",
            "secret",
            "get",
            "--client-id",
            "victor",
            "--domain",
            "anthropic",
            "--field",
            "password",
            "--purpose",
            "victor-auth",
            "--output",
            "json",
            "--biometric-unlock",
        ])
        .unwrap();

        match cli.command {
            Commands::Secret {
                command:
                    SecretCommands::Get {
                        client_id,
                        domain,
                        field,
                        purpose,
                        output,
                        biometric_unlock,
                        ..
                    },
            } => {
                assert_eq!(client_id, "victor");
                assert_eq!(domain, "anthropic");
                assert!(matches!(field, SecretField::Password));
                assert_eq!(purpose, Some("victor-auth".to_string()));
                assert_eq!(output, SecretOutputFormat::Json);
                assert!(biometric_unlock);
            }
            _ => panic!("expected authorized secret get command"),
        }
    }

    #[test]
    fn parses_secret_allow_contract_for_local_tools() {
        let cli = Cli::try_parse_from([
            "sentinelpass",
            "secret",
            "allow",
            "victor",
            "--domain",
            "anthropic",
            "--field",
            "password",
        ])
        .unwrap();

        match cli.command {
            Commands::Secret {
                command:
                    SecretCommands::Allow {
                        client_id,
                        domain,
                        field,
                    },
            } => {
                assert_eq!(client_id, "victor");
                assert_eq!(domain, "anthropic");
                assert!(matches!(field, SecretField::Password));
            }
            _ => panic!("expected secret allow command"),
        }
    }

    #[test]
    fn parses_add_api_key_entry_contract() {
        let cli = Cli::try_parse_from([
            "sentinelpass",
            "add",
            "--title",
            "Anthropic API",
            "--username",
            "ANTHROPIC_API_KEY",
            "--password",
            "sk-ant-test",
            "--url",
            "anthropic",
            "--credential-type",
            "api-key",
        ])
        .unwrap();

        match cli.command {
            Commands::Add {
                title,
                username,
                password,
                url,
                credential_type,
                ..
            } => {
                assert_eq!(title, "Anthropic API");
                assert_eq!(username, "ANTHROPIC_API_KEY");
                assert_eq!(password, Some("sk-ant-test".to_string()));
                assert_eq!(url, Some("anthropic".to_string()));
                assert_eq!(credential_type, CliCredentialType::ApiKey);
                assert_eq!(
                    CredentialType::from(credential_type),
                    CredentialType::ApiKey
                );
            }
            _ => panic!("expected add command"),
        }
    }

    #[test]
    fn generic_add_rejects_passkey_reference_type() {
        let result = Cli::try_parse_from([
            "sentinelpass",
            "add",
            "--title",
            "Example Passkey",
            "--username",
            "user@example.com",
            "--password",
            "passkey-ref:example.com:user@example.com",
            "--credential-type",
            "passkey-reference",
        ]);

        match result {
            Err(err) => assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue),
            Ok(_) => panic!("expected generic add to reject passkey-reference"),
        }
    }

    #[test]
    fn legacy_secret_get_can_opt_into_client_allowlist() {
        let cli = Cli::try_parse_from([
            "sentinelpass",
            "secret-get",
            "--domain",
            "anthropic",
            "--field",
            "password",
            "--client-id",
            "victor",
            "--purpose",
            "victor-auth",
            "--output",
            "json",
        ])
        .unwrap();

        match cli.command {
            Commands::SecretGet {
                domain,
                field,
                client_id,
                purpose,
                output,
                ..
            } => {
                assert_eq!(domain, "anthropic");
                assert!(matches!(field, SecretField::Password));
                assert_eq!(client_id, Some("victor".to_string()));
                assert_eq!(purpose, Some("victor-auth".to_string()));
                assert_eq!(output, SecretOutputFormat::Json);
            }
            _ => panic!("expected legacy secret-get command"),
        }
    }

    #[test]
    fn renders_plain_secret_lookup_as_secret_value_only() {
        let result = SecretLookupResult {
            domain: "anthropic".to_string(),
            field: SecretField::Password,
            client_id: Some("victor".to_string()),
            purpose: Some("victor-auth".to_string()),
            value: "sk-ant-test".to_string(),
        };

        let rendered = render_secret_lookup(&result, SecretOutputFormat::Plain).unwrap();

        assert_eq!(rendered, "sk-ant-test");
    }

    #[test]
    fn renders_json_secret_lookup_with_metadata() {
        let result = SecretLookupResult {
            domain: "anthropic".to_string(),
            field: SecretField::Password,
            client_id: Some("victor".to_string()),
            purpose: Some("victor-auth".to_string()),
            value: "sk-ant-test".to_string(),
        };

        let rendered = render_secret_lookup(&result, SecretOutputFormat::Json).unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["domain"], "anthropic");
        assert_eq!(json["field"], "password");
        assert_eq!(json["client_id"], "victor");
        assert_eq!(json["purpose"], "victor-auth");
        assert_eq!(json["value"], "sk-ant-test");
    }
}
