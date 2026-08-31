use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use rpassword::prompt_password;
use sentinelpass_core::{CredentialType, ExternalSecretField, VaultManager};
use std::path::PathBuf;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

mod commands;

/// SentinelPass CLI - A secure, local-first password manager
#[derive(Parser)]
#[command(name = "sentinelpass")]
#[command(author = "VJ Singh <vijay@anvaiops.com>")]
#[command(version)]
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

        /// Local tool client id used for allowlist authorization (required)
        #[arg(long)]
        client_id: String,

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

    /// Run a command with secrets injected as environment variables
    Exec {
        /// Local tool client id, for example `victor`
        #[arg(long)]
        client_id: String,

        /// Per-client grant token; defaults to $SENTINELPASS_CLIENT_TOKEN
        #[arg(long, env = "SENTINELPASS_CLIENT_TOKEN")]
        token: Option<String>,

        /// If the daemon is locked, request biometric unlock before lookup
        #[arg(long)]
        biometric_unlock: bool,

        /// Purpose label recorded in daemon audit context
        #[arg(long)]
        purpose: Option<String>,

        /// NAME=domain[:field] mapping; repeatable
        #[arg(long = "env")]
        env_specs: Vec<String>,

        /// Command and arguments to run (after `--`)
        #[arg(last = true)]
        command: Vec<std::ffi::OsString>,
    },

    /// Print resolved secrets as shell exports or JSON (no command runs)
    Env {
        /// Local tool client id, for example `victor`
        #[arg(long)]
        client_id: String,

        /// Per-client grant token; defaults to $SENTINELPASS_CLIENT_TOKEN
        #[arg(long, env = "SENTINELPASS_CLIENT_TOKEN")]
        token: Option<String>,

        /// If the daemon is locked, request biometric unlock before lookup
        #[arg(long)]
        biometric_unlock: bool,

        /// Purpose label recorded in daemon audit context
        #[arg(long)]
        purpose: Option<String>,

        /// Output format
        #[arg(long, value_enum, default_value_t = SecretOutputFormat::Exports)]
        format: SecretOutputFormat,

        /// NAME=domain[:field] mapping; repeatable
        #[arg(long = "env")]
        env_specs: Vec<String>,
    },

    /// Manage metadata-only passkey references
    Passkey {
        #[command(subcommand)]
        command: PasskeyCommands,
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

        /// Optional grant duration, for example 30m, 8h, or 7d
        #[arg(long)]
        expires_in: Option<String>,

        /// Also allow the client to write (upsert) this secret
        #[arg(long)]
        write: bool,

        /// Create a legacy grant that works without a client token
        #[arg(long)]
        no_token: bool,
    },

    /// Revoke a local tool's access to one field for one domain/service
    Revoke {
        /// Local tool client id, for example `victor`
        client_id: String,

        /// Domain or service key the client may no longer access
        #[arg(long)]
        domain: Option<String>,

        /// Field to revoke
        #[arg(long, value_enum)]
        field: Option<SecretField>,

        /// Revoke every grant for this client
        #[arg(long)]
        all: bool,
    },

    /// Manage per-client grant tokens
    Token {
        #[command(subcommand)]
        command: SecretTokenCommands,
    },

    /// List local-tool secret access grants
    List {
        /// Optional client id filter
        #[arg(long)]
        client_id: Option<String>,
    },

    /// Show local-tool secret access audit events
    Audit {
        /// Optional client id filter
        #[arg(long)]
        client_id: Option<String>,

        /// Maximum audit rows to inspect
        #[arg(long, default_value_t = 50)]
        limit: usize,

        /// Show only denied or failed access events
        #[arg(long)]
        failures_only: bool,
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

        /// Per-client grant token; defaults to $SENTINELPASS_CLIENT_TOKEN
        #[arg(long, env = "SENTINELPASS_CLIENT_TOKEN")]
        token: Option<String>,

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
enum SecretTokenCommands {
    /// Mint a client token (printed once; authorizes every grant for the client)
    Mint {
        /// Local tool client id, for example `victor`
        #[arg(long)]
        client_id: String,
    },

    /// Replace a client token; the old token stops working immediately
    Rotate {
        /// Local tool client id
        #[arg(long)]
        client_id: String,
    },

    /// Revoke a client token (fail-closed: all grants for the client are denied)
    Revoke {
        /// Local tool client id
        #[arg(long)]
        client_id: String,
    },

    /// Show client token status
    List {
        /// Optional client id filter
        #[arg(long)]
        client_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum PasskeyCommands {
    /// Add a metadata-only reference to a platform passkey
    Add {
        /// WebAuthn relying party ID, for example example.com
        #[arg(long)]
        relying_party_id: String,

        /// Account label shown by the platform authenticator
        #[arg(long)]
        account_label: String,

        /// Source platform, for example icloud-keychain, windows-hello, android, or security-key
        #[arg(long, default_value = "unknown")]
        platform: String,

        /// Optional display-safe credential identifier hint or fingerprint
        #[arg(long)]
        credential_id_hint: Option<String>,

        /// Optional expected sync source, for example icloud-keychain or external-authenticator
        #[arg(long)]
        sync_source: Option<String>,

        /// Notes about this passkey reference; do not include private key material
        #[arg(long)]
        notes: Option<String>,

        /// Mark as favorite
        #[arg(long)]
        favorite: bool,
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
    #[value(name = "exports")]
    Exports,
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

impl From<SecretField> for ExternalSecretField {
    fn from(field: SecretField) -> Self {
        match field {
            SecretField::Username => Self::Username,
            SecretField::Password => Self::Password,
            SecretField::Title => Self::Title,
        }
    }
}

impl From<ExternalSecretField> for SecretField {
    fn from(field: ExternalSecretField) -> Self {
        match field {
            ExternalSecretField::Username => Self::Username,
            ExternalSecretField::Password => Self::Password,
            ExternalSecretField::Title => Self::Title,
        }
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

pub(crate) fn prompt_master_password(confirm: bool) -> Result<String> {
    let password = prompt_password("Enter master password: ")?;
    if confirm {
        let confirm_password = prompt_password("Confirm master password: ")?;
        if password != confirm_password {
            anyhow::bail!("Passwords do not match");
        }
    }
    Ok(password)
}

pub(crate) fn open_vault_with_password(
    vault_path: &PathBuf,
    master_password: &[u8],
) -> Result<VaultManager> {
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

pub(crate) fn run_async<T>(future: impl std::future::Future<Output = T>) -> Result<T> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    Ok(runtime.block_on(future))
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
            let vault_path = get_vault_path(&cli, dev);
            commands::vault::handle_init(vault_path, dev)?;
        }

        Commands::Unlock => {
            let vault_path = get_vault_path(&cli, false);
            commands::vault::handle_unlock(vault_path)?;
        }

        Commands::Lock => {
            commands::vault::handle_lock()?;
        }

        Commands::BiometricStatus => {
            let vault_path = get_vault_path(&cli, false);
            commands::vault::handle_biometric_status(vault_path)?;
        }

        Commands::BiometricEnable {
            ref master_password,
        } => {
            let vault_path = get_vault_path(&cli, false);
            commands::vault::handle_biometric_enable(vault_path, master_password.as_deref())?;
        }

        Commands::BiometricDisable => {
            let vault_path = get_vault_path(&cli, false);
            commands::vault::handle_biometric_disable(vault_path)?;
        }

        Commands::UnlockBiometric => {
            let vault_path = get_vault_path(&cli, false);
            commands::vault::handle_unlock_biometric(vault_path)?;
        }

        Commands::SshAgentStatus => {
            commands::ssh::handle_ssh_agent_status()?;
        }

        Commands::SshAgentAdd { ref key_path } => {
            commands::ssh::handle_ssh_agent_add(key_path)?;
        }

        Commands::SshAgentAddStored { id } => {
            let vault_path = get_vault_path(&cli, false);
            commands::ssh::handle_ssh_agent_add_stored(vault_path, id)?;
        }

        Commands::SshAgentClear => {
            commands::ssh::handle_ssh_agent_clear()?;
        }

        Commands::SshKeyAdd {
            ref name,
            ref private_key_file,
            ref public_key_file,
            ref comment,
        } => {
            let vault_path = get_vault_path(&cli, false);
            commands::ssh::handle_ssh_key_add(
                vault_path,
                name,
                private_key_file,
                public_key_file.as_ref(),
                comment.clone(),
            )?;
        }

        Commands::SshKeyList => {
            let vault_path = get_vault_path(&cli, false);
            commands::ssh::handle_ssh_key_list(vault_path)?;
        }

        Commands::SshKeyGet { id, show_private } => {
            let vault_path = get_vault_path(&cli, false);
            commands::ssh::handle_ssh_key_get(vault_path, id, show_private)?;
        }

        Commands::SshKeyDelete { id, force } => {
            let vault_path = get_vault_path(&cli, false);
            commands::ssh::handle_ssh_key_delete(vault_path, id, force)?;
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
            commands::secret::handle_secret_get(
                domain,
                field,
                biometric_unlock,
                client_id,
                purpose,
                output,
                prompt_reason,
            )?;
        }

        Commands::Secret { command } => {
            commands::secret::handle_secret_command(&command)?;
        }

        Commands::Exec {
            client_id,
            token,
            biometric_unlock,
            purpose,
            env_specs,
            command,
        } => {
            let code = commands::exec::handle_exec_command(
                &env_specs,
                commands::exec::ExecOptions {
                    client_id,
                    token,
                    biometric_unlock,
                    purpose,
                },
                command,
            )?;
            std::process::exit(code);
        }

        Commands::Env {
            client_id,
            token,
            biometric_unlock,
            purpose,
            format,
            env_specs,
        } => {
            let code = commands::exec::handle_env_command(
                &env_specs,
                commands::exec::ExecOptions {
                    client_id,
                    token,
                    biometric_unlock,
                    purpose,
                },
                format,
            )?;
            std::process::exit(code);
        }

        Commands::Passkey { ref command } => match command {
            PasskeyCommands::Add {
                relying_party_id,
                account_label,
                platform,
                credential_id_hint,
                sync_source,
                notes,
                favorite,
            } => {
                let vault_path = get_vault_path(&cli, false);
                commands::passkey::handle_passkey_add(
                    vault_path,
                    relying_party_id,
                    account_label,
                    platform,
                    credential_id_hint.as_deref(),
                    sync_source.as_deref(),
                    notes.as_deref(),
                    *favorite,
                )?;
            }
        },

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
            let credential_type = CredentialType::from(credential_type);
            commands::credentials::handle_add(
                vault_path,
                title,
                username,
                password.as_deref(),
                credential_type,
                url.clone(),
                notes.clone(),
                favorite,
            )?;
        }

        Commands::List { show_passwords } => {
            let vault_path = get_vault_path(&cli, false);
            commands::credentials::handle_list(vault_path, show_passwords)?;
        }

        Commands::Get { id } => {
            let vault_path = get_vault_path(&cli, false);
            commands::credentials::handle_get(vault_path, id)?;
        }

        Commands::Search { ref query } => {
            let vault_path = get_vault_path(&cli, false);
            commands::credentials::handle_search(vault_path, query)?;
        }

        Commands::Delete { id, force } => {
            let vault_path = get_vault_path(&cli, false);
            commands::credentials::handle_delete(vault_path, id, force)?;
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
            commands::credentials::handle_edit(
                vault_path,
                id,
                title.as_deref(),
                username.as_deref(),
                password.as_deref(),
                new_password,
                url.clone(),
                notes.clone(),
                favorite,
            )?;
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
            commands::totp::handle_totp_add(
                vault_path,
                entry_id,
                secret.as_deref(),
                otpauth_uri.as_deref(),
                algorithm.as_deref(),
                digits,
                period,
                issuer.clone(),
                account.clone(),
            )?;
        }

        Commands::TotpCode { entry_id } => {
            let vault_path = get_vault_path(&cli, false);
            commands::totp::handle_totp_code(vault_path, entry_id)?;
        }

        Commands::TotpRemove { entry_id, force } => {
            let vault_path = get_vault_path(&cli, false);
            commands::totp::handle_totp_remove(vault_path, entry_id, force)?;
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
            commands::generate::handle_generate(
                length,
                lowercase,
                uppercase,
                digits,
                symbols,
                exclude_ambiguous,
                count,
            )?;
        }

        Commands::Check { password } => {
            commands::generate::handle_check(password)?;
        }

        Commands::Health {
            detailed,
            only_issues,
        } => {
            let vault_path = get_vault_path(&cli, false);
            commands::generate::handle_health(vault_path, detailed, only_issues)?;
        }

        Commands::Export {
            ref output,
            ref format,
        } => {
            let vault_path = get_vault_path(&cli, false);
            commands::import_export::handle_export(vault_path, output, format)?;
        }

        Commands::Import {
            ref input,
            ref format,
        } => {
            let vault_path = get_vault_path(&cli, false);
            commands::import_export::handle_import(vault_path, input, format)?;
        }

        Commands::KeePassImport { ref input } => {
            let vault_path = get_vault_path(&cli, false);
            commands::import_export::handle_keepass_import(vault_path, input)?;
        }

        Commands::KeePassExport { ref output } => {
            let vault_path = get_vault_path(&cli, false);
            commands::import_export::handle_keepass_export(vault_path, output)?;
        }

        Commands::Sync(ref sync_cmd) => {
            let vault_path = get_vault_path(&cli, false);
            commands::sync::handle(vault_path, sync_cmd)?;
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
                        expires_in,
                        ..
                    },
            } => {
                assert_eq!(client_id, "victor");
                assert_eq!(domain, "anthropic");
                assert!(matches!(field, SecretField::Password));
                assert_eq!(expires_in, None);
            }
            _ => panic!("expected secret allow command"),
        }
    }

    #[test]
    fn parses_secret_allow_with_expiry_for_local_tools() {
        let cli = Cli::try_parse_from([
            "sentinelpass",
            "secret",
            "allow",
            "victor",
            "--domain",
            "anthropic",
            "--field",
            "password",
            "--expires-in",
            "8h",
        ])
        .unwrap();

        match cli.command {
            Commands::Secret {
                command:
                    SecretCommands::Allow {
                        client_id,
                        domain,
                        field,
                        expires_in,
                        ..
                    },
            } => {
                assert_eq!(client_id, "victor");
                assert_eq!(domain, "anthropic");
                assert!(matches!(field, SecretField::Password));
                assert_eq!(expires_in, Some("8h".to_string()));
            }
            _ => panic!("expected expiring secret allow command"),
        }
    }

    #[test]
    fn parses_external_secret_grant_duration_units() {
        use commands::secret::parse_external_secret_grant_duration;
        assert_eq!(
            parse_external_secret_grant_duration("30m").unwrap(),
            chrono::Duration::minutes(30)
        );
        assert_eq!(
            parse_external_secret_grant_duration("8h").unwrap(),
            chrono::Duration::hours(8)
        );
        assert_eq!(
            parse_external_secret_grant_duration("7d").unwrap(),
            chrono::Duration::days(7)
        );
        assert!(parse_external_secret_grant_duration("0h").is_err());
        assert!(parse_external_secret_grant_duration("-1h").is_err());
        assert!(parse_external_secret_grant_duration("1w").is_err());
    }

    #[test]
    fn parses_secret_revoke_contract_for_local_tools() {
        let cli = Cli::try_parse_from([
            "sentinelpass",
            "secret",
            "revoke",
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
                    SecretCommands::Revoke {
                        client_id,
                        domain,
                        field,
                        ..
                    },
            } => {
                assert_eq!(client_id, "victor");
                assert_eq!(domain, Some("anthropic".to_string()));
                assert!(matches!(field, Some(SecretField::Password)));
            }
            _ => panic!("expected secret revoke command"),
        }
    }

    #[test]
    fn parses_secret_list_contract_for_local_tools() {
        let cli = Cli::try_parse_from(["sentinelpass", "secret", "list", "--client-id", "victor"])
            .unwrap();

        match cli.command {
            Commands::Secret {
                command: SecretCommands::List { client_id },
            } => {
                assert_eq!(client_id, Some("victor".to_string()));
            }
            _ => panic!("expected secret list command"),
        }
    }

    #[test]
    fn parses_secret_audit_contract_for_local_tools() {
        let cli = Cli::try_parse_from([
            "sentinelpass",
            "secret",
            "audit",
            "--client-id",
            "victor",
            "--limit",
            "25",
            "--failures-only",
        ])
        .unwrap();

        match cli.command {
            Commands::Secret {
                command:
                    SecretCommands::Audit {
                        client_id,
                        limit,
                        failures_only,
                    },
            } => {
                assert_eq!(client_id, Some("victor".to_string()));
                assert_eq!(limit, 25);
                assert!(failures_only);
            }
            _ => panic!("expected secret audit command"),
        }
    }

    #[test]
    fn renders_external_secret_audit_report_with_filters() {
        use commands::secret::render_external_secret_audit_report;
        let entries = vec![
            sentinelpass_core::AuditEntry {
                timestamp: chrono::Utc::now(),
                event_type: sentinelpass_core::AuditEventType::ExternalSecretAccess {
                    client_id: Some("victor".to_string()),
                    domain: "anthropic".to_string(),
                    field: Some("password".to_string()),
                    purpose: Some("victor-auth".to_string()),
                    success: true,
                },
                severity: 3,
                context: "granted".to_string(),
                pid: None,
                tid: None,
            },
            sentinelpass_core::AuditEntry {
                timestamp: chrono::Utc::now(),
                event_type: sentinelpass_core::AuditEventType::ExternalSecretAccess {
                    client_id: Some("other".to_string()),
                    domain: "anthropic".to_string(),
                    field: Some("password".to_string()),
                    purpose: Some("test".to_string()),
                    success: false,
                },
                severity: 2,
                context: "denied".to_string(),
                pid: None,
                tid: None,
            },
        ];

        let rendered = render_external_secret_audit_report(&entries, Some("victor"), false);

        assert!(rendered.contains("victor"));
        assert!(rendered.contains("anthropic"));
        assert!(rendered.contains("password"));
        assert!(rendered.contains("victor-auth"));
        assert!(!rendered.contains("other"));
        assert!(rendered.contains("Total: 1 events"));
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
    fn parses_passkey_reference_add_contract() {
        let cli = Cli::try_parse_from([
            "sentinelpass",
            "passkey",
            "add",
            "--relying-party-id",
            "example.com",
            "--account-label",
            "user@example.com",
            "--platform",
            "icloud-keychain",
            "--credential-id-hint",
            "cred-123",
            "--sync-source",
            "icloud-keychain",
            "--notes",
            "created on MacBook",
        ])
        .unwrap();

        match cli.command {
            Commands::Passkey {
                command:
                    PasskeyCommands::Add {
                        relying_party_id,
                        account_label,
                        platform,
                        credential_id_hint,
                        sync_source,
                        notes,
                        ..
                    },
            } => {
                assert_eq!(relying_party_id, "example.com");
                assert_eq!(account_label, "user@example.com");
                assert_eq!(platform, "icloud-keychain");
                assert_eq!(credential_id_hint, Some("cred-123".to_string()));
                assert_eq!(sync_source, Some("icloud-keychain".to_string()));
                assert_eq!(notes, Some("created on MacBook".to_string()));
            }
            _ => panic!("expected passkey add command"),
        }
    }

    #[test]
    fn passkey_reference_entry_is_metadata_only() {
        use commands::passkey::build_passkey_reference_entry;
        let entry = build_passkey_reference_entry(
            "example.com",
            "user@example.com",
            "icloud-keychain",
            Some("cred-123"),
            Some("icloud-keychain"),
            Some("created on MacBook"),
            false,
        )
        .unwrap();

        assert_eq!(entry.title, "Passkey reference: example.com");
        assert_eq!(entry.username, "user@example.com");
        assert_eq!(entry.url, Some("example.com".to_string()));
        assert_eq!(entry.notes, Some("created on MacBook".to_string()));
        assert_eq!(entry.credential_type, CredentialType::PasskeyReference);
        assert!(entry.password.contains("\"kind\":\"passkey_reference\""));
        assert!(entry.password.contains("\"platform\":\"icloud-keychain\""));
        assert!(!entry.credential_type.is_retrievable_secret());
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
                assert_eq!(client_id, "victor".to_string());
                assert_eq!(purpose, Some("victor-auth".to_string()));
                assert_eq!(output, SecretOutputFormat::Json);
            }
            _ => panic!("expected legacy secret-get command"),
        }
    }

    #[test]
    fn renders_plain_secret_lookup_as_secret_value_only() {
        use commands::secret::{render_secret_lookup, SecretLookupResult};
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
        use commands::secret::{render_secret_lookup, SecretLookupResult};
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
