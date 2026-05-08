//! Relay server configuration.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Configuration for the relay server, loaded from TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    pub listen_addr: String,
    pub storage_path: PathBuf,
    pub max_entries_per_vault: usize,
    pub max_payload_size: usize,
    pub rate_limit_per_minute: u32,
    pub pairing_ttl_secs: u64,
    pub max_active_pairings: usize,
    pub pairing_fetch_attempt_limit: u32,
    pub pairing_fetch_backoff_base_secs: u64,
    pub pairing_fetch_backoff_max_secs: u64,
    pub tombstone_retention_days: u64,
    pub nonce_window_secs: i64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8743".to_string(),
            storage_path: PathBuf::from("relay.db"),
            max_entries_per_vault: 10_000,
            max_payload_size: 65_536,
            rate_limit_per_minute: 60,
            pairing_ttl_secs: 300,
            max_active_pairings: 5,
            pairing_fetch_attempt_limit: 5,
            pairing_fetch_backoff_base_secs: 5,
            pairing_fetch_backoff_max_secs: 300,
            tombstone_retention_days: 90,
            nonce_window_secs: 300,
        }
    }
}

impl RelayConfig {
    /// Load configuration from a TOML file at the given path.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml_dep::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate values that directly control relay availability and abuse resistance.
    pub fn validate(&self) -> anyhow::Result<()> {
        self.listen_addr.parse::<SocketAddr>().map_err(|e| {
            anyhow::anyhow!("Invalid relay listen address '{}': {}", self.listen_addr, e)
        })?;

        if self.storage_path.as_os_str().is_empty() {
            anyhow::bail!("Relay storage_path must not be empty");
        }
        if self.max_entries_per_vault == 0 {
            anyhow::bail!("Relay max_entries_per_vault must be greater than zero");
        }
        if self.max_payload_size == 0 {
            anyhow::bail!("Relay max_payload_size must be greater than zero");
        }
        if self.rate_limit_per_minute == 0 {
            anyhow::bail!("Relay rate_limit_per_minute must be greater than zero");
        }
        if self.pairing_ttl_secs == 0 {
            anyhow::bail!("Relay pairing_ttl_secs must be greater than zero");
        }
        if self.max_active_pairings == 0 {
            anyhow::bail!("Relay max_active_pairings must be greater than zero");
        }
        if self.pairing_fetch_attempt_limit == 0 {
            anyhow::bail!("Relay pairing_fetch_attempt_limit must be greater than zero");
        }
        if self.pairing_fetch_backoff_base_secs == 0 {
            anyhow::bail!("Relay pairing_fetch_backoff_base_secs must be greater than zero");
        }
        if self.pairing_fetch_backoff_max_secs < self.pairing_fetch_backoff_base_secs {
            anyhow::bail!(
                "Relay pairing_fetch_backoff_max_secs must be greater than or equal to pairing_fetch_backoff_base_secs"
            );
        }
        if self.tombstone_retention_days == 0 {
            anyhow::bail!("Relay tombstone_retention_days must be greater than zero");
        }
        if self.nonce_window_secs <= 0 {
            anyhow::bail!("Relay nonce_window_secs must be greater than zero");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        RelayConfig::default().validate().unwrap();
    }

    #[test]
    fn config_validation_rejects_zero_or_negative_security_limits() {
        let mut config = RelayConfig {
            rate_limit_per_minute: 0,
            ..RelayConfig::default()
        };
        assert!(config.validate().unwrap_err().to_string().contains("rate"));

        config = RelayConfig {
            nonce_window_secs: 0,
            ..RelayConfig::default()
        };
        assert!(config.validate().unwrap_err().to_string().contains("nonce"));
    }

    #[test]
    fn config_validation_rejects_malformed_listen_addr() {
        let config = RelayConfig {
            listen_addr: "not-a-socket".to_string(),
            ..RelayConfig::default()
        };

        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("listen"));
    }

    #[test]
    fn load_rejects_invalid_config_file() {
        let path = std::env::temp_dir().join(format!(
            "sentinelpass-relay-invalid-config-{}.toml",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            r#"
listen_addr = "127.0.0.1:8743"
storage_path = "relay.db"
max_entries_per_vault = 10000
max_payload_size = 65536
rate_limit_per_minute = 0
pairing_ttl_secs = 300
max_active_pairings = 5
pairing_fetch_attempt_limit = 5
pairing_fetch_backoff_base_secs = 5
pairing_fetch_backoff_max_secs = 300
tombstone_retention_days = 90
nonce_window_secs = 300
"#,
        )
        .unwrap();

        let err = RelayConfig::load(&path).unwrap_err();

        assert!(err.to_string().contains("rate_limit_per_minute"));
        let _ = std::fs::remove_file(path);
    }
}
