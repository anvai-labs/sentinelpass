//! Sync configuration stored in the local database.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{DatabaseError, Result};

/// Sync configuration for this device.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncConfig {
    pub sync_enabled: bool,
    pub vault_id: Option<Uuid>,
    pub device_id: Option<Uuid>,
    pub device_name: Option<String>,
    pub relay_url: Option<String>,
    pub last_push_sequence: u64,
    pub last_pull_sequence: u64,
    pub last_sync_at: Option<i64>,
}

impl SyncConfig {
    /// Load sync config from the database. Returns default if no row exists.
    pub fn load(conn: &rusqlite::Connection) -> Result<Self> {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_metadata')",
                [],
                |row| row.get(0),
            )
            .map_err(DatabaseError::Sqlite)?;

        if !exists {
            return Ok(Self::default());
        }

        let result = conn.query_row(
            "SELECT vault_id, device_id, device_name, relay_url,
                    last_push_sequence, last_pull_sequence, last_sync_at, sync_enabled
             FROM sync_metadata WHERE id = 1",
            [],
            |row| {
                let vault_id: Option<String> = row.get(0)?;
                let device_id: Option<String> = row.get(1)?;
                let device_name: Option<String> = row.get(2)?;
                let relay_url: Option<String> = row.get(3)?;
                let last_push_sequence: i64 = row.get(4)?;
                let last_pull_sequence: i64 = row.get(5)?;
                let last_sync_at: Option<i64> = row.get(6)?;
                let sync_enabled: bool = row.get(7)?;

                Ok(SyncConfig {
                    sync_enabled,
                    vault_id: vault_id.and_then(|s| Uuid::parse_str(&s).ok()),
                    device_id: device_id.and_then(|s| Uuid::parse_str(&s).ok()),
                    device_name,
                    relay_url,
                    last_push_sequence: last_push_sequence as u64,
                    last_pull_sequence: last_pull_sequence as u64,
                    last_sync_at,
                })
            },
        );

        match result {
            Ok(config) => Ok(config),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(Self::default()),
            Err(e) => Err(DatabaseError::Sqlite(e).into()),
        }
    }

    /// Save sync config to the database (upsert).
    pub fn save(&self, conn: &rusqlite::Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO sync_metadata (id, vault_id, device_id, device_name, relay_url,
                                        last_push_sequence, last_pull_sequence, last_sync_at, sync_enabled)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                vault_id = excluded.vault_id,
                device_id = excluded.device_id,
                device_name = excluded.device_name,
                relay_url = excluded.relay_url,
                last_push_sequence = excluded.last_push_sequence,
                last_pull_sequence = excluded.last_pull_sequence,
                last_sync_at = excluded.last_sync_at,
                sync_enabled = excluded.sync_enabled",
            rusqlite::params![
                self.vault_id.map(|u| u.to_string()),
                self.device_id.map(|u| u.to_string()),
                self.device_name,
                self.relay_url,
                self.last_push_sequence as i64,
                self.last_pull_sequence as i64,
                self.last_sync_at,
                self.sync_enabled,
            ],
        )
        .map_err(DatabaseError::Sqlite)?;

        Ok(())
    }
}

/// Environment variable that explicitly permits cleartext `http://` relay
/// URLs for loopback development (running `sentinelpass-relay` locally).
/// Non-loopback HTTP is rejected even when this is set.
pub const ALLOW_LOOPBACK_RELAY_ENV: &str = "SENTINELPASS_ALLOW_LOOPBACK_RELAY";

/// Validate a relay URL before it is stored or used.
///
/// Policy (TD-NET-02, containment half; full client redirect/userinfo rules
/// land with sync v2):
/// - `https://` to any host is accepted.
/// - `http://` is accepted only for a loopback host AND when
///   [`ALLOW_LOOPBACK_RELAY_ENV`] is set to exactly `1`.
/// - URLs carrying userinfo (`user:pass@host`) are always rejected —
///   credentials must not live in relay URLs.
/// - Any other scheme (`ftp`, `file`, `ws`, …) is rejected.
pub fn validate_relay_url(url: &str) -> Result<()> {
    let invalid = |reason: &str| {
        crate::PasswordManagerError::InvalidInput(format!("invalid relay URL: {reason}"))
    };

    let parsed = url::Url::parse(url).map_err(|e| invalid(&e.to_string()))?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid(
            "userinfo (user:password@) is not allowed in relay URLs",
        ));
    }

    // Use the typed host (not host_str) — IPv6 rendering varies by url-crate
    // version (brackets or not), and Ipv4Addr/Ipv6Addr::is_loopback is exact.
    let is_loopback = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    };

    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback => {
            let allowed = std::env::var(ALLOW_LOOPBACK_RELAY_ENV)
                .map(|v| v == "1")
                .unwrap_or(false);
            if allowed {
                Ok(())
            } else {
                Err(invalid(&format!(
                    "cleartext HTTP is only permitted for loopback development. If this \
                     is a stored configuration from an older build, either set \
                     {ALLOW_LOOPBACK_RELAY_ENV}=1 for a localhost relay, or re-initialize \
                     sync with an HTTPS relay URL (`sentinelpass sync init --relay-url \
                     https://...`)"
                )))
            }
        }
        "http" => Err(invalid(
            "cleartext HTTP is not permitted for non-loopback relays; use HTTPS",
        )),
        other => Err(invalid(&format!("unsupported scheme '{other}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;

    fn setup_db() -> Database {
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();
        db
    }

    #[test]
    fn default_config() {
        let config = SyncConfig::default();
        assert!(!config.sync_enabled);
        assert!(config.vault_id.is_none());
        assert!(config.device_id.is_none());
        assert_eq!(config.last_push_sequence, 0);
    }

    /// Relay URL transport policy. Env mutations are sequential inside this
    /// one test to avoid cross-test races on the process-global environment.
    #[test]
    fn relay_url_transport_policy() {
        use super::validate_relay_url;

        std::env::remove_var(super::ALLOW_LOOPBACK_RELAY_ENV);

        // HTTPS anywhere: accepted.
        assert!(validate_relay_url("https://relay.example.com").is_ok());
        assert!(validate_relay_url("https://relay.example.com:8443/base").is_ok());

        // HTTP non-loopback: rejected, with or without the dev allowance.
        assert!(validate_relay_url("http://relay.example.com").is_err());
        assert!(validate_relay_url("http://192.168.1.10:8743").is_err());
        std::env::set_var(super::ALLOW_LOOPBACK_RELAY_ENV, "1");
        assert!(
            validate_relay_url("http://relay.example.com").is_err(),
            "loopback allowance must not open non-loopback HTTP"
        );
        std::env::remove_var(super::ALLOW_LOOPBACK_RELAY_ENV);

        // HTTP loopback: only with the explicit dev allowance.
        assert!(validate_relay_url("http://127.0.0.1:8743").is_err());
        assert!(validate_relay_url("http://localhost:8743").is_err());
        assert!(validate_relay_url("http://[::1]:8743").is_err());
        std::env::set_var(super::ALLOW_LOOPBACK_RELAY_ENV, "1");
        assert!(validate_relay_url("http://127.0.0.1:8743").is_ok());
        assert!(validate_relay_url("http://localhost:8743").is_ok());
        assert!(validate_relay_url("http://[::1]:8743").is_ok());
        // Only the exact value 1 opts in.
        std::env::set_var(super::ALLOW_LOOPBACK_RELAY_ENV, "0");
        assert!(validate_relay_url("http://127.0.0.1:8743").is_err());
        std::env::remove_var(super::ALLOW_LOOPBACK_RELAY_ENV);

        // Userinfo and non-HTTP schemes: always rejected.
        assert!(validate_relay_url("https://user:pass@relay.example.com").is_err());
        assert!(validate_relay_url("https://user@relay.example.com").is_err());
        assert!(validate_relay_url("ftp://relay.example.com").is_err());
        assert!(validate_relay_url("file:///etc/passwd").is_err());
        assert!(validate_relay_url("not a url").is_err());
    }

    #[test]
    fn load_returns_default_when_no_table() {
        // Create a bare DB without sync_metadata table
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let config = SyncConfig::load(&conn).unwrap();
        assert!(!config.sync_enabled);
        assert!(config.vault_id.is_none());
    }

    #[test]
    fn load_returns_default_when_no_rows() {
        let db = setup_db();
        // sync_metadata table exists but has no rows
        let config = SyncConfig::load(db.conn()).unwrap();
        assert!(!config.sync_enabled);
        assert!(config.vault_id.is_none());
        assert_eq!(config.last_push_sequence, 0);
        assert_eq!(config.last_pull_sequence, 0);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let db = setup_db();
        let conn = db.conn();

        let vault_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        let config = SyncConfig {
            sync_enabled: true,
            vault_id: Some(vault_id),
            device_id: Some(device_id),
            device_name: Some("My Laptop".to_string()),
            relay_url: Some("https://relay.example.com".to_string()),
            last_push_sequence: 42,
            last_pull_sequence: 37,
            last_sync_at: Some(1700000000),
        };

        config.save(conn).unwrap();

        let loaded = SyncConfig::load(conn).unwrap();
        assert!(loaded.sync_enabled);
        assert_eq!(loaded.vault_id, Some(vault_id));
        assert_eq!(loaded.device_id, Some(device_id));
        assert_eq!(loaded.device_name.as_deref(), Some("My Laptop"));
        assert_eq!(
            loaded.relay_url.as_deref(),
            Some("https://relay.example.com")
        );
        assert_eq!(loaded.last_push_sequence, 42);
        assert_eq!(loaded.last_pull_sequence, 37);
        assert_eq!(loaded.last_sync_at, Some(1700000000));
    }

    #[test]
    fn save_upserts_on_conflict() {
        let db = setup_db();
        let conn = db.conn();

        let config1 = SyncConfig {
            sync_enabled: true,
            device_name: Some("First".to_string()),
            last_push_sequence: 1,
            ..Default::default()
        };
        config1.save(conn).unwrap();

        let config2 = SyncConfig {
            sync_enabled: false,
            device_name: Some("Second".to_string()),
            last_push_sequence: 99,
            ..Default::default()
        };
        config2.save(conn).unwrap();

        let loaded = SyncConfig::load(conn).unwrap();
        assert!(!loaded.sync_enabled);
        assert_eq!(loaded.device_name.as_deref(), Some("Second"));
        assert_eq!(loaded.last_push_sequence, 99);
    }
}
