//! Failed attempt lockout mechanism to prevent brute force attacks

use crate::{DatabaseError, PasswordManagerError, Result};
use chrono::{DateTime, Duration, Utc};
use rusqlite::Connection;
use std::net::IpAddr;
use std::str::FromStr;

/// Default maximum failed attempts before lockout
pub const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Sliding window used when counting recent failures for lockout decisions.
/// Failures older than this are ignored so historical events can't cause
/// permanent lockout.
pub const LOCKOUT_WINDOW_SECONDS: i64 = 3600; // 1 hour

/// Lockout configuration
#[derive(Debug, Clone)]
pub struct LockoutConfig {
    /// Maximum failed attempts before triggering lockout
    pub max_attempts: u32,
    /// Base lockout duration in seconds (exponential backoff multiplier)
    pub base_lockout_seconds: i64,
    /// Whether to enable lockout
    pub enabled: bool,
}

impl Default for LockoutConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            base_lockout_seconds: 60, // 1 minute
            enabled: true,
        }
    }
}

impl LockoutConfig {
    /// Calculate lockout duration based on number of failed attempts
    /// Uses exponential backoff: 2^(attempts - max_attempts) * base_duration
    pub fn calculate_lockout_duration(&self, failed_attempts: u32) -> Option<Duration> {
        if !self.enabled || failed_attempts < self.max_attempts {
            return None;
        }

        let excess_attempts = failed_attempts - self.max_attempts;
        let multiplier = 2_i64.pow(excess_attempts.min(10)); // Cap at 2^10 to avoid overflow
        let seconds = self.base_lockout_seconds * multiplier;

        Some(Duration::seconds(seconds))
    }
}

/// Lockout manager for tracking failed unlock attempts
pub struct LockoutManager {
    conn: Connection,
    config: LockoutConfig,
}

impl LockoutManager {
    /// Create a new lockout manager
    pub fn new(conn: Connection, config: LockoutConfig) -> Result<Self> {
        Ok(Self { conn, config })
    }

    /// Create with default configuration
    pub fn with_defaults(conn: Connection) -> Result<Self> {
        Ok(Self {
            conn,
            config: LockoutConfig::default(),
        })
    }

    /// Record a failed unlock attempt
    pub fn record_failed_attempt(&self, ip_address: Option<IpAddr>) -> Result<()> {
        let ip_str = ip_address.map(|ip| ip.to_string());
        let now = Utc::now().timestamp();

        self.conn
            .execute(
                "INSERT INTO failed_attempts (attempt_time, ip_address) VALUES (?1, ?2)",
                (now, ip_str),
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        Ok(())
    }

    /// Get the count of failed attempts within a time window
    pub fn get_recent_failed_attempts(&self, within_seconds: i64) -> Result<u32> {
        let cutoff = Utc::now().timestamp() - within_seconds;

        let count: u32 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM failed_attempts WHERE attempt_time > ?1",
                [cutoff],
                |row| row.get(0),
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        Ok(count)
    }

    /// Get total failed attempts (all time)
    pub fn get_total_failed_attempts(&self) -> Result<u32> {
        let count: u32 = self
            .conn
            .query_row("SELECT COUNT(*) FROM failed_attempts", [], |row| row.get(0))
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        Ok(count)
    }

    /// Get the timestamp of the last failed attempt
    pub fn get_last_failed_attempt_time(&self) -> Result<Option<DateTime<Utc>>> {
        let result: Option<i64> = self
            .conn
            .query_row("SELECT MAX(attempt_time) FROM failed_attempts", [], |row| {
                row.get(0)
            })
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        Ok(result.map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or_default()))
    }

    /// Check if the vault is currently locked out
    pub fn is_locked_out(&self) -> Result<bool> {
        if !self.config.enabled {
            return Ok(false);
        }

        let recent_attempts = self.get_recent_failed_attempts(LOCKOUT_WINDOW_SECONDS)?;
        let lockout_duration = match self.config.calculate_lockout_duration(recent_attempts) {
            Some(d) => d,
            None => return Ok(false),
        };

        if let Some(last_attempt) = self.get_last_failed_attempt_time()? {
            let lockout_until = last_attempt + lockout_duration;
            Ok(Utc::now() < lockout_until)
        } else {
            Ok(false)
        }
    }

    /// Get the remaining lockout time in seconds
    pub fn get_remaining_lockout_seconds(&self) -> Result<Option<i64>> {
        if !self.config.enabled {
            return Ok(None);
        }

        let recent_attempts = self.get_recent_failed_attempts(LOCKOUT_WINDOW_SECONDS)?;
        let lockout_duration = match self.config.calculate_lockout_duration(recent_attempts) {
            Some(d) => d,
            None => return Ok(None),
        };

        if let Some(last_attempt) = self.get_last_failed_attempt_time()? {
            let lockout_until = last_attempt + lockout_duration;
            let remaining = lockout_until - Utc::now();
            if remaining.num_seconds() > 0 {
                return Ok(Some(remaining.num_seconds()));
            }
        }

        Ok(None)
    }

    /// Clear all failed attempt records (e.g., after successful unlock)
    pub fn clear_failed_attempts(&self) -> Result<()> {
        self.conn
            .execute("DELETE FROM failed_attempts", [])
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        Ok(())
    }

    /// Clear failed attempts older than the specified duration
    pub fn clear_old_attempts(&self, older_than_seconds: i64) -> Result<u32> {
        let cutoff = Utc::now().timestamp() - older_than_seconds;

        let deleted = self
            .conn
            .execute(
                "DELETE FROM failed_attempts WHERE attempt_time < ?1",
                [cutoff],
            )
            .map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

        Ok(deleted as u32)
    }
}

/// Parse an IP address from a string
pub fn parse_ip_address(ip_str: &str) -> Option<IpAddr> {
    IpAddr::from_str(ip_str).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_in_memory_lockout() -> LockoutManager {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS failed_attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_time INTEGER NOT NULL,
                ip_address TEXT
            )",
            [],
        )
        .unwrap();
        LockoutManager::with_defaults(conn).unwrap()
    }

    #[test]
    fn test_lockout_config_default() {
        let config = LockoutConfig::default();
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.base_lockout_seconds, 60);
        assert!(config.enabled);
    }

    #[test]
    fn test_calculate_lockout_duration() {
        let config = LockoutConfig::default();

        // No lockout below max attempts
        assert!(config.calculate_lockout_duration(3).is_none());
        assert!(config.calculate_lockout_duration(4).is_none());

        // Lockout at max attempts
        let duration = config.calculate_lockout_duration(5).unwrap();
        assert_eq!(duration, Duration::seconds(60));

        // Exponential backoff
        let duration = config.calculate_lockout_duration(6).unwrap();
        assert_eq!(duration, Duration::seconds(120));

        let duration = config.calculate_lockout_duration(7).unwrap();
        assert_eq!(duration, Duration::seconds(240));
    }

    #[test]
    fn test_record_failed_attempt() {
        let lockout = create_in_memory_lockout();

        lockout.record_failed_attempt(None).unwrap();
        assert_eq!(lockout.get_total_failed_attempts().unwrap(), 1);

        let ip = parse_ip_address("192.168.1.1").unwrap();
        lockout.record_failed_attempt(Some(ip)).unwrap();
        assert_eq!(lockout.get_total_failed_attempts().unwrap(), 2);
    }

    #[test]
    fn test_clear_failed_attempts() {
        let lockout = create_in_memory_lockout();

        lockout.record_failed_attempt(None).unwrap();
        lockout.record_failed_attempt(None).unwrap();
        assert_eq!(lockout.get_total_failed_attempts().unwrap(), 2);

        lockout.clear_failed_attempts().unwrap();
        assert_eq!(lockout.get_total_failed_attempts().unwrap(), 0);
    }

    #[test]
    fn test_is_locked_out() {
        let lockout = create_in_memory_lockout();

        // Not locked out initially
        assert!(!lockout.is_locked_out().unwrap());

        // Add 5 failed attempts
        for _ in 0..5 {
            lockout.record_failed_attempt(None).unwrap();
        }

        // Should be locked out now
        assert!(lockout.is_locked_out().unwrap());

        // Clear attempts
        lockout.clear_failed_attempts().unwrap();
        assert!(!lockout.is_locked_out().unwrap());
    }

    #[test]
    fn test_get_remaining_lockout_seconds() {
        let lockout = create_in_memory_lockout();

        // No lockout initially
        assert!(lockout.get_remaining_lockout_seconds().unwrap().is_none());

        // Add 5 failed attempts
        for _ in 0..5 {
            lockout.record_failed_attempt(None).unwrap();
        }

        // Should have remaining time
        let remaining = lockout.get_remaining_lockout_seconds().unwrap();
        assert!(remaining.is_some());
        assert!(remaining.unwrap() > 0);
    }

    #[test]
    fn test_parse_ip_address() {
        assert!(parse_ip_address("192.168.1.1").is_some());
        assert!(parse_ip_address("::1").is_some());
        assert!(parse_ip_address("invalid").is_none());
    }
}
