//! Password health analysis for vault security assessment.
//!
//! This module provides functionality to analyze vault passwords and identify:
//! - Weak passwords (low entropy, predictable patterns)
//! - Reused passwords (same password across multiple sites)
//! - Compromised passwords (breach-correlation via HaveIBeenPwned —
//!   NOT YET IMPLEMENTED: `is_compromised` is a stub returning false;
//!   no network call exists. Wire to the k-anonymity range-query API or
//!   remove the claim before advertising breach checking)

use crate::crypto::strength::PasswordAnalysis;
use crate::vault::{Entry, VaultManager};
use crate::{PasswordManagerError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Health score for a password (0-5)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HealthScore {
    Critical = 0,  // Compromised or very weak
    Weak = 1,      // Low entropy
    Fair = 2,      // Moderate strength
    Good = 3,      // Strong but reused
    Strong = 4,    // Strong, unique
    Excellent = 5, // Very strong, unique, not compromised
}

impl HealthScore {
    /// Get numeric score
    pub fn score(&self) -> u8 {
        *self as u8
    }

    /// Get display label
    pub fn label(&self) -> &'static str {
        match self {
            HealthScore::Critical => "Critical",
            HealthScore::Weak => "Weak",
            HealthScore::Fair => "Fair",
            HealthScore::Good => "Good",
            HealthScore::Strong => "Strong",
            HealthScore::Excellent => "Excellent",
        }
    }

    /// Get color hint for UI
    pub fn color(&self) -> &'static str {
        match self {
            HealthScore::Critical => "#dc2626",  // red
            HealthScore::Weak => "#ea580c",      // orange
            HealthScore::Fair => "#ca8a04",      // yellow
            HealthScore::Good => "#16a34a",      // green
            HealthScore::Strong => "#15803d",    // dark green
            HealthScore::Excellent => "#14532d", // darker green
        }
    }
}

/// Health status for a single password
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHealth {
    /// Entry ID
    pub entry_id: i64,
    /// Entry title
    pub title: String,
    /// Entry username
    pub username: String,
    /// Entry URL (if available)
    pub url: Option<String>,
    /// Health score
    pub score: HealthScore,
    /// Whether password is compromised (in data breaches)
    pub is_compromised: bool,
    /// Whether password is reused across multiple sites
    pub is_reused: bool,
    /// Number of sites sharing this password
    pub reuse_count: usize,
    /// Password strength analysis
    pub strength: PasswordStrengthInfo,
}

/// Password strength information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordStrengthInfo {
    /// Overall score (0-5)
    pub score: u8,
    /// Entropy bits
    pub entropy_bits: f64,
    /// Estimated crack time (seconds)
    pub crack_time_seconds: f64,
    /// Password length
    pub length: usize,
    /// Has lowercase letters
    pub has_lowercase: bool,
    /// Has uppercase letters
    pub has_uppercase: bool,
    /// Has digits
    pub has_digits: bool,
    /// Has symbols
    pub has_symbols: bool,
}

impl From<PasswordAnalysis> for PasswordStrengthInfo {
    fn from(analysis: PasswordAnalysis) -> Self {
        Self {
            score: analysis.strength.score(),
            entropy_bits: analysis.entropy_bits,
            crack_time_seconds: analysis.crack_time_seconds,
            length: analysis.length,
            has_lowercase: analysis.has_lowercase,
            has_uppercase: analysis.has_uppercase,
            has_digits: analysis.has_digits,
            has_symbols: analysis.has_symbols,
        }
    }
}

/// Overall vault health summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHealthSummary {
    /// Total number of passwords in vault
    pub total_passwords: usize,
    /// Number of compromised passwords
    pub compromised_count: usize,
    /// Number of weak passwords
    pub weak_count: usize,
    /// Number of reused passwords
    pub reused_count: usize,
    /// Number of unique passwords
    pub unique_count: usize,
    /// Overall health score (0-100)
    pub overall_score: u8,
    /// Password strength distribution
    pub strength_distribution: StrengthDistribution,
    /// Most common weak passwords
    pub weak_passwords: Vec<WeakPasswordEntry>,
    /// Breach sources (if any passwords compromised)
    pub breach_sources: Vec<String>,
}

/// Distribution of password strengths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrengthDistribution {
    pub critical: usize,
    pub weak: usize,
    pub fair: usize,
    pub good: usize,
    pub strong: usize,
    pub excellent: usize,
}

/// Entry with a weak password
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakPasswordEntry {
    pub entry_id: i64,
    pub title: String,
    pub username: String,
    pub reason: String, // "Compromised", "Weak", "Reused"
}

impl VaultHealthSummary {
    /// Calculate overall health score (0-100)
    pub fn calculate_score(&mut self) {
        if self.total_passwords == 0 {
            self.overall_score = 100; // Empty vault is "healthy"
            return;
        }

        // Start with 100 and deduct points for issues
        let mut score = 100u8;

        // Deduct for compromised passwords (most severe)
        let compromised_penalty = (self.compromised_count as u8 * 20).min(80);
        score = score.saturating_sub(compromised_penalty);

        // Deduct for weak passwords
        let weak_penalty = (self.weak_count as u8 * 10).min(50);
        score = score.saturating_sub(weak_penalty);

        // Deduct for reused passwords
        let reuse_penalty = if self.reused_count > 0 {
            // Calculate percentage of reused passwords
            let reuse_pct = (self.reused_count * 100) / self.total_passwords;
            (reuse_pct / 5) as u8 // 5% penalty per 5% reused
        } else {
            0
        };
        score = score.saturating_sub(reuse_penalty);

        // Bonus for high unique count
        if self.unique_count == self.total_passwords && self.total_passwords > 5 {
            score = score.saturating_add(10);
        }

        self.overall_score = score.min(100);
    }
}

/// Password health analyzer
pub struct PasswordHealthAnalyzer;

impl PasswordHealthAnalyzer {
    /// Analyze the health of all passwords in the vault
    pub fn analyze_vault(vault: &VaultManager) -> Result<VaultHealthSummary> {
        if !vault.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        // Get all entries with full details including passwords
        let summaries = vault.list_entries()?;
        let mut entries = Vec::new();
        for summary in &summaries {
            match vault.get_entry(summary.entry_id) {
                Ok(entry) => entries.push(entry),
                Err(_) => continue,
            }
        }

        // Build password usage map
        let mut password_usage: HashMap<Vec<u8>, Vec<Entry>> = HashMap::new();
        for entry in &entries {
            let password_bytes = entry.password.as_bytes().to_vec();
            password_usage
                .entry(password_bytes)
                .or_default()
                .push(entry.clone());
        }

        // Find reused passwords (used more than once)
        let reused_passwords: HashSet<Vec<u8>> = password_usage
            .iter()
            .filter(|(_, entries)| entries.len() > 1)
            .map(|(password, _)| password.clone())
            .collect();

        // Analyze each entry
        let mut health_records = Vec::new();
        let mut compromised_count = 0;
        let mut weak_count = 0;
        let mut strength_dist = StrengthDistribution {
            critical: 0,
            weak: 0,
            fair: 0,
            good: 0,
            strong: 0,
            excellent: 0,
        };

        for entry in &entries {
            let is_reused = reused_passwords.contains(entry.password.as_bytes());
            let reuse_count = if is_reused {
                password_usage
                    .get(entry.password.as_bytes())
                    .map(|v| v.len())
                    .unwrap_or(1)
            } else {
                1
            };

            // Analyze password strength
            let analysis = crate::crypto::strength::analyze_password(&entry.password)?;

            // Determine health score
            let score = Self::calculate_health_score(&analysis, is_reused, false);

            // Update counts
            if score == HealthScore::Critical {
                compromised_count += 1;
            }
            if score <= HealthScore::Weak {
                weak_count += 1;
            }

            // Update strength distribution
            match score {
                HealthScore::Critical => strength_dist.critical += 1,
                HealthScore::Weak => strength_dist.weak += 1,
                HealthScore::Fair => strength_dist.fair += 1,
                HealthScore::Good => strength_dist.good += 1,
                HealthScore::Strong => strength_dist.strong += 1,
                HealthScore::Excellent => strength_dist.excellent += 1,
            }

            health_records.push(PasswordHealth {
                entry_id: entry.entry_id.unwrap_or(0),
                title: entry.title.clone(),
                username: entry.username.clone(),
                url: entry.url.clone(),
                score,
                is_compromised: false, // Will be updated by HaveIBeenPwned check
                is_reused,
                reuse_count,
                strength: PasswordStrengthInfo::from(analysis),
            });
        }

        // Find weak password entries for summary
        let weak_passwords: Vec<WeakPasswordEntry> = health_records
            .iter()
            .filter(|h| h.score <= HealthScore::Weak)
            .map(|h| WeakPasswordEntry {
                entry_id: h.entry_id,
                title: h.title.clone(),
                username: h.username.clone(),
                reason: if h.is_compromised {
                    "Compromised".to_string()
                } else if h.is_reused {
                    "Reused".to_string()
                } else {
                    "Weak".to_string()
                },
            })
            .take(10) // Limit to top 10
            .collect();

        let unique_count = entries.len() - reused_passwords.len();

        let mut summary = VaultHealthSummary {
            total_passwords: entries.len(),
            compromised_count,
            weak_count,
            reused_count: reused_passwords.len(),
            unique_count,
            overall_score: 0, // Will be calculated
            strength_distribution: strength_dist,
            weak_passwords,
            breach_sources: Vec::new(), // Will be populated by HaveIBeenPwned
        };

        summary.calculate_score();

        Ok(summary)
    }

    /// Get detailed health report for all entries
    pub fn get_health_report(vault: &VaultManager) -> Result<Vec<PasswordHealth>> {
        if !vault.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        // Get all entries with full details including passwords
        let summaries = vault.list_entries()?;
        let mut entries = Vec::new();
        for summary in &summaries {
            match vault.get_entry(summary.entry_id) {
                Ok(entry) => entries.push(entry),
                Err(_) => continue,
            }
        }

        // Build password usage map
        let mut password_usage: HashMap<Vec<u8>, Vec<Entry>> = HashMap::new();
        for entry in &entries {
            let password_bytes = entry.password.as_bytes().to_vec();
            password_usage
                .entry(password_bytes)
                .or_default()
                .push(entry.clone());
        }

        // Find reused passwords
        let reused_passwords: HashSet<Vec<u8>> = password_usage
            .iter()
            .filter(|(_, entries)| entries.len() > 1)
            .map(|(password, _)| password.clone())
            .collect();

        // Analyze each entry
        let mut health_records = Vec::new();
        for entry in &entries {
            let is_reused = reused_passwords.contains(entry.password.as_bytes());
            let reuse_count = if is_reused {
                password_usage
                    .get(entry.password.as_bytes())
                    .map(|v| v.len())
                    .unwrap_or(1)
            } else {
                1
            };

            let analysis = crate::crypto::strength::analyze_password(&entry.password)?;
            let score = Self::calculate_health_score(&analysis, is_reused, false);

            health_records.push(PasswordHealth {
                entry_id: entry.entry_id.unwrap_or(0),
                title: entry.title.clone(),
                username: entry.username.clone(),
                url: entry.url.clone(),
                score,
                is_compromised: false, // Placeholder - will use HaveIBeenPwned
                is_reused,
                reuse_count,
                strength: PasswordStrengthInfo::from(analysis),
            });
        }

        Ok(health_records)
    }

    /// Calculate health score for a password
    fn calculate_health_score(
        analysis: &PasswordAnalysis,
        is_reused: bool,
        is_compromised: bool,
    ) -> HealthScore {
        // Compromised passwords are always critical
        if is_compromised {
            return HealthScore::Critical;
        }

        // Reused strong passwords get downgraded to Good
        if is_reused && analysis.strength.score() >= 4 {
            return HealthScore::Good;
        }

        // Map strength score to health score
        match analysis.strength.score() {
            0 => HealthScore::Critical,
            1 => HealthScore::Weak,
            2 => HealthScore::Fair,
            3 => HealthScore::Good,
            4 => HealthScore::Strong,
            5 => HealthScore::Excellent,
            _ => HealthScore::Weak,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_score_labels() {
        assert_eq!(HealthScore::Critical.label(), "Critical");
        assert_eq!(HealthScore::Weak.label(), "Weak");
        assert_eq!(HealthScore::Fair.label(), "Fair");
        assert_eq!(HealthScore::Good.label(), "Good");
        assert_eq!(HealthScore::Strong.label(), "Strong");
        assert_eq!(HealthScore::Excellent.label(), "Excellent");
    }

    #[test]
    fn test_health_score_colors() {
        assert_eq!(HealthScore::Critical.color(), "#dc2626");
        assert_eq!(HealthScore::Weak.color(), "#ea580c");
        assert_eq!(HealthScore::Excellent.color(), "#14532d");
    }

    #[test]
    fn test_health_score_ordering() {
        assert!(HealthScore::Critical < HealthScore::Weak);
        assert!(HealthScore::Weak < HealthScore::Fair);
        assert!(HealthScore::Fair < HealthScore::Good);
        assert!(HealthScore::Good < HealthScore::Strong);
        assert!(HealthScore::Strong < HealthScore::Excellent);
    }

    #[test]
    fn test_calculate_health_score_compromised() {
        use crate::crypto::strength::PasswordStrength;

        let analysis = PasswordAnalysis {
            strength: PasswordStrength::VeryStrong,
            entropy_bits: 100.0,
            crack_time_seconds: 1e15,
            length: 20,
            has_lowercase: true,
            has_uppercase: true,
            has_digits: true,
            has_symbols: true,
            warnings: vec![],
            suggestions: vec![],
        };

        let score = PasswordHealthAnalyzer::calculate_health_score(&analysis, false, true);
        assert_eq!(score, HealthScore::Critical);
    }

    #[test]
    fn test_calculate_health_score_reused_strong() {
        use crate::crypto::strength::PasswordStrength;

        let analysis = PasswordAnalysis {
            strength: PasswordStrength::VeryStrong,
            entropy_bits: 100.0,
            crack_time_seconds: 1e15,
            length: 20,
            has_lowercase: true,
            has_uppercase: true,
            has_digits: true,
            has_symbols: true,
            warnings: vec![],
            suggestions: vec![],
        };

        let score = PasswordHealthAnalyzer::calculate_health_score(&analysis, true, false);
        assert_eq!(score, HealthScore::Good);
    }
}
