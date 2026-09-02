//! Rotation-policy engine (ADR-001).
//!
//! Pure functions over value inputs — no I/O, no clock reads — so the policy
//! is unit-testable and the vault layer owns all time and database concerns.
//!
//! Interval resolution order: entry override → entity override → kind default
//! (Appendix B of the ADR); the criticality and reuse multipliers then apply.
//! Status floors: strength below threshold floors at [`RotationStatus::Weak`],
//! reuse at [`RotationStatus::Reused`], expiry and age at `DueSoon`/`Overdue`.
//! The most severe floor wins.

use serde::{Deserialize, Serialize};

use super::{Criticality, EntityKind};

/// Days before a due date / interval boundary at which `DueSoon` fires.
pub const DUE_SOON_WINDOW_DAYS: i64 = 14;

/// Reuse at or above this count floors the status at `Reused`.
pub const REUSE_FLOOR_COUNT: usize = 2;

const SECONDS_PER_DAY: i64 = 86_400;

/// Base rotation interval per entity kind (ADR-001 Appendix B).
pub fn base_interval_days(kind: EntityKind) -> i64 {
    match kind {
        EntityKind::Database | EntityKind::Broker => 90,
        EntityKind::RegulatoryData => 365,
        _ => 180,
    }
}

/// Rotation status for an entry. Ordering is severity: the recommendation
/// reports the most severe triggered floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Ok,
    DueSoon,
    Weak,
    Reused,
    Overdue,
}

/// Rotation recommendation for one entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRecommendation {
    pub status: RotationStatus,
    pub reasons: Vec<String>,
    pub resolved_interval_days: i64,
}

/// Inputs to [`recommend`]. All values, no side tables.
pub struct RecommendationInput {
    pub kind: EntityKind,
    pub criticality: Criticality,
    /// Per-entry interval override (entry_lifecycle).
    pub entry_override_days: Option<i64>,
    /// Per-entity interval override (entities).
    pub entity_override_days: Option<i64>,
    /// Days since `password_rotated_at`, or since entry creation when the
    /// entry has never been stamped.
    pub age_days: i64,
    pub reuse_count: usize,
    /// 0–5 strength score; `None` when strength was not analyzed.
    pub strength_score: Option<u8>,
    /// Scores at or above this are at least `Weak`; strictly lower scores
    /// floor the status at `Weak`.
    pub weak_threshold_score: u8,
    /// Provider-managed expiry (unix seconds); drives `DueSoon`/`Overdue`
    /// independently of age.
    pub expires_at: Option<i64>,
    pub now: i64,
    /// Tool-managed secrets (v0.8.0 external writes) whose age is not
    /// tracked here: age-based floors are suppressed. Reuse, strength, and
    /// expiry floors always apply.
    pub suppress_age: bool,
}

/// Resolve the effective rotation interval, then apply the status floors.
pub fn recommend(input: &RecommendationInput) -> RotationRecommendation {
    let interval = resolved_interval_days(input);

    let mut status = RotationStatus::Ok;
    let mut reasons = Vec::new();
    let mut set_floor = |floor: RotationStatus, reason: String| {
        if floor > status {
            status = floor;
        }
        reasons.push(reason);
    };

    if let Some(score) = input.strength_score {
        if score < input.weak_threshold_score {
            set_floor(
                RotationStatus::Weak,
                format!(
                    "strength score {} is below the weak threshold {}",
                    score, input.weak_threshold_score
                ),
            );
        }
    }

    if input.reuse_count >= REUSE_FLOOR_COUNT {
        set_floor(
            RotationStatus::Reused,
            format!("secret is shared across {} entries", input.reuse_count),
        );
    }

    if let Some(expires_at) = input.expires_at {
        let days_left = (expires_at - input.now).div_euclid(SECONDS_PER_DAY);
        if days_left <= 0 {
            set_floor(
                RotationStatus::Overdue,
                "secret is past its recorded expiry".to_string(),
            );
        } else if days_left <= DUE_SOON_WINDOW_DAYS {
            set_floor(
                RotationStatus::DueSoon,
                format!("secret expires in {} days", days_left),
            );
        }
    }

    if !input.suppress_age {
        let days_remaining = interval - input.age_days;
        if days_remaining <= 0 {
            set_floor(
                RotationStatus::Overdue,
                format!(
                    "secret is {} days past its {} day rotation interval",
                    -days_remaining, interval
                ),
            );
        } else if days_remaining <= DUE_SOON_WINDOW_DAYS {
            set_floor(
                RotationStatus::DueSoon,
                format!(
                    "rotation due in {} days (interval {} days)",
                    days_remaining, interval
                ),
            );
        }
    }

    RotationRecommendation {
        status,
        reasons,
        resolved_interval_days: interval,
    }
}

/// Entry override → entity override → kind default, then criticality and
/// reuse multipliers, floored at one day.
pub fn resolved_interval_days(input: &RecommendationInput) -> i64 {
    let base = input
        .entry_override_days
        .or(input.entity_override_days)
        .unwrap_or_else(|| base_interval_days(input.kind));

    let mut interval = match input.criticality {
        Criticality::High => base / 2,
        Criticality::Low => base * 2,
        Criticality::Medium => base,
    };

    if input.reuse_count >= REUSE_FLOOR_COUNT {
        interval /= 2;
    }

    interval.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> RecommendationInput {
        RecommendationInput {
            kind: EntityKind::Database,
            criticality: Criticality::Medium,
            entry_override_days: None,
            entity_override_days: None,
            age_days: 0,
            reuse_count: 1,
            strength_score: None,
            weak_threshold_score: 2,
            expires_at: None,
            now: 1_000_000,
            suppress_age: false,
        }
    }

    #[test]
    fn fresh_unique_strong_secret_is_ok() {
        let recommendation = recommend(&input());
        assert_eq!(recommendation.status, RotationStatus::Ok);
        assert!(recommendation.reasons.is_empty());
        assert_eq!(recommendation.resolved_interval_days, 90);
    }

    #[test]
    fn interval_resolution_prefers_entry_then_entity_then_kind() {
        let mut input = input();
        input.entity_override_days = Some(30);
        assert_eq!(resolved_interval_days(&input), 30);
        input.entry_override_days = Some(7);
        assert_eq!(resolved_interval_days(&input), 7);
        input.entry_override_days = None;
        input.entity_override_days = None;
        assert_eq!(resolved_interval_days(&input), 90);
    }

    #[test]
    fn criticality_and_reuse_multipliers_apply_after_resolution() {
        let mut input = input();
        input.criticality = Criticality::High;
        assert_eq!(resolved_interval_days(&input), 45);

        input.criticality = Criticality::Low;
        assert_eq!(resolved_interval_days(&input), 360);

        input.criticality = Criticality::Medium;
        input.reuse_count = 2;
        assert_eq!(resolved_interval_days(&input), 45);

        // Never resolves to zero
        input.entry_override_days = Some(1);
        input.reuse_count = 4;
        assert_eq!(resolved_interval_days(&input), 1);
    }

    #[test]
    fn kind_defaults_match_policy_table() {
        assert_eq!(base_interval_days(EntityKind::Database), 90);
        assert_eq!(base_interval_days(EntityKind::Broker), 90);
        assert_eq!(base_interval_days(EntityKind::RegulatoryData), 365);
        assert_eq!(base_interval_days(EntityKind::Notification), 180);
        assert_eq!(base_interval_days(EntityKind::Other), 180);
    }

    #[test]
    fn reuse_floors_status_and_is_not_beaten_by_weak() {
        let mut input = input();
        input.reuse_count = 2;
        input.strength_score = Some(0);
        input.weak_threshold_score = 2;
        let recommendation = recommend(&input);
        assert_eq!(recommendation.status, RotationStatus::Reused);
        assert_eq!(recommendation.reasons.len(), 2);
    }

    #[test]
    fn expiry_drives_due_soon_and_overdue_independently_of_age() {
        let mut input = input();
        input.expires_at = Some(input.now + 3 * SECONDS_PER_DAY);
        assert_eq!(recommend(&input).status, RotationStatus::DueSoon);

        input.expires_at = Some(input.now - SECONDS_PER_DAY);
        assert_eq!(recommend(&input).status, RotationStatus::Overdue);
    }

    #[test]
    fn age_drives_due_soon_and_overdue_unless_suppressed() {
        let mut input = input();
        input.age_days = 85; // within the 14-day window of the 90d interval
        assert_eq!(recommend(&input).status, RotationStatus::DueSoon);

        input.age_days = 91;
        assert_eq!(recommend(&input).status, RotationStatus::Overdue);

        // Tool-managed: same age, no age floors
        input.age_days = 400;
        input.suppress_age = true;
        assert_eq!(recommend(&input).status, RotationStatus::Ok);

        // ...but reuse still floors
        input.reuse_count = 3;
        assert_eq!(recommend(&input).status, RotationStatus::Reused);
    }

    #[test]
    fn overdue_is_the_most_severe_floor() {
        let mut input = input();
        input.age_days = 200; // Overdue
        input.reuse_count = 3; // Reused
        input.strength_score = Some(0); // Weak
        assert_eq!(recommend(&input).status, RotationStatus::Overdue);
    }
}
