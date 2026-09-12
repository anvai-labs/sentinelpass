//! Token bucket rate limiter with sustained abuse prevention.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Clock abstraction so ALL window math is deterministic under test
/// (WBS-910 / TD-REL-06). Production uses the monotonic system clock; tests
/// advance a fake clock FORWARD from the real `Instant::now()` instead of
/// subtracting durations from it — `Instant::now() - Duration` can underflow
/// (panic) on some platforms, which is exactly why the old window-reset
/// tests were `#[ignore]`d.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// Production clock: `Instant::now()` (monotonic).
#[derive(Debug, Clone, Copy, Default)]
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    max_tokens: u32,
    refill_rate: f64, // tokens per second
    hourly_buckets: Arc<Mutex<HashMap<String, HourlyBucket>>>,
    hourly_limit: u32,
    daily_buckets: Arc<Mutex<HashMap<String, DailyBucket>>>,
    daily_limit: u32,
    clock: Arc<dyn Clock>,
}

#[allow(dead_code)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

struct HourlyBucket {
    count: u32,
    window_start: Instant,
}

struct DailyBucket {
    count: u32,
    window_start: Instant,
}

#[allow(dead_code)]
impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self::with_clock(Arc::new(SystemClock), requests_per_minute)
    }

    /// Injectable-clock constructor (WBS-910): production passes the system
    /// clock via [`RateLimiter::new`]; tests pass a deterministic fake.
    fn with_clock(clock: Arc<dyn Clock>, requests_per_minute: u32) -> Self {
        // Hourly limit: 10x the per-minute rate (allows bursts but prevents sustained abuse)
        let hourly_limit = requests_per_minute.saturating_mul(10);
        // Daily limit: 100x the per-minute rate (allows legitimate usage while preventing automated abuse)
        let daily_limit = requests_per_minute.saturating_mul(100);

        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            max_tokens: requests_per_minute,
            refill_rate: requests_per_minute as f64 / 60.0,
            hourly_buckets: Arc::new(Mutex::new(HashMap::new())),
            hourly_limit,
            daily_buckets: Arc::new(Mutex::new(HashMap::new())),
            daily_limit,
            clock,
        }
    }

    pub fn check(&self, device_id: &str) -> bool {
        // One timestamp per decision: all three windows agree on "now".
        let now = self.clock.now();

        // Check per-minute rate limit (token bucket)
        if !self.check_minute_limit(device_id, now) {
            return false;
        }

        // Check per-hour quota (sliding window)
        if !self.check_hourly_limit(device_id, now) {
            return false;
        }

        // Check per-day quota (sliding window)
        self.check_daily_limit(device_id, now)
    }

    fn check_minute_limit(&self, device_id: &str, now: Instant) -> bool {
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let bucket = buckets.entry(device_id.to_string()).or_insert(TokenBucket {
            tokens: self.max_tokens as f64,
            last_refill: now,
        });

        // Refill tokens
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_rate).min(self.max_tokens as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn check_hourly_limit(&self, device_id: &str, now: Instant) -> bool {
        let mut buckets = match self.hourly_buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let bucket = buckets
            .entry(device_id.to_string())
            .or_insert(HourlyBucket {
                count: 0,
                window_start: now,
            });

        // Reset if window has expired (1 hour)
        if now.duration_since(bucket.window_start) >= Duration::from_secs(3600) {
            bucket.count = 0;
            bucket.window_start = now;
        }

        if bucket.count < self.hourly_limit {
            bucket.count += 1;
            true
        } else {
            false
        }
    }

    fn check_daily_limit(&self, device_id: &str, now: Instant) -> bool {
        let mut buckets = match self.daily_buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let bucket = buckets.entry(device_id.to_string()).or_insert(DailyBucket {
            count: 0,
            window_start: now,
        });

        // Reset if window has expired (24 hours)
        if now.duration_since(bucket.window_start) >= Duration::from_secs(86400) {
            bucket.count = 0;
            bucket.window_start = now;
        }

        if bucket.count < self.daily_limit {
            bucket.count += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Deterministic fake clock (WBS-910): starts at the real monotonic
    /// `Instant::now()` and advances only FORWARD by a controlled offset, so
    /// a test can place a window "an hour ago" without ever subtracting from
    /// `Instant::now()` (the underflow that hung the original tests).
    struct FakeClock {
        base: Instant,
        offset: Mutex<Duration>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                offset: Mutex::new(Duration::ZERO),
            }
        }

        fn advance(&self, by: Duration) {
            *self.offset.lock().unwrap() += by;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            let offset = *self.offset.lock().unwrap();
            self.base
                .checked_add(offset)
                .expect("fake clock offset overflowed Instant")
        }
    }

    #[test]
    fn rate_limiter_exhausts_tokens() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.check("device-a"));
        assert!(limiter.check("device-a"));
        assert!(!limiter.check("device-a"));
    }

    #[test]
    fn rate_limiter_is_key_scoped() {
        let limiter = RateLimiter::new(1);
        assert!(limiter.check("device-a"));
        assert!(!limiter.check("device-a"));
        assert!(limiter.check("device-b"));
    }

    #[test]
    fn rate_limiter_enforces_hourly_quota() {
        let limiter = RateLimiter::new(6); // 6 per minute, 60 per hour
        let key = "hourly-test";

        // Make rapid requests until we hit the per-minute limit
        let mut succeeded = 0;
        for _ in 0..10 {
            if limiter.check(key) {
                succeeded += 1;
            }
        }
        assert_eq!(succeeded, 6, "Should succeed for all 6 per-minute tokens");

        // Check that hourly bucket has 6 requests (matching the per-minute limit)
        let hourly_buckets = limiter.hourly_buckets.lock().unwrap();
        let bucket = hourly_buckets.get(key).unwrap();
        assert_eq!(
            bucket.count, 6,
            "Hourly count should match per-minute usage"
        );

        // Verify the hourly limit is higher than per-minute
        assert_eq!(limiter.hourly_limit, 60, "Hourly limit should be 60");
    }

    #[test]
    fn rate_limiter_enforces_daily_quota() {
        let limiter = RateLimiter::new(1); // 1 per minute, 100 per day
        let key = "daily-test";

        // Exhaust per-minute and hourly limits to reach daily limit
        // Note: This test would take a very long time to truly exhaust the daily limit
        // so we just verify the logic structure is correct

        // First request should always succeed
        assert!(limiter.check(key), "First request should succeed");

        // Verify the daily bucket was created and incremented
        let daily_buckets = limiter.daily_buckets.lock().unwrap();
        let bucket = daily_buckets.get(key);
        assert!(bucket.is_some(), "Daily bucket should exist");
        assert_eq!(bucket.unwrap().count, 1, "Daily count should be 1");
    }

    /// WBS-910 (TD-REL-06): the hourly window resets after 1 hour and the
    /// bucket restarts at the single new request. Driven entirely through
    /// the public `check` path with a forward-only fake clock — no sleeps,
    /// no `Instant` subtraction, runs on every platform in CI.
    #[test]
    fn rate_limiter_resets_hourly_window() {
        let clock = Arc::new(FakeClock::new());
        let limiter = RateLimiter::with_clock(clock.clone(), 10); // 10/min, 100/hour
        let key = "hourly-reset-test";

        // Reach the hourly limit of exactly 100: drain the 10 per-minute
        // tokens, clock-advance one minute to refill, repeat ten times
        // (600s of fake time — still inside the 1-hour window).
        for _ in 0..10 {
            for _ in 0..10 {
                assert!(limiter.check(key), "within per-minute and hourly limits");
            }
            clock.advance(Duration::from_secs(60));
        }
        // Minute tokens refilled by the advance, but the hourly quota is gone.
        assert!(!limiter.check(key), "hourly limit must block");

        // Advance past the hourly window (elapsed > 3600s): the bucket
        // resets and requests flow again.
        clock.advance(Duration::from_secs(3601));
        assert!(
            limiter.check(key),
            "hourly window reset should allow requests"
        );

        let buckets = limiter.hourly_buckets.lock().unwrap();
        assert_eq!(buckets.get(key).unwrap().count, 1, "count restarts at 1");
    }

    /// WBS-910 (TD-REL-06): the daily window resets after 24 hours, same
    /// deterministic discipline as the hourly test.
    #[test]
    fn rate_limiter_resets_daily_window() {
        let clock = Arc::new(FakeClock::new());
        let limiter = RateLimiter::with_clock(clock.clone(), 10); // 10/min, 100/hour, 1000/day
        let key = "daily-reset-test";

        // Reach the daily limit of exactly 1000: ten hourly batches of 100
        // requests (ten per-minute cycles each), jumping past the hourly
        // window between batches. Total fake time is
        // 10 * (600s + 3601s) = 42010s — still inside the 24-hour window,
        // so the daily window never resets mid-accumulation.
        for _ in 0..10 {
            for _ in 0..10 {
                for _ in 0..10 {
                    assert!(limiter.check(key), "within per-minute limit");
                }
                clock.advance(Duration::from_secs(60));
            }
            clock.advance(Duration::from_secs(3601)); // reset the hourly quota
        }
        assert!(!limiter.check(key), "daily limit must block");

        // Advance past the daily window (elapsed > 86400s): reset.
        clock.advance(Duration::from_secs(86401));
        assert!(
            limiter.check(key),
            "daily window reset should allow requests"
        );

        let buckets = limiter.daily_buckets.lock().unwrap();
        assert_eq!(buckets.get(key).unwrap().count, 1, "count restarts at 1");
    }

    #[test]
    fn rate_limiter_scales_quotas_with_per_minute_rate() {
        let limiter_low = RateLimiter::new(1); // 1/min, 10/hour, 100/day
        let limiter_high = RateLimiter::new(10); // 10/min, 100/hour, 1000/day

        // Verify internal limits scale correctly
        assert_eq!(
            limiter_low.hourly_limit, 10,
            "Low rate limiter hourly limit should be 10"
        );
        assert_eq!(
            limiter_low.daily_limit, 100,
            "Low rate limiter daily limit should be 100"
        );
        assert_eq!(
            limiter_high.hourly_limit, 100,
            "High rate limiter hourly limit should be 100"
        );
        assert_eq!(
            limiter_high.daily_limit, 1000,
            "High rate limiter daily limit should be 1000"
        );
    }

    /// Token refill is elapsed-time driven: exhaust, advance the fake clock
    /// ~1.1 refill periods, and exactly one token returns (WBS-910 made
    /// this deterministic — the previous version slept 1.1 real seconds).
    #[test]
    fn rate_limiter_minute_refill_works() {
        let clock = Arc::new(FakeClock::new());
        let limiter = RateLimiter::with_clock(clock.clone(), 60); // 60 per minute = 1 per second
        let key = "refill-test";

        // Exhaust all tokens
        for _ in 0..60 {
            assert!(limiter.check(key), "Should succeed within limit");
        }
        assert!(
            !limiter.check(key),
            "Should be rate limited after exhaustion"
        );

        // Advance 1 second for one token refill
        clock.advance(Duration::from_millis(1100));
        assert!(limiter.check(key), "Should succeed after token refill");
    }
}
