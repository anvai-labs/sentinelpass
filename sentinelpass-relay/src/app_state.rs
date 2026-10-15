//! Shared relay application state.

use crate::config::RelayConfig;
use crate::rate_limit::RateLimiter;
use crate::storage::RelayStorage;
use std::sync::Arc;

/// Shared state for handlers and middleware.
#[derive(Clone)]
pub struct RelayAppState {
    pub storage: RelayStorage,
    pub config: Arc<RelayConfig>,
    pub rate_limiter: RateLimiter,
    database_work: Arc<tokio::sync::Semaphore>,
}

impl RelayAppState {
    pub fn new(storage: RelayStorage, config: RelayConfig) -> Self {
        let rate_limiter = RateLimiter::new(config.rate_limit_per_minute);
        Self {
            storage,
            config: Arc::new(config),
            rate_limiter,
            database_work: Arc::new(tokio::sync::Semaphore::new(16)),
        }
    }

    /// Keep synchronous SQLite work off async executor threads. Acquire
    /// before spawning, so saturation cannot create an unbounded work queue.
    pub(crate) async fn run_blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(Self) -> Result<T, crate::error::RelayError> + Send + 'static,
    ) -> Result<T, crate::error::RelayError> {
        let permit = self
            .database_work
            .clone()
            .try_acquire_owned()
            .map_err(|_| crate::error::RelayError::RateLimited)?;
        let state = self.clone();
        tokio::task::spawn_blocking(move || {
            // Keep capacity held even if the requesting HTTP future is dropped.
            let _permit = permit;
            work(state)
        })
        .await
        .map_err(|e| crate::error::RelayError::Internal(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn saturated_database_work_rejects_without_enqueuing_and_recovers() {
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let capacity = state
            .database_work
            .clone()
            .try_acquire_many_owned(16)
            .unwrap();
        assert!(matches!(
            state.run_blocking(|_| Ok(())).await,
            Err(crate::error::RelayError::RateLimited)
        ));
        drop(capacity);
        assert_eq!(state.run_blocking(|_| Ok(42)).await.unwrap(), 42);
    }
}
