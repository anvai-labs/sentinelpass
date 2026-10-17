//! Bounded blocking I/O with cancellation of the waiter, not forced OS-thread
//! termination. A detached worker retains its permits until it actually exits.
use super::{Cancellation, CustodyError};
use sentinelpass_protocol::custody::Result;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

static PROCESS_BUDGET: Semaphore = Semaphore::const_new(64);
static AUDIT_BUDGET: Semaphore = Semaphore::const_new(8);
const PENDING: u8 = 0;
const STOPPED: u8 = 1;
const COMMITTING: u8 = 2;

pub(super) struct Work {
    phase: AtomicU8,
    lifetime: Cancellation,
    cancel: Cancellation,
    deadline: Instant,
}
impl Work {
    pub(super) fn check(&self) -> Result<()> {
        if self.lifetime.check().is_err() {
            return Err(CustodyError::Invalidated);
        }
        self.cancel.check()?;
        if Instant::now() >= self.deadline {
            return Err(CustodyError::Expired);
        }
        if self.phase.load(Ordering::Acquire) == STOPPED {
            return Err(CustodyError::Cancelled);
        }
        Ok(())
    }
    /// Last authorization check before commit/receipt finalization. After this
    /// transition, a caller that departs has an uncertain mutation outcome.
    pub(super) fn begin_commit(&self) -> Result<()> {
        self.check()?;
        self.phase
            .compare_exchange(PENDING, COMMITTING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CustodyError::Cancelled)?;
        self.check()
    }
}
struct StopOnDrop(Arc<Work>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        let _ =
            self.0
                .phase
                .compare_exchange(PENDING, STOPPED, Ordering::AcqRel, Ordering::Acquire);
    }
}

pub(super) async fn run<T: Send + 'static>(
    budget: Arc<Semaphore>,
    lifetime: Cancellation,
    cancel: &Cancellation,
    deadline: Instant,
    operation: impl FnOnce(&Work) -> Result<T> + Send + 'static,
) -> Result<T> {
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| CustodyError::Unavailable)?;
    let work = Arc::new(Work {
        phase: AtomicU8::new(PENDING),
        lifetime: lifetime.clone(),
        cancel: cancel.clone(),
        deadline,
    });
    work.check()?;
    let local = budget
        .try_acquire_owned()
        .map_err(|_| CustodyError::Capacity)?;
    let global = PROCESS_BUDGET
        .try_acquire()
        .map_err(|_| CustodyError::Capacity)?;
    let guard = StopOnDrop(work.clone());
    let (send, receive) = tokio::sync::oneshot::channel();
    runtime.spawn_blocking(move || {
        let result = work.check().and_then(|()| operation(&work));
        let result = if work.phase.load(Ordering::Acquire) == COMMITTING {
            result
        } else {
            work.check().and(result)
        };
        // The failed send owns and drops any late zeroizing secret here.
        drop((local, global));
        let _ = send.send(result);
    });
    let result = tokio::select! {
        biased;
        _ = lifetime.cancelled() => Err(CustodyError::Invalidated),
        _ = cancel.cancelled() => Err(CustodyError::Cancelled),
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => Err(CustodyError::Expired),
        result = receive => result.map_err(|_| CustodyError::Unavailable)?,
    };
    drop(guard);
    result
}

/// Audit is best effort, bounded by the same process budget and never holds a
/// custody lock or secret. Failure to admit an audit cannot undo delivery.
pub(super) fn audit(
    vault: Arc<crate::VaultManager>,
    operation: crate::audit::CustodyAuditOperation,
    success: bool,
) {
    let Ok(audit_permit) = AUDIT_BUDGET.try_acquire() else {
        tracing::warn!("Personal custody audit capacity unavailable");
        return;
    };
    let Ok(permit) = PROCESS_BUDGET.try_acquire() else {
        tracing::warn!("Personal custody audit capacity unavailable");
        return;
    };
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    runtime.spawn_blocking(move || {
        let (_permit, _audit_permit) = (permit, audit_permit);
        vault.custody_audit(operation, success);
    });
}

/// Records admission denials as well as executed mutations. A mutation moves
/// this guard into its worker, so abandoning the waiter cannot mislabel a later
/// successful commit as a failed mutation.
pub(super) struct AuditAttempt {
    vault: Arc<crate::VaultManager>,
    operation: crate::audit::CustodyAuditOperation,
    settled: bool,
}
impl AuditAttempt {
    pub(super) fn new(
        vault: Arc<crate::VaultManager>,
        operation: crate::audit::CustodyAuditOperation,
    ) -> Self {
        Self {
            vault,
            operation,
            settled: false,
        }
    }
    pub(super) fn finish_blocking(mut self, success: bool) {
        self.settled = true;
        self.vault.custody_audit(self.operation, success);
    }
    pub(super) fn finish(mut self, success: bool) {
        self.settled = true;
        audit(self.vault.clone(), self.operation, success);
    }
}
impl Drop for AuditAttempt {
    fn drop(&mut self) {
        if !self.settled {
            audit(self.vault.clone(), self.operation, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::{Cancellation, CustodyError};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};
    use tokio::sync::{Notify, Semaphore};

    #[derive(Default)]
    struct Gate {
        entered: Notify,
        ready: Mutex<bool>,
        release: Condvar,
    }
    impl Gate {
        fn block(&self) {
            self.entered.notify_one();
            let mut ready = self.ready.lock().unwrap();
            while !*ready {
                ready = self.release.wait(ready).unwrap();
            }
        }
        fn open(&self) {
            *self.ready.lock().unwrap() = true;
            self.release.notify_all();
        }
    }
    struct Release(Arc<Gate>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.open();
        }
    }

    #[tokio::test]
    async fn cancelled_blocking_work_keeps_capacity_until_it_exits() {
        let budget = Arc::new(Semaphore::new(1));
        let gate = Arc::new(Gate::default());
        let _release = Release(gate.clone());
        let cancel = Cancellation::new();
        let worker_gate = gate.clone();
        let future = run(
            budget.clone(),
            Cancellation::new(),
            &cancel,
            Instant::now() + Duration::from_secs(5),
            move |_| {
                worker_gate.block();
                Ok(())
            },
        );
        tokio::pin!(future);
        tokio::select! { _ = gate.entered.notified() => {}, result = &mut future => panic!("unexpected {result:?}") }
        cancel.cancel();
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(200), &mut future)
                .await
                .unwrap(),
            Err(CustodyError::Cancelled)
        );
        assert_eq!(budget.available_permits(), 0);
        assert_eq!(
            run(
                budget.clone(),
                Cancellation::new(),
                &Cancellation::new(),
                Instant::now() + Duration::from_secs(5),
                |_| Ok(())
            )
            .await,
            Err(CustodyError::Capacity)
        );
        gate.open();
        tokio::time::timeout(Duration::from_secs(1), async {
            while budget.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_discards_a_late_owned_result_and_retains_worker_permit() {
        struct OwnedResult(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for OwnedResult {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let budget = Arc::new(Semaphore::new(1));
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = dropped.clone();
        let gate = Arc::new(Gate::default());
        let _release = Release(gate.clone());
        let worker_gate = gate.clone();
        let cancel = Cancellation::new();
        let future = run(
            budget.clone(),
            Cancellation::new(),
            &cancel,
            Instant::now() + Duration::from_secs(5),
            move |_| {
                worker_gate.block();
                Ok(OwnedResult(observed))
            },
        );
        tokio::pin!(future);
        tokio::select! { _ = gate.entered.notified() => {}, _ = &mut future => panic!("unexpected completion") }
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(matches!(future.await, Err(CustodyError::Expired)));
        assert_eq!(budget.available_permits(), 0);
        gate.open();
        while !dropped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn cancellation_distinguishes_rollback_from_already_accepted_commit() {
        use crate::custody::NativeSecret;
        use rand::RngCore;
        use sentinelpass_protocol::custody::{CustodyScope, ObjectRef};
        for accepted in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let vault = Arc::new(crate::VaultManager::custody_benchmark_fixture(
                &dir.path().join("synthetic.db"),
            ));
            let scope = CustodyScope::decode(include_bytes!(
                "../../../bindings/custody/scope.golden.json"
            ))
            .unwrap();
            let reference = ObjectRef::decode(include_bytes!(
                "../../../bindings/custody/reference.golden.json"
            ))
            .unwrap();
            let mut value = zeroize::Zeroizing::new([0; 32]);
            rand::rngs::OsRng.fill_bytes(value.as_mut());
            let value = NativeSecret(value);
            let gate = Arc::new(Gate::default());
            let _release = Release(gate.clone());
            let worker_gate = gate.clone();
            let budget = Arc::new(Semaphore::new(1));
            let cancel = Cancellation::new();
            let (write_vault, write_scope, write_reference) =
                (vault.clone(), scope.clone(), reference.clone());
            let future = run(
                budget.clone(),
                Cancellation::new(),
                &cancel,
                Instant::now() + Duration::from_secs(5),
                move |work| {
                    write_vault.custody_put_checked(
                        &write_scope,
                        None,
                        &write_reference,
                        &value,
                        || work.check(),
                        || {
                            if accepted {
                                work.begin_commit()?;
                            }
                            worker_gate.block();
                            if !accepted {
                                work.begin_commit()?;
                            }
                            Ok(())
                        },
                    )
                },
            );
            tokio::pin!(future);
            tokio::select! { _ = gate.entered.notified() => {}, result = &mut future => panic!("unexpected {result:?}") }
            cancel.cancel();
            assert_eq!(future.await, Err(CustodyError::Cancelled));
            gate.open();
            tokio::time::timeout(Duration::from_secs(2), async {
                while budget.available_permits() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(vault.custody_read(&scope, &reference).is_ok(), accepted);
        }
    }
}
