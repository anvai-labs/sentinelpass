use super::*;
use crate::daemon::DaemonVault;

fn scope() -> CustodyScope {
    serde_json::from_str(include_str!(
        "../../../../bindings/custody/scope.golden.json"
    ))
    .unwrap()
}
fn reference() -> ObjectRef {
    serde_json::from_str(include_str!(
        "../../../../bindings/custody/reference.golden.json"
    ))
    .unwrap()
}

// Helper to set up a reader with acquired lease and delivery receiver.
// Eliminates duplication across multiple custody tests.
async fn setup_reader_with_lease(
    harness: &Harness,
) -> (
    super::super::synthetic::Controller,
    NativeReadSession,
    CustodyLease,
    RuntimeReceiver,
) {
    let (control, read) = harness.reader().await;
    let receiver = control.receiver(&scope(), &reference()).unwrap();
    let mut lease = read
        .acquire(&scope(), &reference(), &Cancellation::new())
        .await
        .unwrap();
    lease
        .deliver_to(&receiver, &Cancellation::new())
        .await
        .unwrap();
    (control, read, lease, receiver)
}

// Helper to create a replay approval from an existing approval.
// Eliminates duplication across multiple custody tests.
fn replay_approval(approval: &PersonalApproval) -> PersonalApproval {
    PersonalApproval {
        state: approval.state.clone(),
        id: approval.id.clone(),
    }
}

// Helper to approve and execute a remove operation.
// Eliminates duplication across multiple custody tests.
async fn approve_and_remove(harness: &Harness) {
    let approval = harness
        .approve(harness.password.as_bytes(), "remove", None)
        .await
        .unwrap();
    harness
        .admin
        .remove(&scope(), &reference(), approval, &Cancellation::new())
        .await
        .unwrap();
}

struct Harness {
    _dir: tempfile::TempDir,
    password: Zeroizing<String>,
    daemon: DaemonVault,
    admin: PersonalCustodyAdmin,
}
impl Harness {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new(uuid::Uuid::new_v4().to_string());
        let path = dir.path().join("personal.db");
        let mut vault = crate::VaultManager::create(&path, password.as_bytes()).unwrap();
        vault.custody_test_audit_dir(dir.path().join("audit"));
        let daemon = DaemonVault::new(Some(path), 600).unwrap();
        daemon.unlock_with_manager(vault).await;
        let admin = Self::attach(&daemon).await;
        Self {
            _dir: dir,
            password,
            daemon,
            admin,
        }
    }
    async fn attach(daemon: &DaemonVault) -> PersonalCustodyAdmin {
        let state = Arc::new(Mutex::new(PersonalState {
            vault: daemon.manager().await,
            owner: scope(),
            approvals: StepUpState::new(),
            sources: HashMap::new(),
            reads: Vec::new(),
            lifetime: Cancellation::new(),
            workers: Arc::new(tokio::sync::Semaphore::new(1)),
            read_workers: Arc::new(tokio::sync::Semaphore::new(MAX_LIVE_LEASES)),
            generation: 0,
        }));
        daemon
            .custody
            .0
            .lock()
            .unwrap()
            .push(Arc::downgrade(&state));
        PersonalCustodyAdmin {
            state,
            connection: rand::random(),
        }
    }
    fn source(&self) -> NativeSource {
        let mut value = Zeroizing::new([0; 32]);
        rand::rngs::OsRng.fill_bytes(value.as_mut());
        let id = random_id().unwrap();
        self.admin.state.lock().unwrap().sources.insert(
            id,
            SourceEntry {
                scope: scope(),
                reference: reference(),
                value: NativeSecret(value),
                expires: Instant::now() + Duration::from_secs(120),
            },
        );
        NativeSource {
            state: Arc::downgrade(&self.admin.state),
            id,
        }
    }
    // Synthetic trusted native UI: fresh full password verification, no reused
    // unlock proof. This helper is not compiled into any product adapter.
    async fn approve(
        &self,
        password: &[u8],
        action: &str,
        source: Option<&NativeSource>,
    ) -> Result<PersonalApproval> {
        let vault = self.daemon.manager().await.ok_or(CustodyError::Locked)?;
        let _permit = self.daemon.kdf_permit().await;
        if self
            .admin
            .state
            .lock()
            .unwrap()
            .approvals
            .throttled()
            .is_some()
        {
            return Err(CustodyError::Denied);
        }
        let path = vault.vault_path().to_owned();
        let password = Zeroizing::new(password.to_vec());
        let verified =
            tokio::task::spawn_blocking(move || crate::VaultManager::open(path, &password))
                .await
                .unwrap();
        let state = self.admin.state.lock().unwrap();
        let current = state.vault.as_ref().ok_or(CustodyError::Locked)?;
        if !Arc::ptr_eq(&vault, current) {
            return Err(CustodyError::Invalidated);
        }
        match verified {
            Ok(verified) if verified.vault_uuid() == vault.vault_uuid() => {
                state.approvals.record_success()
            }
            _ => {
                state.approvals.record_failure();
                return Err(CustodyError::Denied);
            }
        }
        let reference = reference();
        let op = operation(
            &vault,
            action,
            &scope(),
            if action != "put" {
                Some(&reference)
            } else {
                None
            },
            source.map(|_| &reference),
            source.map(|s| &s.id),
        )?;
        let (id, _) = state.approvals.mint(self.admin.connection, &op);
        Ok(PersonalApproval {
            state: Arc::downgrade(&self.admin.state),
            id,
        })
    }
    async fn enroll(&self) {
        let source = self.source();
        let approval = self
            .approve(self.password.as_bytes(), "put", Some(&source))
            .await
            .unwrap();
        self.admin
            .put(&scope(), None, source, approval, &Cancellation::new())
            .await
            .unwrap();
    }
    async fn reader(&self) -> (super::super::synthetic::Controller, NativeReadSession) {
        let approval = self
            .approve(self.password.as_bytes(), "grant", None)
            .await
            .unwrap();
        let read = self
            .admin
            .authorize_read(&scope(), &reference(), approval, &Cancellation::new())
            .await
            .unwrap();
        let control = super::super::synthetic::Controller {
            state: read.state.clone(),
        };
        (control, read)
    }
}

#[tokio::test]
async fn native_custody_requires_fresh_exact_approval_and_burns_replays() {
    let harness = Harness::new().await;
    let source = harness.source();
    assert!(matches!(
        harness
            .approve(b"incorrect-synthetic-input", "put", Some(&source))
            .await,
        Err(CustodyError::Denied)
    ));
    let approval = harness
        .approve(harness.password.as_bytes(), "put", Some(&source))
        .await
        .unwrap();
    let replay = replay_approval(&approval);
    harness
        .admin
        .put(&scope(), None, source, approval, &Cancellation::new())
        .await
        .unwrap();
    assert_eq!(
        harness
            .admin
            .remove(&scope(), &reference(), replay, &Cancellation::new())
            .await,
        Err(CustodyError::Denied)
    );
    let approval = harness
        .approve(harness.password.as_bytes(), "remove", None)
        .await
        .unwrap();
    let mut wrong = scope();
    wrong.subject.push('x');
    assert_eq!(
        harness
            .admin
            .remove(&wrong, &reference(), approval, &Cancellation::new())
            .await,
        Err(CustodyError::Denied)
    );
    assert!(harness
        .daemon
        .manager()
        .await
        .unwrap()
        .custody_read(&scope(), &reference())
        .is_ok());
}

#[tokio::test]
async fn daemon_lock_wipes_native_sources_receivers_and_denies_late_delivery() {
    let harness = Harness::new().await;
    harness.enroll().await;
    let (control, read) = harness.reader().await;
    let retained_manager = harness.daemon.manager().await.unwrap();
    let receiver = control.receiver(&scope(), &reference()).unwrap();
    let mut lease = read
        .acquire(&scope(), &reference(), &Cancellation::new())
        .await
        .unwrap();
    let gate = control.pause_delivery();
    let task = tokio::spawn(async move { lease.deliver_to(&receiver, &Cancellation::new()).await });
    gate.started.notified().await;
    let _source = harness.source();
    harness.daemon.lock().await;
    gate.release.notify_one();
    assert_eq!(task.await.unwrap(), Err(CustodyError::Invalidated));
    assert!(retained_manager.is_unlocked()); // Arc survival cannot revive custody
    assert!(harness.admin.state.lock().unwrap().sources.is_empty());
    assert!(lock(&read.state).unwrap().objects.is_empty());
    assert!(lock(&read.state).unwrap().vault.is_none());
    assert_eq!(control.live_handles(), 0);
}

#[tokio::test]
async fn native_remove_revokes_existing_reads_and_wipes_delivered_value() {
    let harness = Harness::new().await;
    harness.enroll().await;
    let (control, read, _lease, receiver) = setup_reader_with_lease(&harness).await;
    assert!(control.receiver_matches_object(&receiver));
    approve_and_remove(&harness).await;
    assert!(!control.receiver_has_secret(&receiver));
    assert!(matches!(
        read.acquire(&scope(), &reference(), &Cancellation::new())
            .await,
        Err(CustodyError::Invalidated)
    ));
}

#[tokio::test]
async fn repeated_grants_share_capacity_and_replacement_invalidates_old_session() {
    let harness = Harness::new().await;
    harness.enroll().await;
    let (_control, read) = harness.reader().await;
    let (_other_control, other) = harness.reader().await;
    assert!(Arc::ptr_eq(&read.state, &other.state));
    let mut leases = Vec::new();
    for _ in 0..MAX_LIVE_LEASES {
        leases.push(
            read.acquire(&scope(), &reference(), &Cancellation::new())
                .await
                .unwrap(),
        );
    }
    assert!(matches!(
        other
            .acquire(&scope(), &reference(), &Cancellation::new())
            .await,
        Err(CustodyError::Capacity)
    ));
    let replacement =
        crate::VaultManager::open(harness.daemon.vault_path(), harness.password.as_bytes())
            .unwrap();
    harness.daemon.unlock_with_manager(replacement).await;
    assert!(matches!(
        read.acquire(&scope(), &reference(), &Cancellation::new())
            .await,
        Err(CustodyError::Invalidated)
    ));
    assert!(harness.admin.state.lock().unwrap().vault.is_none());
}

#[cfg(unix)]
#[test]
#[ignore = "manual loaded-provider storage timing; run alone"]
fn qualification_storage() {
    use crate::custody::tests::rss_high_water;
    use sentinelpass_protocol::custody::Purpose;
    type Backing = (
        tempfile::TempDir,
        Arc<crate::VaultManager>,
        Vec<(CustodyScope, ObjectRef)>,
    );
    fn trial(backings: &[Backing]) -> f64 {
        let barrier = std::sync::Barrier::new(backings.len());
        std::thread::scope(|threads| {
            let jobs: Vec<_> = backings
                .iter()
                .map(|(_, vault, grants)| {
                    let barrier = &barrier;
                    threads.spawn(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_time()
                            .build()
                            .unwrap();
                        rt.block_on(async {
                            barrier.wait();
                            let mut maximum: f64 = 0.0;
                            for _ in 0..100 {
                                // Model an already-authorized native unlock. Values
                                // are loaded anew and wiped every cycle. Password/OS
                                // interaction is intentionally outside warm timing.
                                let (control, read) =
                                    fixture(grants[0].0.clone(), grants[0].1.clone());
                                {
                                    let mut state = lock(&read.state).unwrap();
                                    state.objects.clear();
                                    state.vault = Some(vault.clone());
                                    for (scope, reference) in grants {
                                        drop(vault.custody_read(scope, reference).unwrap());
                                        state.objects.push(Object {
                                            scope: scope.clone(),
                                            reference: reference.clone(),
                                            value: None,
                                        });
                                    }
                                }
                                for (scope, reference) in grants {
                                    let receiver = control.receiver(scope, reference).unwrap();
                                    let start = Instant::now();
                                    let mut lease = read
                                        .acquire(scope, reference, &Cancellation::new())
                                        .await
                                        .unwrap();
                                    lease
                                        .deliver_to(&receiver, &Cancellation::new())
                                        .await
                                        .unwrap();
                                    maximum = maximum.max(start.elapsed().as_secs_f64() * 1000.0);
                                    assert!(control.receiver_matches_object(&receiver));
                                    lease.close();
                                }
                                let mut wrong = grants[0].0.clone();
                                wrong.subject.push('x');
                                assert!(matches!(
                                    read.acquire(&wrong, &grants[0].1, &Cancellation::new())
                                        .await,
                                    Err(CustodyError::Denied)
                                ));
                                control.invalidate();
                                assert_eq!(control.live_handles(), 0);
                                assert!(lock(&read.state).unwrap().objects.is_empty());
                            }
                            maximum
                        })
                    })
                })
                .collect();
            jobs.into_iter()
                .map(|j| j.join().unwrap())
                .fold(0.0, f64::max)
        })
    }
    for owners in [1, 8] {
        let cold = Instant::now();
        let backings: Vec<Backing> = (0..owners)
            .map(|owner| {
                let dir = tempfile::tempdir().unwrap();
                let vault = Arc::new(crate::VaultManager::custody_benchmark_fixture(
                    &dir.path().join("synthetic.db"),
                ));
                let grants: Vec<_> = [Purpose::MailRecovery, Purpose::StorageRecovery]
                    .into_iter()
                    .enumerate()
                    .map(|(index, purpose)| {
                        let mut scope = scope();
                        scope.subject = format!("owner-{owner}");
                        scope.purpose = purpose;
                        let mut reference = reference();
                        reference.object_id = format!("object-{index}");
                        let mut value = Zeroizing::new([0; 32]);
                        rand::rngs::OsRng.fill_bytes(value.as_mut());
                        vault
                            .custody_put(&scope, None, &reference, &NativeSecret(value))
                            .unwrap();
                        (scope, reference)
                    })
                    .collect();
                (dir, vault, grants)
            })
            .collect();
        let cold_ms = cold.elapsed().as_secs_f64() * 1000.0;
        let baseline = rss_high_water();
        for _ in 0..3 {
            trial(&backings);
        }
        let samples: Vec<_> = (0..30).map(|_| trial(&backings)).collect();
        let peak = rss_high_water();
        let mut sorted = samples.clone();
        sorted.sort_by(f64::total_cmp);
        println!(
            "CUSTODY_RECEIPT {}",
            serde_json::json!({
                "owners": owners, "secretsPerOwner": 2, "cyclesPerOwner": 100, "denialsPerOwner": 100,
                "warmups": 3, "trials": 30, "trialMaxDispatchDeliveryMs": samples,
                "p95TrialMaximumMs": sorted[28], "coldProviderInitMs": cold_ms,
                "rssBaselineHighWaterBytes": baseline, "rssHighWaterBytes": peak,
                "rssIncrementBytes": peak.saturating_sub(baseline), "liveHandlesAfterClose": 0,
                "humanKdfOsTime": "excluded; test-only loaded DEK, never a production enrollment",
                "storage": "temporary SQLite files, SPENV, content receipts and audit writes"
            })
        );
        assert!(sorted[28] <= 100.0);
        assert!(peak.saturating_sub(baseline) <= 16 * 1024 * 1024);
    }
}

// A real vault DB mutex is held by another OS thread, not an async sleep. The
// release sender drops on panic, so a failing test cannot hang runtime teardown.
struct BlockedDb {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl BlockedDb {
    async fn new(vault: Arc<crate::VaultManager>) -> Self {
        let (release, wait) = std::sync::mpsc::channel();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let _lock = vault.custody_test_lock_db();
            let _ = entered.send(());
            let _ = wait.recv();
        });
        let result = Self {
            release: Some(release),
            thread: Some(thread),
        };
        ready.await.unwrap();
        result
    }
}
impl Drop for BlockedDb {
    fn drop(&mut self) {
        self.release.take();
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
async fn wait_for_permits(budget: &tokio::sync::Semaphore, count: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while budget.available_permits() != count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn blocked_storage_delivery_cancels_on_single_thread_executor() {
    let harness = Harness::new().await;
    harness.enroll().await;
    let (control, read) = harness.reader().await;
    let receiver = control.receiver(&scope(), &reference()).unwrap();
    let mut lease = read
        .acquire(&scope(), &reference(), &Cancellation::new())
        .await
        .unwrap();
    let vault = harness.daemon.manager().await.unwrap();
    // Exercise the actual cross-process receipt-file lock, not a simulated
    // delay. Dropping the File releases it even if an assertion panics.
    let blocked = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("{}.contents.lock", vault.vault_path().display()))
        .unwrap();
    blocked.lock().unwrap();
    let budget = read.state.lock().unwrap().workers.clone();
    let cancel = Cancellation::new();
    let delivery = lease.deliver_to(&receiver, &cancel);
    tokio::pin!(delivery);
    tokio::select! { result = &mut delivery => panic!("unexpected {result:?}"), _ = wait_for_permits(&budget, MAX_LIVE_LEASES - 1) => {} }
    cancel.cancel();
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(200), &mut delivery)
            .await
            .unwrap(),
        Err(CustodyError::Cancelled)
    );
    assert!(!control.receiver_has_secret(&receiver));
    assert_eq!(control.live_handles(), 0);
    drop(blocked);
    wait_for_permits(&budget, MAX_LIVE_LEASES).await;
    assert!(!control.receiver_has_secret(&receiver));
}

#[tokio::test]
async fn daemon_lock_does_not_wait_for_blocked_storage_grant() {
    let harness = Harness::new().await;
    harness.enroll().await;
    let approval = harness
        .approve(harness.password.as_bytes(), "grant", None)
        .await
        .unwrap();
    let retained = harness.daemon.manager().await.unwrap();
    let blocked = BlockedDb::new(retained.clone()).await;
    let budget = harness.admin.state.lock().unwrap().workers.clone();
    let (scope, reference, cancel) = (scope(), reference(), Cancellation::new());
    let grant = harness
        .admin
        .authorize_read(&scope, &reference, approval, &cancel);
    tokio::pin!(grant);
    tokio::select! { _ = &mut grant => panic!("unexpected grant"), _ = wait_for_permits(&budget, 0) => {} }
    tokio::time::timeout(Duration::from_millis(200), harness.daemon.lock())
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_millis(200), &mut grant)
            .await
            .unwrap(),
        Err(CustodyError::Invalidated)
    ));
    assert!(retained.is_unlocked());
    drop(blocked);
    wait_for_permits(&budget, 1).await;
    assert!(harness.admin.state.lock().unwrap().reads.is_empty());
}

#[tokio::test]
async fn cancelled_aborted_or_revoked_mutation_cannot_commit_after_storage_unblocks() {
    for mode in ["cancel", "abort", "lock"] {
        let harness = Harness::new().await;
        harness.enroll().await;
        let approval = harness
            .approve(harness.password.as_bytes(), "remove", None)
            .await
            .unwrap();
        let vault = harness.daemon.manager().await.unwrap();
        let blocked = BlockedDb::new(vault.clone()).await;
        let budget = harness.admin.state.lock().unwrap().workers.clone();
        let cancel = Cancellation::new();
        let (scope, reference) = (scope(), reference());
        {
            let remove = harness.admin.remove(&scope, &reference, approval, &cancel);
            tokio::pin!(remove);
            tokio::select! { result = &mut remove => panic!("unexpected {result:?}"), _ = wait_for_permits(&budget, 0) => {} }
            if mode != "abort" {
                let expected = if mode == "lock" {
                    tokio::time::timeout(Duration::from_millis(200), harness.daemon.lock())
                        .await
                        .unwrap();
                    CustodyError::Invalidated
                } else {
                    cancel.cancel();
                    CustodyError::Cancelled
                };
                assert_eq!(
                    tokio::time::timeout(Duration::from_millis(200), &mut remove)
                        .await
                        .unwrap(),
                    Err(expected)
                );
            }
        }
        assert_eq!(budget.available_permits(), 0);
        drop(blocked);
        wait_for_permits(&budget, 1).await;
        assert!(vault.custody_read(&scope, &reference).is_ok());
    }
}

#[tokio::test]
async fn durable_grants_retain_metadata_only_between_deliveries() {
    let harness = Harness::new().await;
    harness.enroll().await;
    let (control, read) = harness.reader().await;
    for _ in 0..2 {
        let metadata_only = {
            let state = read.state.lock().unwrap();
            state.objects.len() == 1 && state.objects.iter().all(|object| object.value.is_none())
        };
        assert!(
            metadata_only,
            "durable grants must not retain recovery plaintext"
        );
        let receiver = control.receiver(&scope(), &reference()).unwrap();
        let mut lease = read
            .acquire(&scope(), &reference(), &Cancellation::new())
            .await
            .unwrap();
        lease
            .deliver_to(&receiver, &Cancellation::new())
            .await
            .unwrap();
        assert!(control.receiver_matches_object(&receiver));
        lease.close();
        assert!(!control.receiver_has_secret(&receiver));
        assert_eq!(control.live_handles(), 0);
    }
}

#[tokio::test]
async fn restart_keeps_objects_but_rejects_old_native_authority() {
    let harness = Harness::new().await;
    harness.enroll().await;
    let (control, read, _lease, receiver) = setup_reader_with_lease(&harness).await;
    let old_remove = harness
        .approve(harness.password.as_bytes(), "remove", None)
        .await
        .unwrap();
    let old_source = harness.source();
    let old_put = harness
        .approve(harness.password.as_bytes(), "put", Some(&old_source))
        .await
        .unwrap();
    let Harness {
        _dir,
        password,
        daemon,
        admin,
    } = harness;
    let path = daemon.vault_path().to_owned();
    drop(daemon);
    assert!(!control.receiver_has_secret(&receiver));
    assert!(matches!(
        read.acquire(&scope(), &reference(), &Cancellation::new())
            .await,
        Err(CustodyError::Invalidated)
    ));
    assert!(admin.state.lock().unwrap().sources.is_empty());
    let vault = crate::VaultManager::open(&path, password.as_bytes()).unwrap();
    let daemon = DaemonVault::new(Some(path), 600).unwrap();
    daemon.unlock_with_manager(vault).await;
    let new_admin = Harness::attach(&daemon).await;
    assert_eq!(
        new_admin
            .remove(&scope(), &reference(), old_remove, &Cancellation::new())
            .await,
        Err(CustodyError::Denied)
    );
    assert_eq!(
        new_admin
            .put(&scope(), None, old_source, old_put, &Cancellation::new())
            .await,
        Err(CustodyError::Denied)
    );
    let restarted = Harness {
        _dir,
        password,
        daemon,
        admin: new_admin,
    };
    let (new_control, new_read) = restarted.reader().await;
    let new_receiver = new_control.receiver(&scope(), &reference()).unwrap();
    let mut new_lease = new_read
        .acquire(&scope(), &reference(), &Cancellation::new())
        .await
        .unwrap();
    new_lease
        .deliver_to(&new_receiver, &Cancellation::new())
        .await
        .unwrap();
    assert!(new_control.receiver_matches_object(&new_receiver));
    assert!(!control.receiver_has_secret(&receiver));
}

#[tokio::test]
async fn native_audit_records_outcomes_without_recovery_or_authority_canaries() {
    use base64::Engine;
    let harness = Harness::new().await;
    let canary = Zeroizing::new(uuid::Uuid::new_v4().simple().to_string());
    let source = harness.source();
    let mut value = Zeroizing::new([0; 32]);
    value.copy_from_slice(canary.as_bytes());
    harness
        .admin
        .state
        .lock()
        .unwrap()
        .sources
        .get_mut(&source.id)
        .unwrap()
        .value = NativeSecret(value);
    let approval = harness
        .approve(harness.password.as_bytes(), "put", Some(&source))
        .await
        .unwrap();
    let approval_canary = Zeroizing::new(approval.id.clone());
    let replay = PersonalApproval {
        state: approval.state.clone(),
        id: approval.id.clone(),
    };
    harness
        .admin
        .put(&scope(), None, source, approval, &Cancellation::new())
        .await
        .unwrap();
    assert_eq!(
        harness
            .admin
            .remove(&scope(), &reference(), replay, &Cancellation::new())
            .await,
        Err(CustodyError::Denied)
    );
    let (control, _read, _lease, receiver) = setup_reader_with_lease(&harness).await;
    assert!(control.receiver_matches_object(&receiver));
    let approval = harness
        .approve(harness.password.as_bytes(), "remove", None)
        .await
        .unwrap();
    harness
        .admin
        .remove(&scope(), &reference(), approval, &Cancellation::new())
        .await
        .unwrap();
    let path = harness._dir.path().join("audit/audit.log");
    let audit = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let output = std::fs::read_to_string(&path).unwrap();
            let outcomes: Vec<_> = output
                .lines()
                // An asynchronous append may be partway through its last
                // record. Poll again rather than treating that as a failure.
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .map(|entry| entry["event_type"]["PersonalCustody"].clone())
                .collect();
            if [
                ("Put", true),
                ("Remove", false),
                ("Grant", true),
                ("Deliver", true),
                ("Remove", true),
            ]
            .iter()
            .all(|(op, success)| {
                outcomes
                    .iter()
                    .any(|entry| entry["operation"] == *op && entry["success"] == *success)
            }) {
                break output;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("native audit outcomes did not arrive");
    for forbidden in [
        canary.as_str(),
        approval_canary.as_str(),
        harness.password.as_str(),
        scope().subject.as_str(),
        reference().object_id.as_str(),
    ] {
        assert!(
            !audit.contains(forbidden),
            "audit leaked a synthetic canary"
        );
    }
    let encoded = [
        Zeroizing::new(hex::encode(canary.as_bytes())),
        Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(canary.as_bytes())),
    ];
    for forbidden in &encoded {
        assert!(
            !audit.contains(forbidden.as_str()),
            "audit leaked an encoded canary"
        );
    }
    // Metadata is intentionally visible in SQLite; only recovery bytes are
    // forbidden there. Scan all temporary vault/receipt/audit artifacts.
    let mut pending = vec![harness._dir.path().to_owned()];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(
                std::fs::read_dir(path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path()),
            );
        } else {
            let bytes = std::fs::read(path).unwrap();
            assert!(
                !bytes
                    .windows(canary.len())
                    .any(|window| window == canary.as_bytes()),
                "persisted artifact leaked recovery plaintext"
            );
        }
    }
}
