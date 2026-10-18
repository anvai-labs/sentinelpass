use super::*;
use sentinelpass_protocol::custody::Purpose;

#[tokio::test]
async fn dropping_authority_invalidates_retained_read_and_runtime_handles() {
    let (control, provider) = fixture(scope(), reference());
    let cancel = Cancellation::new();
    let mut lease = provider
        .acquire(&scope(), &reference(), &cancel)
        .await
        .unwrap();
    let receiver = control.receiver(&scope(), &reference()).unwrap();
    drop(control);
    assert!(matches!(
        provider.acquire(&scope(), &reference(), &cancel).await,
        Err(CustodyError::Invalidated)
    ));
    assert_eq!(
        lease.deliver_to(&receiver, &cancel).await,
        Err(CustodyError::Invalidated)
    );
    assert!(lock(&provider.state).unwrap().objects.is_empty());
}

#[tokio::test(start_paused = true)]
async fn idle_expiry_wipes_receiver_without_a_followup_request() {
    let (control, provider) = fixture(scope(), reference());
    let cancel = Cancellation::new();
    let mut lease = provider
        .acquire(&scope(), &reference(), &cancel)
        .await
        .unwrap();
    let receiver = control.receiver(&scope(), &reference()).unwrap();
    lease.deliver_to(&receiver, &cancel).await.unwrap();
    tokio::time::advance(Duration::from_secs(121)).await;
    tokio::task::yield_now().await;
    // Inspect directly: this check cannot perform opportunistic cleanup.
    let state = lock(&control.state).unwrap();
    assert!(state.leases.is_empty());
    assert!(state.receivers.is_empty());
}

#[tokio::test]
async fn aborting_future_or_replaying_inflight_handle_burns_authority() {
    for replay in [false, true] {
        let (control, provider) = fixture(scope(), reference());
        let cancel = Cancellation::new();
        let mut lease = provider
            .acquire(&scope(), &reference(), &cancel)
            .await
            .unwrap();
        let mut duplicate = CustodyLease {
            state: lease.state.clone(),
            id: lease.id,
            expires: lease.expires,
        };
        let receiver = control.receiver(&scope(), &reference()).unwrap();
        let gate = control.pause_delivery();
        let mut pending = Box::pin(lease.deliver_to(&receiver, &cancel));
        tokio::select! {
            result = &mut pending => panic!("unexpected completion: {result:?}"),
            _ = gate.started.notified() => {}
        }
        if replay {
            assert_eq!(
                duplicate.deliver_to(&receiver, &cancel).await,
                Err(CustodyError::Invalidated)
            );
            gate.release.notify_one();
            assert_eq!(pending.await, Err(CustodyError::Invalidated));
        } else {
            drop(pending);
        }
        assert!(!control.receiver_has_secret(&receiver));
        assert_eq!(control.live_handles(), 0);
    }
}

#[tokio::test]
async fn delivered_custody_expires_and_unregistered_receivers_are_bounded() {
    let (control, provider) = fixture(scope(), reference());
    let cancel = Cancellation::new();
    let mut receivers = Vec::new();
    for _ in 0..8 {
        receivers.push(control.receiver(&scope(), &reference()).unwrap());
    }
    assert!(matches!(
        control.receiver(&scope(), &reference()),
        Err(CustodyError::Capacity)
    ));
    drop(receivers.pop());
    let receiver = control.receiver(&scope(), &reference()).unwrap();
    let mut lease = provider
        .acquire(&scope(), &reference(), &cancel)
        .await
        .unwrap();
    lease.deliver_to(&receiver, &cancel).await.unwrap();
    assert!(control.receiver_matches_object(&receiver));
    control.advance(Duration::from_secs(120));
    assert!(!control.receiver_has_secret(&receiver));
    drop(receivers);
    assert_eq!(control.live_handles(), 0);
}

#[tokio::test]
async fn authority_is_checked_again_when_reference_changes_during_delivery() {
    let (control, provider) = fixture(scope(), reference());
    let cancel = Cancellation::new();
    let mut lease = provider
        .acquire(&scope(), &reference(), &cancel)
        .await
        .unwrap();
    let receiver = control.receiver(&scope(), &reference()).unwrap();
    let gate = control.pause_delivery();
    let mut pending = Box::pin(lease.deliver_to(&receiver, &cancel));
    tokio::select! {
        result = &mut pending => panic!("unexpected completion: {result:?}"),
        _ = gate.started.notified() => {}
    }
    lock(&control.state).unwrap().objects[0].reference.revision = "2".into();
    gate.release.notify_one();
    assert_eq!(pending.await, Err(CustodyError::StaleReference));
    assert!(!control.receiver_has_secret(&receiver));
    assert_eq!(control.live_handles(), 0);
}

proptest::proptest! {
    #[test]
    fn arbitrary_metadata_never_panics_or_bypasses_validation(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..8192)) {
        if let Ok(scope) = CustodyScope::decode(&bytes) { assert!(scope.validate().is_ok()); }
        if let Ok(reference) = ObjectRef::decode(&bytes) { assert!(reference.validate().is_ok()); }
        if let Ok(info) = ProviderCapabilities::decode(&bytes) { assert!(info.validate().is_ok()); }
    }
}

#[cfg(unix)]
pub(super) fn rss_high_water() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // getrusage initializes the complete output on success.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let rss = unsafe { usage.assume_init() }.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        rss
    } else {
        rss * 1024
    }
}

#[cfg(unix)]
#[test]
#[ignore = "manual synthetic timing receipt; run alone with --ignored --nocapture"]
fn qualification() {
    fn trial(owners: usize) -> f64 {
        let barrier = Arc::new(std::sync::Barrier::new(owners));
        std::thread::scope(|threads| {
            let jobs: Vec<_> = (0..owners)
                .map(|owner| {
                    let barrier = barrier.clone();
                    threads.spawn(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_time()
                            .build()
                            .unwrap();
                        rt.block_on(async {
                            let mut mail = scope();
                            mail.subject = format!("synthetic-{owner}");
                            let mut storage = mail.clone();
                            storage.purpose = Purpose::StorageRecovery;
                            let (control, provider) = fixture(mail.clone(), reference());
                            let mut second = Zeroizing::new([0; SECRET_BYTES]);
                            rand::rngs::OsRng.fill_bytes(second.as_mut());
                            lock(&control.state).unwrap().objects.push(Object {
                                scope: storage.clone(),
                                reference: reference(),
                                value: Some(NativeSecret(second)),
                            });
                            let cancel = Cancellation::new();
                            control.synthetic_lock();
                            barrier.wait();
                            let mut maximum_ms: f64 = 0.0;
                            for _ in 0..100 {
                                control.synthetic_unlock();
                                for purpose in [&mail, &storage] {
                                    let receiver = control.receiver(purpose, &reference()).unwrap();
                                    let start = Instant::now();
                                    let mut lease = provider
                                        .acquire(purpose, &reference(), &cancel)
                                        .await
                                        .unwrap();
                                    lease.deliver_to(&receiver, &cancel).await.unwrap();
                                    maximum_ms =
                                        maximum_ms.max(start.elapsed().as_secs_f64() * 1000.0);
                                    assert!(control.receiver_has_secret(&receiver));
                                    lease.close();
                                    assert!(!control.receiver_has_secret(&receiver));
                                }
                                assert_eq!(control.live_handles(), 0);
                                control.synthetic_lock();
                            }
                            control.synthetic_unlock();
                            for _ in 0..100 {
                                let mut wrong = mail.clone();
                                wrong.subject.push('x');
                                assert!(matches!(
                                    provider.acquire(&wrong, &reference(), &cancel).await,
                                    Err(CustodyError::Denied)
                                ));
                            }
                            control.invalidate();
                            assert_eq!(control.live_handles(), 0);
                            maximum_ms
                        })
                    })
                })
                .collect();
            jobs.into_iter()
                .map(|job| job.join().unwrap())
                .fold(0.0, f64::max)
        })
    }
    let cold = Instant::now();
    let (control, _provider) = fixture(scope(), reference());
    control.invalidate();
    let cold_ms = cold.elapsed().as_secs_f64() * 1000.0;
    for owners in [1, 8] {
        let baseline = rss_high_water();
        for _ in 0..3 {
            trial(owners);
        }
        let samples: Vec<_> = (0..30).map(|_| trial(owners)).collect();
        let peak = rss_high_water();
        let mut sorted = samples.clone();
        sorted.sort_by(f64::total_cmp);
        let p95 = sorted[28];
        println!(
            "CUSTODY_RECEIPT {}",
            serde_json::json!({
                "owners": owners, "secretsPerOwner": 2, "cyclesPerOwner": 100,
                "denialsPerOwner": 100, "warmups": 3, "trials": 30,
                "trialMaxDispatchDeliveryMs": samples, "p95TrialMaximumMs": p95,
                "coldProviderInitMs": cold_ms, "rssBaselineHighWaterBytes": baseline,
                "rssHighWaterBytes": peak, "rssIncrementBytes": peak.saturating_sub(baseline),
                "liveHandlesAfterClose": 0, "humanKdfOsTime": "not measured; synthetic only"
            })
        );
        assert!(p95 <= 100.0);
        assert!(peak.saturating_sub(baseline) <= 16 * 1024 * 1024);
    }
}

fn scope() -> CustodyScope {
    CustodyScope {
        version: 1,
        namespace: "sandesha".into(),
        issuer: "https://issuer.example".into(),
        subject: "synthetic-owner".into(),
        mailbox_id: "synthetic-mailbox".into(),
        purpose: Purpose::MailRecovery,
    }
}
fn reference() -> ObjectRef {
    ObjectRef {
        object_id: "synthetic-object".into(),
        revision: "1".into(),
        key_epoch: "1".into(),
        binding_sha256: "a".repeat(64),
    }
}

#[tokio::test]
async fn delivery_is_exact_single_use_and_close_disposes_runtime_custody() {
    let (control, provider) = fixture(scope(), reference());
    let cancel = Cancellation::new();
    let mut lease = provider
        .acquire(&scope(), &reference(), &cancel)
        .await
        .unwrap();
    let receiver = control.receiver(&scope(), &reference()).unwrap();
    lease.deliver_to(&receiver, &cancel).await.unwrap();
    assert!(control.receiver_has_secret(&receiver));
    assert_eq!(
        lease.deliver_to(&receiver, &cancel).await,
        Err(CustodyError::Invalidated)
    );
    lease.close();
    assert!(!control.receiver_has_secret(&receiver));
    assert_eq!(control.live_handles(), 0);
}

#[tokio::test]
async fn reads_require_exact_preapproved_owner_purpose_reference_and_epoch() {
    let (_control, provider) = fixture(scope(), reference());
    let cancel = Cancellation::new();
    for field in 0..5 {
        let mut wrong = scope();
        match field {
            0 => wrong.namespace.push('x'),
            1 => wrong.issuer.push('x'),
            2 => wrong.subject.push('x'),
            3 => wrong.mailbox_id.push('x'),
            _ => wrong.purpose = Purpose::StorageRecovery,
        }
        assert!(matches!(
            provider.acquire(&wrong, &reference(), &cancel).await,
            Err(CustodyError::Denied)
        ));
    }
    for field in 0..4 {
        let mut wrong = reference();
        match field {
            0 => wrong.object_id.push('x'),
            1 => wrong.revision = "2".into(),
            2 => wrong.key_epoch = "2".into(),
            _ => wrong.binding_sha256 = "b".repeat(64),
        }
        assert!(provider.acquire(&scope(), &wrong, &cancel).await.is_err());
    }
}

#[tokio::test]
async fn cross_peer_receiver_is_denied_and_burns_the_lease() {
    let (control, provider) = fixture(scope(), reference());
    let (other, _) = fixture(scope(), reference());
    let cancel = Cancellation::new();
    let mut lease = provider
        .acquire(&scope(), &reference(), &cancel)
        .await
        .unwrap();
    let foreign = other.receiver(&scope(), &reference()).unwrap();
    assert_eq!(
        lease.deliver_to(&foreign, &cancel).await,
        Err(CustodyError::Denied)
    );
    assert_eq!(control.live_handles(), 0);
    assert!(!other.receiver_has_secret(&foreign));
}

#[tokio::test]
async fn forged_receiver_is_denied_with_a_live_lease() {
    let (control, provider) = fixture(scope(), reference());
    let cancel = Cancellation::new();
    let mut lease = provider
        .acquire(&scope(), &reference(), &cancel)
        .await
        .unwrap();
    let receiver = control.receiver(&scope(), &reference()).unwrap();
    let forged = RuntimeReceiver {
        state: receiver.state.clone(),
        id: [0; 32],
    };
    {
        let state = lock(&control.state).unwrap();
        assert!(state.leases.contains_key(&lease.id));
        assert!(!state.receivers.contains_key(&forged.id));
    }
    assert_eq!(
        lease.deliver_to(&forged, &cancel).await,
        Err(CustodyError::Invalidated)
    );
    assert!(!control.receiver_has_secret(&receiver));
    assert!(!lock(&control.state).unwrap().leases.contains_key(&lease.id));
}

#[tokio::test]
async fn session_invalidation_rejects_previously_live_lease_and_receiver() {
    let (control, provider) = fixture(scope(), reference());
    let cancel = Cancellation::new();
    let mut lease = provider
        .acquire(&scope(), &reference(), &cancel)
        .await
        .unwrap();
    let receiver = control.receiver(&scope(), &reference()).unwrap();
    assert_eq!(control.live_handles(), 2);
    control.invalidate();
    assert_eq!(control.live_handles(), 0);
    assert!(!control.receiver_has_secret(&receiver));
    assert_eq!(
        lease.deliver_to(&receiver, &cancel).await,
        Err(CustodyError::Invalidated)
    );
}

#[tokio::test]
async fn lease_capacity_drop_expiry_and_cancel_are_bounded() {
    let (control, provider) = fixture(scope(), reference());
    let cancel = Cancellation::new();
    let mut leases = Vec::new();
    for _ in 0..8 {
        leases.push(
            provider
                .acquire(&scope(), &reference(), &cancel)
                .await
                .unwrap(),
        );
    }
    assert!(matches!(
        provider.acquire(&scope(), &reference(), &cancel).await,
        Err(CustodyError::Capacity)
    ));
    drop(leases.pop());
    assert!(provider
        .acquire(&scope(), &reference(), &cancel)
        .await
        .is_ok());
    control.advance(Duration::from_secs(120));
    let receiver = control.receiver(&scope(), &reference()).unwrap();
    assert_eq!(
        leases[0].deliver_to(&receiver, &cancel).await,
        Err(CustodyError::Expired)
    );
    drop(leases);
    drop(receiver);
    assert_eq!(control.live_handles(), 0);
    cancel.cancel();
    assert!(matches!(
        provider.acquire(&scope(), &reference(), &cancel).await,
        Err(CustodyError::Cancelled)
    ));
}

#[tokio::test]
async fn invalidation_cancellation_and_delivery_timeout_dispose_late_output() {
    for event in 0..3 {
        let (control, provider) = fixture(scope(), reference());
        let cancel = Cancellation::new();
        let mut lease = provider
            .acquire(&scope(), &reference(), &cancel)
            .await
            .unwrap();
        let receiver = control.receiver(&scope(), &reference()).unwrap();
        let gate = control.pause_delivery();
        let delivery = lease.deliver_to(&receiver, &cancel);
        tokio::pin!(delivery);
        tokio::select! {
            result = &mut delivery => panic!("delivery completed before release: {result:?}"),
            _ = gate.started.notified() => {}
        }
        match event {
            0 => control.invalidate(),
            1 => cancel.cancel(),
            _ => control.advance(Duration::from_secs(5)),
        }
        gate.release.notify_one();
        assert!(delivery.await.is_err());
        assert!(!control.receiver_has_secret(&receiver));
    }
}
