//! Personal custody native ports and lifecycle (KC-01/02).
//!
//! No production enrollment constructor is exposed. Dedicated vault storage and
//! native administration are exercised by a synthetic trusted-UI harness. Metadata,
//! a vault unlock or OIDC login can never mint these capabilities.
//!
//! Native secrets deliberately cannot be formatted, cloned or serialized:
//! ```compile_fail
//! use sentinelpass_core::custody::NativeSecret;
//! fn leak(s: &NativeSecret) { println!("{s:?}"); }
//! ```
//! ```compile_fail
//! use sentinelpass_core::custody::NativeSecret;
//! fn copy(s: NativeSecret) { let _ = s.clone(); }
//! ```
//! ```compile_fail
//! use sentinelpass_core::custody::NativeSecret;
//! fn wire(s: &NativeSecret) { let _ = serde_json::to_string(s); }
//! ```

use rand::RngCore;
pub use sentinelpass_protocol::custody::{
    CustodyError, CustodyScope, ObjectRef, ProviderCapabilities, FEATURE_CUSTODY_V1,
    MAX_METADATA_BYTES,
};
use sentinelpass_protocol::custody::{
    Result, DELIVERY_SECONDS, LEASE_SECONDS, MAX_LIVE_LEASES, SECRET_BYTES,
};
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

mod personal;
mod workers;
pub(crate) use personal::CustodyLifecycle;
pub use personal::{NativeSource, PersonalApproval, PersonalCustodyAdmin};

/// Owned only by approved native runtime contexts. No raw-byte public accessor.
pub struct NativeSecret(pub(crate) Zeroizing<[u8; SECRET_BYTES]>);

/// Cancellation is revocation only; constructing one never grants authority.
#[derive(Clone, Default)]
pub struct Cancellation(Arc<CancelState>);
#[derive(Default)]
struct CancelState {
    cancelled: AtomicBool,
    changed: tokio::sync::Notify,
}
impl Cancellation {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
    fn check(&self) -> Result<()> {
        if self.0.cancelled.load(Ordering::Acquire) {
            Err(CustodyError::Cancelled)
        } else {
            Ok(())
        }
    }
    async fn cancelled(&self) {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.check().is_err() {
                return;
            }
            changed.await;
        }
    }
}

/// Provider-neutral read port; no enumeration or administrative methods.
pub trait CustodyProvider {
    type Lease: CustodyLeasePort;
    fn describe(&self) -> ProviderCapabilities;
    fn acquire(
        &self,
        scope: &CustodyScope,
        reference: &ObjectRef,
        cancel: &Cancellation,
    ) -> impl Future<Output = Result<Self::Lease>> + Send;
}
pub trait CustodyLeasePort {
    type Receiver;
    fn deliver_to(
        &mut self,
        receiver: &Self::Receiver,
        cancel: &Cancellation,
    ) -> impl Future<Output = Result<()>> + Send;
    fn close(&mut self);
}
/// Separate privilege port. Sources bind the complete proposed reference and
/// secret in a registered native runtime; approval binds that registration too.
/// Approval/source minting remains private until the trusted UI is qualified.
pub trait CustodyAdmin {
    type Source;
    type Approval;
    fn put(
        &self,
        scope: &CustodyScope,
        expected: Option<&ObjectRef>,
        source: Self::Source,
        approval: Self::Approval,
        cancel: &Cancellation,
    ) -> impl Future<Output = Result<ObjectRef>> + Send;
    fn remove(
        &self,
        scope: &CustodyScope,
        expected: &ObjectRef,
        approval: Self::Approval,
        cancel: &Cancellation,
    ) -> impl Future<Output = Result<()>> + Send;
}

type Id = [u8; 32];
type Shared = Arc<Mutex<State>>;
fn random_id() -> Result<Id> {
    let mut id = [0; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut id)
        .map_err(|_| CustodyError::Unavailable)?;
    Ok(id)
}
fn lock(state: &Shared) -> Result<MutexGuard<'_, State>> {
    state.lock().map_err(|_| CustodyError::Invalidated)
}

struct Object {
    scope: CustodyScope,
    reference: ObjectRef,
    // Durable grants are metadata only. In-memory backing exists exclusively
    // in the KC-01 synthetic adapter, which is not compiled into products.
    #[cfg(test)]
    value: Option<NativeSecret>,
}
struct LeaseEntry {
    scope: CustodyScope,
    reference: ObjectRef,
    expires: Instant,
    started: bool,
    expiry_task: tokio::task::AbortHandle,
    lifetime: Cancellation,
}
impl Drop for LeaseEntry {
    fn drop(&mut self) {
        self.lifetime.cancel();
        self.expiry_task.abort();
    }
}
struct ReceiverEntry {
    scope: CustodyScope,
    reference: ObjectRef,
    lease: Option<Id>,
    value: Option<NativeSecret>,
}
struct State {
    active: bool,
    lifetime: Cancellation,
    workers: Arc<tokio::sync::Semaphore>,
    // Revalidate durable reference/receipt on both sides of delivery. This is
    // not authority by itself; the registered session and exact grant are too.
    vault: Option<Arc<crate::VaultManager>>,
    // Only exact objects enrolled by a trusted authority belong here. KC-01
    // populates synthetic test fixtures only; never a caller-controlled grant.
    objects: Vec<Object>,
    leases: HashMap<Id, LeaseEntry>,
    receivers: HashMap<Id, ReceiverEntry>,
    #[cfg(test)]
    offset: Duration,
    #[cfg(test)]
    gate: Option<Arc<DeliveryGate>>,
}
impl State {
    fn now(&self) -> Instant {
        #[cfg(test)]
        {
            Instant::now() + self.offset
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }
    fn authorize(&self, scope: &CustodyScope, reference: &ObjectRef) -> Result<&Object> {
        scope.validate()?;
        reference.validate()?;
        if !self.active {
            return Err(CustodyError::Invalidated);
        }
        let object = self
            .objects
            .iter()
            .find(|o| &o.scope == scope && o.reference.object_id == reference.object_id)
            .ok_or(CustodyError::Denied)?;
        if &object.reference != reference {
            return Err(CustodyError::StaleReference);
        }
        Ok(object)
    }
    fn invalidate(&mut self) {
        self.lifetime.cancel();
        self.active = false;
        self.leases.clear();
        self.receivers.clear();
        self.objects.clear();
        self.vault = None;
    }
    fn close(&mut self, id: Id) {
        self.leases.remove(&id);
        // Drop zeroizes any delivered secret; no callback can retain a copy.
        self.receivers
            .retain(|_, receiver| receiver.lease != Some(id));
    }
    fn reap(&mut self) {
        let now = self.now();
        self.leases.retain(|_, lease| lease.expires > now);
        self.receivers.retain(|_, receiver| {
            receiver
                .lease
                .is_none_or(|id| self.leases.contains_key(&id))
        });
    }
}

/// Native read-only handle, created only by an approved enrollment adapter.
pub struct NativeReadSession {
    state: Shared,
}
/// Registry-bound native receiver. Not a raw pointer, callback, or JSON brand.
pub struct RuntimeReceiver {
    state: Shared,
    id: Id,
}
impl Drop for RuntimeReceiver {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.receivers.remove(&self.id);
        }
    }
}
/// The registry enforces one-shot delivery even if an internal handle is copied.
pub struct CustodyLease {
    state: Shared,
    id: Id,
    expires: Instant,
}
impl Drop for CustodyLease {
    fn drop(&mut self) {
        self.close();
    }
}

// Dropping a pending future must burn its lease and wipe staged/delivered output.
struct DeliveryGuard {
    state: Shared,
    id: Id,
    armed: bool,
}
impl Drop for DeliveryGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut state) = self.state.lock() {
                state.close(self.id);
            }
        }
    }
}

impl CustodyProvider for NativeReadSession {
    type Lease = CustodyLease;
    fn describe(&self) -> ProviderCapabilities {
        // This engine is not a qualified production adapter.
        ProviderCapabilities::unavailable()
    }
    async fn acquire(
        &self,
        scope: &CustodyScope,
        reference: &ObjectRef,
        cancel: &Cancellation,
    ) -> Result<CustodyLease> {
        let started = Instant::now();
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| CustodyError::Unavailable)?;
        cancel.check()?;
        // Give aborted expiry tasks a cleanup turn before allocating another
        // lease, even when a caller loops over immediately-ready native reads.
        tokio::task::yield_now().await;
        cancel.check()?;
        let (vault, lifetime, budget) = {
            let state = lock(&self.state)?;
            state.authorize(scope, reference)?;
            (
                state.vault.clone(),
                state.lifetime.clone(),
                state.workers.clone(),
            )
        };
        if let Some(vault) = vault {
            let scope = scope.clone();
            let reference = reference.clone();
            workers::run(
                budget,
                lifetime,
                cancel,
                started + Duration::from_secs(LEASE_SECONDS),
                move |work| {
                    drop(vault.custody_read_checked(&scope, &reference, || work.check())?);
                    Ok(())
                },
            )
            .await?;
        }
        let mut state = lock(&self.state)?;
        state.authorize(scope, reference)?;
        state.reap();
        if state.leases.len() >= MAX_LIVE_LEASES {
            return Err(CustodyError::Capacity);
        }
        // The acquisition budget includes any blocking-pool admission and I/O.
        if started.elapsed() >= Duration::from_secs(LEASE_SECONDS) {
            return Err(CustodyError::Expired);
        }
        cancel.check()?;
        let id = random_id()?;
        if state.leases.contains_key(&id) {
            return Err(CustodyError::Unavailable);
        }
        let expires = state.now() + Duration::from_secs(LEASE_SECONDS);
        // At most one timer per live lease. Closing/dropping/revoking a lease
        // aborts it; a sequential caller cannot accumulate detached timers.
        // The task owns only a Weak reference and cannot prolong session life.
        let weak = Arc::downgrade(&self.state);
        let expiry_task = runtime
            .spawn(async move {
                tokio::time::sleep_until(tokio::time::Instant::from_std(expires)).await;
                if let Some(state) = weak.upgrade() {
                    if let Ok(mut state) = state.lock() {
                        state.close(id);
                    }
                }
            })
            .abort_handle();
        state.leases.insert(
            id,
            LeaseEntry {
                scope: scope.clone(),
                reference: reference.clone(),
                expires,
                started: false,
                expiry_task,
                lifetime: Cancellation::new(),
            },
        );
        Ok(CustodyLease {
            state: self.state.clone(),
            id,
            expires,
        })
    }
}
impl CustodyLeasePort for CustodyLease {
    type Receiver = RuntimeReceiver;
    async fn deliver_to(
        &mut self,
        receiver: &RuntimeReceiver,
        cancel: &Cancellation,
    ) -> Result<()> {
        let mut guard = DeliveryGuard {
            state: self.state.clone(),
            id: self.id,
            armed: true,
        };
        cancel.check()?;
        if !Arc::ptr_eq(&self.state, &receiver.state) {
            return Err(CustodyError::Denied);
        }
        let (scope, reference, mut value, deadline, vault, lifetime, budget) = {
            let mut state = lock(&self.state)?;
            if state.now() >= self.expires {
                return Err(CustodyError::Expired);
            }
            let lease = state
                .leases
                .get(&self.id)
                .ok_or(CustodyError::Invalidated)?;
            if lease.started {
                return Err(CustodyError::Invalidated);
            }
            let scope = lease.scope.clone();
            let reference = lease.reference.clone();
            let lifetime = lease.lifetime.clone();
            let destination = state
                .receivers
                .get(&receiver.id)
                .ok_or(CustodyError::Invalidated)?;
            if destination.scope != scope
                || destination.reference != reference
                || destination.lease.is_some()
            {
                return Err(CustodyError::Denied);
            }
            state.authorize(&scope, &reference)?;
            let value: Option<NativeSecret> = None;
            #[cfg(test)]
            let value = if state.vault.is_none() {
                state
                    .authorize(&scope, &reference)?
                    .value
                    .as_ref()
                    .map(|value| NativeSecret(Zeroizing::new(*value.0)))
            } else {
                value
            };
            let deadline = self
                .expires
                .min(state.now() + Duration::from_secs(DELIVERY_SECONDS));
            state
                .leases
                .get_mut(&self.id)
                .ok_or(CustodyError::Invalidated)?
                .started = true;
            state
                .receivers
                .get_mut(&receiver.id)
                .ok_or(CustodyError::Invalidated)?
                .lease = Some(self.id);
            (
                scope,
                reference,
                value,
                deadline,
                state.vault.clone(),
                lifetime,
                state.workers.clone(),
            )
        };
        if let Some(vault) = vault.clone() {
            let scope = scope.clone();
            let reference = reference.clone();
            workers::run(
                budget.clone(),
                lifetime.clone(),
                cancel,
                deadline,
                move |work| {
                    drop(vault.custody_read_checked(&scope, &reference, || work.check())?);
                    Ok(())
                },
            )
            .await?;
        }
        // Synthetic asynchronous boundary for conformance race ordering. There
        // is deliberately no pluggable callback accepting plaintext.
        #[cfg(test)]
        {
            let gate = { lock(&self.state)?.gate.clone() };
            if let Some(gate) = gate {
                gate.started.notify_one();
                tokio::time::timeout(
                    Duration::from_secs(DELIVERY_SECONDS),
                    gate.release.notified(),
                )
                .await
                .map_err(|_| CustodyError::Expired)?;
            }
        }
        if let Some(vault) = vault.clone() {
            let scope = scope.clone();
            let reference = reference.clone();
            value = Some(
                workers::run(budget, lifetime, cancel, deadline, move |work| {
                    vault.custody_read_checked(&scope, &reference, || work.check())
                })
                .await?,
            );
        }
        let mut state = lock(&self.state)?;
        cancel.check()?;
        if state.now() >= deadline {
            return Err(CustodyError::Expired);
        }
        state.authorize(&scope, &reference)?;
        if !state.leases.contains_key(&self.id) {
            return Err(CustodyError::Invalidated);
        }
        let destination = state
            .receivers
            .get_mut(&receiver.id)
            .ok_or(CustodyError::Invalidated)?;
        if destination.lease != Some(self.id) {
            return Err(CustodyError::Invalidated);
        }
        destination.value = Some(value.ok_or(CustodyError::Unavailable)?);
        guard.armed = false;
        drop(state);
        if let Some(vault) = vault {
            workers::audit(vault, crate::audit::CustodyAuditOperation::Deliver, true);
        }
        Ok(())
    }
    fn close(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.close(self.id);
        }
    }
}

#[cfg(test)]
mod synthetic;
#[cfg(test)]
mod tests;
#[cfg(test)]
use synthetic::{fixture, DeliveryGate};
