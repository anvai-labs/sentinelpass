//! KC-02 native authority. Constructors are test-only until trusted enrollment
//! and native transport review. In particular, an Arc<VaultManager>, an OIDC
//! token or a service grant cannot construct a PersonalCustodyAdmin.
use super::*;
use crate::daemon::ipc::stepup::StepUpState;
use std::sync::Weak;

type Authority = Arc<Mutex<PersonalState>>;

pub struct PersonalCustodyAdmin {
    state: Authority,
    connection: u128,
}
/// Opaque source registration. Bytes stay in the native authority registry.
pub struct NativeSource {
    state: Weak<Mutex<PersonalState>>,
    id: Id,
}
impl Drop for NativeSource {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            if let Ok(mut state) = state.lock() {
                state.sources.remove(&self.id);
            }
        }
    }
}
pub struct PersonalApproval {
    state: Weak<Mutex<PersonalState>>,
    id: String,
}
impl Drop for PersonalApproval {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .approvals
                .discard(&self.id);
        }
    }
}
struct SourceEntry {
    scope: CustodyScope,
    reference: ObjectRef,
    value: NativeSecret,
    expires: Instant,
}
struct PersonalState {
    vault: Option<Arc<crate::VaultManager>>,
    owner: CustodyScope,
    approvals: StepUpState,
    sources: HashMap<Id, SourceEntry>,
    reads: Vec<Weak<Mutex<State>>>,
    lifetime: Cancellation,
    workers: Arc<tokio::sync::Semaphore>,
    read_workers: Arc<tokio::sync::Semaphore>,
    generation: u64,
}
impl PersonalState {
    fn check_owner(&self, scope: &CustodyScope) -> Result<()> {
        let mut owner = self.owner.clone();
        owner.purpose = scope.purpose;
        if &owner != scope {
            return Err(CustodyError::Denied);
        }
        Ok(())
    }
    fn invalidate_reads(&mut self) {
        self.generation = self.generation.saturating_add(1);
        if self.generation == u64::MAX {
            self.lifetime.cancel();
        }
        for read in self.reads.drain(..).filter_map(|r| r.upgrade()) {
            // A poisoned state is still wiped. Never revive authority.
            read.lock().unwrap_or_else(|e| e.into_inner()).invalidate();
        }
    }
    fn invalidate(&mut self) {
        self.lifetime.cancel();
        self.invalidate_reads();
        self.sources.clear();
        self.approvals = StepUpState::new();
        self.vault = None;
    }
}
impl Drop for PersonalCustodyAdmin {
    fn drop(&mut self) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .invalidate();
    }
}

/// Owned by DaemonVault; invalidation precedes releasing its manager reference.
#[derive(Default)]
pub(crate) struct CustodyLifecycle(Mutex<Vec<Weak<Mutex<PersonalState>>>>);
impl CustodyLifecycle {
    pub(crate) fn invalidate(&self) {
        let mut owners = self.0.lock().unwrap_or_else(|e| e.into_inner());
        for owner in owners.drain(..).filter_map(|o| o.upgrade()) {
            owner.lock().unwrap_or_else(|e| e.into_inner()).invalidate();
        }
    }
}

// Versioned, domain-separated approval bytes include the vault, exact scope,
// expected outcome and source registry ID. No secret is serialized.
fn operation(
    vault: &crate::VaultManager,
    action: &str,
    scope: &CustodyScope,
    expected: Option<&ObjectRef>,
    target: Option<&ObjectRef>,
    source: Option<&Id>,
) -> Result<Vec<u8>> {
    scope.validate()?;
    if let Some(r) = expected {
        r.validate()?;
    }
    if let Some(r) = target {
        r.validate()?;
    }
    serde_json::to_vec(&(
        "sentinelpass.personal-custody.v1",
        vault.vault_uuid(),
        action,
        scope,
        expected,
        target,
        source,
    ))
    .map_err(|_| CustodyError::Denied)
}
fn consume(
    state: &PersonalState,
    authority: &Authority,
    approval: &PersonalApproval,
    connection: u128,
    op: &[u8],
) -> Result<()> {
    if !approval.state.ptr_eq(&Arc::downgrade(authority)) {
        return Err(CustodyError::Denied);
    }
    state
        .approvals
        .take_if_valid(&approval.id, connection, op)
        .map_err(|_| CustodyError::Denied)
}

impl CustodyAdmin for PersonalCustodyAdmin {
    type Source = NativeSource;
    type Approval = PersonalApproval;
    async fn put(
        &self,
        scope: &CustodyScope,
        expected: Option<&ObjectRef>,
        source: NativeSource,
        approval: PersonalApproval,
        cancel: &Cancellation,
    ) -> Result<ObjectRef> {
        let deadline = Instant::now() + Duration::from_secs(LEASE_SECONDS);
        let audit;
        let (vault, entry, budget, lifetime) = {
            let mut state = self.state.lock().map_err(|_| CustodyError::Invalidated)?;
            let vault = state.vault.as_ref().ok_or(CustodyError::Locked)?.clone();
            audit =
                workers::AuditAttempt::new(vault.clone(), crate::audit::CustodyAuditOperation::Put);
            if !source.state.ptr_eq(&Arc::downgrade(&self.state)) {
                return Err(CustodyError::Denied);
            }
            let entry = state
                .sources
                .remove(&source.id)
                .ok_or(CustodyError::Invalidated)?;
            let op = operation(
                &vault,
                "put",
                scope,
                expected,
                Some(&entry.reference),
                Some(&source.id),
            )?;
            consume(&state, &self.state, &approval, self.connection, &op)?;
            state.check_owner(scope)?;
            cancel.check()?;
            if entry.scope != *scope || entry.expires <= Instant::now() {
                return Err(CustodyError::Denied);
            }
            state.invalidate_reads();
            (vault, entry, state.workers.clone(), state.lifetime.clone())
        };
        drop((source, approval));
        let scope = scope.clone();
        let expected = expected.cloned();
        workers::run(
            budget,
            lifetime,
            cancel,
            deadline.min(entry.expires),
            move |work| {
                let outcome = vault.custody_put_checked(
                    &scope,
                    expected.as_ref(),
                    &entry.reference,
                    &entry.value,
                    || work.check(),
                    || work.begin_commit(),
                );
                audit.finish_blocking(outcome.is_ok());
                outcome.map(|()| entry.reference)
            },
        )
        .await
    }
    async fn remove(
        &self,
        scope: &CustodyScope,
        expected: &ObjectRef,
        approval: PersonalApproval,
        cancel: &Cancellation,
    ) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(LEASE_SECONDS);
        let audit;
        let (vault, budget, lifetime) = {
            let mut state = self.state.lock().map_err(|_| CustodyError::Invalidated)?;
            let vault = state.vault.as_ref().ok_or(CustodyError::Locked)?.clone();
            audit = workers::AuditAttempt::new(
                vault.clone(),
                crate::audit::CustodyAuditOperation::Remove,
            );
            let op = operation(&vault, "remove", scope, Some(expected), None, None)?;
            consume(&state, &self.state, &approval, self.connection, &op)?;
            state.check_owner(scope)?;
            cancel.check()?;
            state.invalidate_reads();
            (vault, state.workers.clone(), state.lifetime.clone())
        };
        drop(approval);
        let scope = scope.clone();
        let expected = expected.clone();
        workers::run(budget, lifetime, cancel, deadline, move |work| {
            let outcome = vault.custody_remove_checked(
                &scope,
                &expected,
                || work.check(),
                || work.begin_commit(),
            );
            audit.finish_blocking(outcome.is_ok());
            outcome
        })
        .await
    }
}

impl PersonalCustodyAdmin {
    /// Exact-object native read enrollment. Fresh approval is unconditional.
    /// Multiple grants share ONE lease/receiver registry for this owner/app.
    pub async fn authorize_read(
        &self,
        scope: &CustodyScope,
        reference: &ObjectRef,
        approval: PersonalApproval,
        cancel: &Cancellation,
    ) -> Result<NativeReadSession> {
        let deadline = Instant::now() + Duration::from_secs(LEASE_SECONDS);
        let audit;
        let (vault, budget, lifetime, generation) = {
            let state = self.state.lock().map_err(|_| CustodyError::Invalidated)?;
            let vault = state.vault.as_ref().ok_or(CustodyError::Locked)?.clone();
            audit = workers::AuditAttempt::new(
                vault.clone(),
                crate::audit::CustodyAuditOperation::Grant,
            );
            let op = operation(&vault, "grant", scope, Some(reference), None, None)?;
            consume(&state, &self.state, &approval, self.connection, &op)?;
            state.check_owner(scope)?;
            cancel.check()?;
            (
                vault,
                state.workers.clone(),
                state.lifetime.clone(),
                state.generation,
            )
        };
        drop(approval);
        let read_vault = vault.clone();
        let read_scope = scope.clone();
        let read_reference = reference.clone();
        workers::run(budget, lifetime.clone(), cancel, deadline, move |work| {
            drop(read_vault.custody_read_checked(&read_scope, &read_reference, || work.check())?);
            Ok(())
        })
        .await?;
        let outcome = (|| {
            let mut state = self.state.lock().map_err(|_| CustodyError::Invalidated)?;
            if state.generation != generation || lifetime.check().is_err() {
                return Err(CustodyError::Invalidated);
            }
            cancel.check()?;
            if Instant::now() >= deadline {
                return Err(CustodyError::Expired);
            }
            let shared = state
                .reads
                .iter()
                .find_map(Weak::upgrade)
                .unwrap_or_else(|| {
                    Arc::new(Mutex::new(State {
                        active: true,
                        lifetime: Cancellation::new(),
                        workers: state.read_workers.clone(),
                        vault: Some(vault.clone()),
                        objects: Vec::new(),
                        leases: HashMap::new(),
                        receivers: HashMap::new(),
                        #[cfg(test)]
                        offset: Duration::ZERO,
                        #[cfg(test)]
                        gate: None,
                    }))
                });
            {
                let mut session = lock(&shared)?;
                if !session.active {
                    return Err(CustodyError::Invalidated);
                }
                if let Some(old) = session
                    .objects
                    .iter()
                    .find(|o| o.reference.object_id == reference.object_id)
                {
                    if old.reference != *reference || old.scope != *scope {
                        return Err(CustodyError::StaleReference);
                    }
                } else {
                    if session.objects.len() >= MAX_LIVE_LEASES {
                        return Err(CustodyError::Capacity);
                    }
                    session.objects.push(Object {
                        scope: scope.clone(),
                        reference: reference.clone(),
                        #[cfg(test)]
                        value: None,
                    });
                }
            }
            state.reads.clear();
            state.reads.push(Arc::downgrade(&shared));
            Ok(NativeReadSession { state: shared })
        })();
        audit.finish(outcome.is_ok());
        outcome
    }
}

#[cfg(test)]
mod tests;
