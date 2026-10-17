//! Test-only enrollment and receiver fixture. Never compiled into a consumer.
use super::*;
pub(super) struct DeliveryGate {
    pub started: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
}
pub(super) struct Controller {
    pub(super) state: Shared,
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.invalidate();
    }
}
pub(super) fn fixture(
    scope: CustodyScope,
    reference: ObjectRef,
) -> (Controller, NativeReadSession) {
    let mut bytes = Zeroizing::new([0; SECRET_BYTES]);
    rand::rngs::OsRng.fill_bytes(bytes.as_mut());
    let state = Arc::new(Mutex::new(State {
        active: true,
        lifetime: Cancellation::new(),
        workers: Arc::new(tokio::sync::Semaphore::new(MAX_LIVE_LEASES)),
        vault: None,
        objects: vec![Object {
            scope,
            reference,
            value: Some(NativeSecret(bytes)),
        }],
        leases: HashMap::new(),
        receivers: HashMap::new(),
        offset: Duration::ZERO,
        gate: None,
    }));
    (
        Controller {
            state: state.clone(),
        },
        NativeReadSession { state },
    )
}
impl Controller {
    // Models only a test adapter's authorization transition; no password/KDF.
    // Synthetic backing objects remain available like an external store would.
    pub fn synthetic_lock(&self) {
        let mut state = lock(&self.state).unwrap();
        state.active = false;
        state.leases.clear();
        state.receivers.clear();
    }
    pub fn synthetic_unlock(&self) {
        lock(&self.state).unwrap().active = true;
    }
    pub fn receiver(&self, scope: &CustodyScope, reference: &ObjectRef) -> Result<RuntimeReceiver> {
        let mut state = lock(&self.state)?;
        state.authorize(scope, reference)?;
        state.reap();
        if state.receivers.len() >= MAX_LIVE_LEASES {
            return Err(CustodyError::Capacity);
        }
        let id = random_id()?;
        if state.receivers.contains_key(&id) {
            return Err(CustodyError::Unavailable);
        }
        state.receivers.insert(
            id,
            ReceiverEntry {
                scope: scope.clone(),
                reference: reference.clone(),
                lease: None,
                value: None,
            },
        );
        Ok(RuntimeReceiver {
            state: self.state.clone(),
            id,
        })
    }
    pub fn receiver_has_secret(&self, receiver: &RuntimeReceiver) -> bool {
        let mut state = lock(&self.state).unwrap();
        state.reap();
        state.active
            && state
                .receivers
                .get(&receiver.id)
                .is_some_and(|r| r.value.is_some())
    }
    // A native test context checks correct delivery without exporting bytes.
    pub fn receiver_matches_object(&self, receiver: &RuntimeReceiver) -> bool {
        use subtle::ConstantTimeEq;
        let mut state = lock(&self.state).unwrap();
        state.reap();
        let Some(destination) = state.receivers.get(&receiver.id) else {
            return false;
        };
        let Some(value) = &destination.value else {
            return false;
        };
        let Ok(object) = state.authorize(&destination.scope, &destination.reference) else {
            return false;
        };
        // Test-only comparison, outside timing. Durable grants deliberately
        // have no plaintext backing value; authenticate a fresh storage read.
        let stored;
        let expected = if let Some(vault) = &state.vault {
            let Ok(loaded) = vault.custody_read(&object.scope, &object.reference) else {
                return false;
            };
            stored = loaded;
            &stored
        } else if let Some(value) = &object.value {
            value
        } else {
            return false;
        };
        bool::from(value.0.as_slice().ct_eq(expected.0.as_slice()))
    }
    pub fn invalidate(&self) {
        let mut state = lock(&self.state).unwrap();
        state.invalidate();
    }
    pub fn live_handles(&self) -> usize {
        let mut state = lock(&self.state).unwrap();
        state.reap();
        state.leases.len() + state.receivers.len()
    }
    pub fn advance(&self, duration: Duration) {
        lock(&self.state).unwrap().offset += duration;
    }
    pub fn pause_delivery(&self) -> Arc<DeliveryGate> {
        let gate = Arc::new(DeliveryGate {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        lock(&self.state).unwrap().gate = Some(gate.clone());
        gate
    }
}
