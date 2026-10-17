#![no_main]
use libfuzzer_sys::fuzz_target;
use sentinelpass_protocol::custody::{CustodyScope, ObjectRef, ProviderCapabilities};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(scope) = CustodyScope::decode(bytes) { assert!(scope.validate().is_ok()); }
    if let Ok(reference) = ObjectRef::decode(bytes) { assert!(reference.validate().is_ok()); }
    if let Ok(info) = ProviderCapabilities::decode(bytes) { assert!(info.validate().is_ok()); }
});
