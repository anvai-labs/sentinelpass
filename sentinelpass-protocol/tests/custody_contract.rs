use sentinelpass_protocol::custody::{CustodyError, CustodyScope, ObjectRef, ProviderCapabilities};

const SCOPE: &str = r#"{"version":1,"namespace":"sandesha","issuer":"https://issuer.example","subject":"subject-1","mailboxId":"mailbox-1","purpose":"mail-recovery"}"#;
const REFERENCE: &str = r#"{"objectId":"object-1","revision":"1","keyEpoch":"1","bindingSha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#;

#[test]
fn custody_scope_rejects_positional_array_metadata() {
    let bytes = include_bytes!("fixtures/scope.array.invalid.json");
    assert!(CustodyScope::decode(bytes).is_err());
    assert!(serde_json::from_slice::<CustodyScope>(bytes).is_err());
}

#[test]
fn custody_reference_rejects_positional_array_metadata() {
    let bytes = include_bytes!("fixtures/reference.array.invalid.json");
    assert!(ObjectRef::decode(bytes).is_err());
    assert!(serde_json::from_slice::<ObjectRef>(bytes).is_err());
}

#[test]
fn custody_capabilities_rejects_positional_array_metadata() {
    let bytes = include_bytes!("fixtures/capabilities.array.invalid.json");
    assert!(ProviderCapabilities::decode(bytes).is_err());
    assert!(serde_json::from_slice::<ProviderCapabilities>(bytes).is_err());
}

#[test]
fn custody_golden_metadata_round_trips_without_coercion() {
    assert_eq!(include_str!("fixtures/scope.golden.json").trim(), SCOPE);
    assert_eq!(
        include_str!("fixtures/reference.golden.json").trim(),
        REFERENCE
    );
    let scope = CustodyScope::decode(SCOPE.as_bytes()).unwrap();
    let reference = ObjectRef::decode(REFERENCE.as_bytes()).unwrap();
    assert_eq!(serde_json::to_string(&scope).unwrap(), SCOPE);
    assert_eq!(serde_json::to_string(&reference).unwrap(), REFERENCE);
}

#[test]
fn custody_capability_negotiation_does_not_enable_unimplemented_adapters() {
    use sentinelpass_protocol::custody::ProviderCapabilities;
    let info = ProviderCapabilities::unavailable();
    for version in [0, 1, 2, u32::MAX] {
        assert_eq!(
            info.require_native_transfer(version),
            Err(CustodyError::Unsupported)
        );
    }
    assert!(!info.can_sync);
    assert!(!info.can_portable_export);
    let json = serde_json::to_vec(&info).unwrap();
    assert_eq!(ProviderCapabilities::decode(&json).unwrap(), info);
}

#[test]
fn custody_rejects_unknown_duplicate_and_unsupported_metadata() {
    for text in [
        SCOPE.replace("\"version\":1", "\"version\":2"),
        SCOPE.replace("\"version\":1", "\"version\":1,\"version\":1"),
        SCOPE.replace("\"version\":1", "\"version\":1,\"secret\":\"canary\""),
        SCOPE.replace("mail-recovery", "password"),
        SCOPE.replace("subject-1", "*"),
        SCOPE.replace("subject-1", ""),
        SCOPE.replace("subject-1", &"x".repeat(513)),
    ] {
        assert!(CustodyScope::decode(text.as_bytes()).is_err());
        assert!(serde_json::from_str::<CustodyScope>(&text).is_err());
    }
    assert_eq!(
        CustodyScope::decode(&vec![b' '; 4097]),
        Err(CustodyError::Denied)
    );
}

#[test]
fn custody_rejects_noncanonical_cas_epoch_and_digest() {
    for value in [
        "0",
        "01",
        "-1",
        "+1",
        "1.0",
        "1e1",
        "18446744073709551616",
        "",
    ] {
        for field in ["revision", "keyEpoch"] {
            let text = REFERENCE.replace(
                &format!("\"{field}\":\"1\""),
                &format!("\"{field}\":\"{value}\""),
            );
            assert!(ObjectRef::decode(text.as_bytes()).is_err());
        }
    }
    assert!(ObjectRef::decode(REFERENCE.replace("abcdef", "ABCDEF").as_bytes()).is_err());
}
