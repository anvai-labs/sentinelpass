use sentinelpass_mobile_bridge::{sp_custody_validate_metadata, ErrorCode};
const SCOPE: &[u8] = include_bytes!("../../bindings/custody/scope.golden.json");
const REFERENCE: &[u8] = include_bytes!("../../bindings/custody/reference.golden.json");

#[test]
fn custody_ffi_rejects_positional_array_metadata() {
    let vectors: [(u32, &[u8]); 3] = [
        (
            1,
            include_bytes!("../../bindings/custody/scope.array.invalid.json"),
        ),
        (
            2,
            include_bytes!("../../bindings/custody/reference.array.invalid.json"),
        ),
        (
            3,
            include_bytes!("../../bindings/custody/capabilities.array.invalid.json"),
        ),
    ];
    for (kind, bytes) in vectors {
        assert_eq!(
            unsafe { sp_custody_validate_metadata(2, kind, bytes.as_ptr(), bytes.len()) },
            ErrorCode::InvalidParam,
            "metadata kind {kind} accepted a positional array"
        );
    }
}

#[test]
fn custody_ffi_metadata_is_bounded_and_fails_closed() {
    unsafe {
        assert_eq!(
            sp_custody_validate_metadata(2, 1, SCOPE.as_ptr(), SCOPE.len()),
            ErrorCode::Success
        );
        assert_eq!(
            sp_custody_validate_metadata(2, 2, REFERENCE.as_ptr(), REFERENCE.len()),
            ErrorCode::Success
        );
        for abi in [0, 1, 3, u32::MAX] {
            assert_eq!(
                sp_custody_validate_metadata(abi, 1, SCOPE.as_ptr(), SCOPE.len()),
                ErrorCode::AbiUnsupported
            );
        }
        assert_eq!(
            sp_custody_validate_metadata(2, 0, SCOPE.as_ptr(), SCOPE.len()),
            ErrorCode::InvalidParam
        );
        assert_eq!(
            sp_custody_validate_metadata(2, 1, std::ptr::null(), 0),
            ErrorCode::InvalidParam
        );
        // Length rejected before pointer access, including usize overflow input.
        assert_eq!(
            sp_custody_validate_metadata(2, 1, SCOPE.as_ptr(), usize::MAX),
            ErrorCode::InvalidParam
        );
        assert_eq!(
            sp_custody_validate_metadata(2, 1, REFERENCE.as_ptr(), REFERENCE.len()),
            ErrorCode::InvalidParam
        );
        let bad =
            String::from_utf8_lossy(SCOPE).replace("\"version\":1", "\"version\":1,\"version\":1");
        assert_eq!(
            sp_custody_validate_metadata(2, 1, bad.as_ptr(), bad.len()),
            ErrorCode::InvalidParam
        );
    }
}
