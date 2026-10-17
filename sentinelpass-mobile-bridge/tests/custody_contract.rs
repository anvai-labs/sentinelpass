use sentinelpass_mobile_bridge::{sp_custody_validate_metadata, ErrorCode};
const SCOPE: &[u8] = include_bytes!("../../bindings/custody/scope.golden.json");
const REFERENCE: &[u8] = include_bytes!("../../bindings/custody/reference.golden.json");

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
