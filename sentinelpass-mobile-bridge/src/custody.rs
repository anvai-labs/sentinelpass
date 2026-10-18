//! Metadata validation only. Does not open a vault, enroll a provider, mint a
//! handle, prompt for authentication or release any secret.
use crate::{abi, ErrorCode};
use sentinelpass_core::custody::{
    CustodyScope, ObjectRef, ProviderCapabilities, MAX_METADATA_BYTES,
};

pub(crate) fn validate(abi_version: u32, kind: u32, metadata: &[u8]) -> ErrorCode {
    if abi::negotiate(abi_version).is_err() {
        return ErrorCode::AbiUnsupported;
    }
    if metadata.is_empty() || metadata.len() > MAX_METADATA_BYTES {
        return ErrorCode::InvalidParam;
    }
    let valid = match kind {
        1 => CustodyScope::decode(metadata).is_ok(),
        2 => ObjectRef::decode(metadata).is_ok(),
        3 => ProviderCapabilities::decode(metadata).is_ok(),
        _ => false,
    };
    if valid {
        ErrorCode::Success
    } else {
        ErrorCode::InvalidParam
    }
}
