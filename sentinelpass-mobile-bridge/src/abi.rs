// ABI/feature negotiation (WBS-803)
//
// Single source of truth for the bridge's ABI contract version and feature
// flags. Both the C ABI (`sp_bridge_info` / `sp_bridge_negotiate`) and the
// JNI surface (`nativeAbiVersion`) read from here; consumers handshake before
// performing vault operations and fail closed on mismatch (ADR-009).

use crate::error::BridgeError;

/// ABI contract version of this build.
///
/// Bump on ANY breaking change to the exported C ABI (signature changes,
/// struct layout changes, removed symbols) or the JNI contract. Additive,
/// backward-compatible changes (new symbols, new trailing error codes) do not
/// require a bump, but a bump must also raise [`MIN_SUPPORTED_ABI_VERSION`]
/// only when older consumers genuinely cannot interoperate.
pub const ABI_VERSION: u32 = 1;

/// Oldest consumer ABI version this bridge can still serve.
pub const MIN_SUPPORTED_ABI_VERSION: u32 = 1;

/// Base vault surface (init/lock, entry CRUD, TOTP, password tools).
pub const FEATURE_BASE: u32 = 1 << 0;

/// Platform-keystore biometric slot (Android Keystore / iOS Keychain
/// SecAccessControl wrapping the DEK). Off until WBS-812/821 land — a
/// biometric prompt alone must never be reported as sufficient (ADR-009:
/// a UI prompt authorizes nothing unless it authorizes the cryptographic
/// operation).
// Negotiation vocabulary: consumers test this flag; it is simply never SET
// until the slot exists, hence "unused" until WBS-812/821.
#[allow(dead_code)]
pub const FEATURE_PLATFORM_KEYSTORE: u32 = 1 << 1;

/// Relay-based sync v2 (ADR-006) wired through the bridge. Off until the
/// mobile sync surface is implemented; the CloudKit/Drive paths are removed
/// under WBS-807 and must never be advertised.
#[allow(dead_code)]
pub const FEATURE_RELAY_SYNC_V2: u32 = 1 << 2;

/// ABI/feature description reported to consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeInfo {
    pub abi_version: u32,
    pub min_supported_abi_version: u32,
    pub feature_flags: u32,
}

/// Feature flags of this build. Fail-closed: capabilities are advertised
/// only once actually implemented behind the ABI.
pub fn feature_flags() -> u32 {
    let flags = FEATURE_BASE;
    // FEATURE_PLATFORM_KEYSTORE (WBS-812/821, Stage M2) and
    // FEATURE_RELAY_SYNC_V2 stay unset until those WBS items land.
    flags
}

/// Description of this build's ABI surface.
pub fn abi_info() -> BridgeInfo {
    BridgeInfo {
        abi_version: ABI_VERSION,
        min_supported_abi_version: MIN_SUPPORTED_ABI_VERSION,
        feature_flags: feature_flags(),
    }
}

/// Negotiate a consumer's ABI version against this build.
///
/// Compatible iff `MIN_SUPPORTED_ABI_VERSION <= client_abi_version <=
/// ABI_VERSION`. The returned [`BridgeInfo`] lets a compatible consumer
/// feature-detect optional capabilities; an incompatible consumer receives
/// [`BridgeError::AbiUnsupported`] and must refuse to operate.
pub fn negotiate(client_abi_version: u32) -> Result<BridgeInfo, BridgeError> {
    if client_abi_version < MIN_SUPPORTED_ABI_VERSION {
        return Err(BridgeError::AbiUnsupported(format!(
            "client ABI {client_abi_version} is older than the minimum supported version {MIN_SUPPORTED_ABI_VERSION}"
        )));
    }
    if client_abi_version > ABI_VERSION {
        return Err(BridgeError::AbiUnsupported(format!(
            "client ABI {client_abi_version} is newer than this bridge's version {ABI_VERSION} — update the bridge library"
        )));
    }
    Ok(abi_info())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_accepts_current_version() {
        let info = negotiate(ABI_VERSION).expect("current version must negotiate");
        assert_eq!(info.abi_version, ABI_VERSION);
        assert_eq!(info.min_supported_abi_version, MIN_SUPPORTED_ABI_VERSION);
        assert_eq!(
            info.feature_flags & FEATURE_BASE,
            FEATURE_BASE,
            "base surface must always be advertised"
        );
    }

    #[test]
    fn negotiate_accepts_version_within_supported_range() {
        if MIN_SUPPORTED_ABI_VERSION < ABI_VERSION {
            let info = negotiate(ABI_VERSION - 1).expect("in-range version must negotiate");
            assert_eq!(info.abi_version, ABI_VERSION);
        } else {
            // Range is collapsed; nothing else to accept.
            assert!(negotiate(ABI_VERSION).is_ok());
        }
    }

    #[test]
    fn negotiate_rejects_older_than_supported() {
        let err = negotiate(MIN_SUPPORTED_ABI_VERSION - 1)
            .expect_err("older-than-supported ABI must be refused");
        assert!(
            matches!(err, BridgeError::AbiUnsupported(_)),
            "expected AbiUnsupported, got {err:?}"
        );
    }

    #[test]
    fn negotiate_rejects_newer_than_bridge() {
        let err = negotiate(ABI_VERSION + 1).expect_err("newer-than-bridge ABI must be refused");
        assert!(matches!(err, BridgeError::AbiUnsupported(_)));
        assert!(negotiate(u32::MAX).is_err());
    }

    #[test]
    fn unimplemented_capabilities_fail_closed() {
        // WBS-812/821 flip FEATURE_PLATFORM_KEYSTORE on when the keystore-bound
        // slot actually wraps the DEK; WBS sync items flip FEATURE_RELAY_SYNC_V2.
        // Until then the bridge must NOT advertise them (a prompt is not a
        // cryptographic authorization — ADR-009).
        let flags = feature_flags();
        assert_eq!(
            flags & FEATURE_PLATFORM_KEYSTORE,
            0,
            "platform keystore slot not implemented yet — must not be advertised"
        );
        assert_eq!(
            flags & FEATURE_RELAY_SYNC_V2,
            0,
            "relay sync v2 not wired on mobile yet — must not be advertised"
        );
    }
}
