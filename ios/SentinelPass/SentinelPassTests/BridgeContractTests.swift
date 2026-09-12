import XCTest

#if canImport(sentinelpass)
import sentinelpass
#endif

/// WBS-828: real XCTest coverage over the compiled bridge contract — the
/// same assertions the Rust suite pins, executed against the actual static
/// library on an iOS simulator. These replace the self-contained toy tests
/// (which tested nothing but their own helpers).
///
/// Feature-flag values mirror `sentinelpass-mobile-bridge/src/abi.rs`
/// (they are Rust constants, not part of the C header contract):
/// BASE = 1<<0, PLATFORM_KEYSTORE = 1<<1, RELAY_SYNC_V2 = 1<<2. If the Rust
/// values change, change them HERE IN THE SAME COMMIT — the drift is exactly
/// what this suite exists to catch.
private enum FeatureFlags {
    static let base: UInt32 = 1 << 0
    static let platformKeystore: UInt32 = 1 << 1
    static let relaySyncV2: UInt32 = 1 << 2
}

final class BridgeContractTests: XCTestCase {

    func testAbiHandshakeReportsV2AndFailClosedFlags() throws {
        #if canImport(sentinelpass)
        var info = SPBridgeInfo(
            abi_version: 0, min_supported_abi_version: 0, feature_flags: 0, reserved: 1
        )
        XCTAssertEqual(code(of: sp_bridge_info(&info)), SPErrorCode_Success)
        XCTAssertEqual(info.abi_version, 2, "ABI v2: platform slots in, legacy biometric out")
        XCTAssertEqual(info.min_supported_abi_version, 2)
        XCTAssertEqual(info.reserved, 0, "reserved must be zeroed by the callee")
        XCTAssertEqual(
            info.feature_flags & FeatureFlags.base, FeatureFlags.base,
            "base surface must always be advertised"
        )
        XCTAssertEqual(
            info.feature_flags & FeatureFlags.platformKeystore, FeatureFlags.platformKeystore,
            "keystore slot is implemented since WBS-812/821"
        )
        XCTAssertEqual(
            info.feature_flags & FeatureFlags.relaySyncV2, 0,
            "relay sync v2 is not wired on mobile yet — must not be advertised"
        )
        #else
        throw XCTSkip("bridge module unavailable")
        #endif
    }

    func testNegotiateAcceptsCurrentAndRefusesMismatch() throws {
        #if canImport(sentinelpass)
        var info = SPBridgeInfo(
            abi_version: 0, min_supported_abi_version: 0, feature_flags: 0, reserved: 0
        )
        XCTAssertEqual(code(of: sp_bridge_negotiate(2, &info)), SPErrorCode_Success)
        // Older than supported: refused, but out_info still describes the build.
        var refused = info
        XCTAssertEqual(
            code(of: sp_bridge_negotiate(1, &refused)), SPErrorCode_AbiUnsupported
        )
        XCTAssertEqual(refused.abi_version, 2)
        // Newer than the bridge: refused the same way.
        XCTAssertEqual(
            code(of: sp_bridge_negotiate(3, &refused)), SPErrorCode_AbiUnsupported
        )
        #else
        throw XCTSkip("bridge module unavailable")
        #endif
    }

    func testPasswordGenerateProducesOwnedStringFreedExactlyOnce() throws {
        #if canImport(sentinelpass)
        var pw: UnsafePointer<CChar>? = nil
        XCTAssertEqual(
            code(of: sp_password_generate(24, true, &pw)), SPErrorCode_Success
        )
        let generated = String(cString: pw!)
        XCTAssertEqual(generated.count, 24)
        // Ownership rule 2: exactly one sanctioned release.
        sp_string_free(pw)
        #else
        throw XCTSkip("bridge module unavailable")
        #endif
    }

    func testPasswordGenerateRejectsOutOfBoundsLengths() throws {
        #if canImport(sentinelpass)
        var pw: UnsafePointer<CChar>? = nil
        XCTAssertNotEqual(
            code(of: sp_password_generate(7, false, &pw)), SPErrorCode_Success
        )
        XCTAssertNotEqual(
            code(of: sp_password_generate(129, false, &pw)), SPErrorCode_Success
        )
        #else
        throw XCTSkip("bridge module unavailable")
        #endif
    }

    func testSlotChallengeIsFreshHex64() throws {
        #if canImport(sentinelpass)
        var a: UnsafePointer<CChar>? = nil
        var b: UnsafePointer<CChar>? = nil
        XCTAssertEqual(code(of: sp_slot_challenge(&a)), SPErrorCode_Success)
        XCTAssertEqual(code(of: sp_slot_challenge(&b)), SPErrorCode_Success)
        let hexA = String(cString: a!)
        let hexB = String(cString: b!)
        XCTAssertEqual(hexA.count, 64, "32 bytes hex-encoded")
        XCTAssertNotEqual(hexA, hexB, "challenges must not repeat")
        sp_string_free(a)
        sp_string_free(b)
        #else
        throw XCTSkip("bridge module unavailable")
        #endif
    }

    func testSlotHasBlobRejectsGarbage() throws {
        #if canImport(sentinelpass)
        var has = true
        let status = "not-a-blob".withCString { c in
            sp_slot_has_blob(c, &has)
        }
        XCTAssertEqual(code(of: status), SPErrorCode_Success)
        XCTAssertFalse(has)
        #else
        throw XCTSkip("bridge module unavailable")
        #endif
    }

    func testFreesAreNullSafe() throws {
        #if canImport(sentinelpass)
        sp_string_free(nil)
        sp_bytes_free(nil, 0)
        sp_entry_free(nil)
        sp_entry_list_free(nil, 0)
        #else
        throw XCTSkip("bridge module unavailable")
        #endif
    }

    /// Un-typed C enums import as structs; this keeps the comparisons above
    /// readable without reaching into the importer's raw-value details.
    private func code(of error: SPErrorCode) -> SPErrorCode {
        error
    }
}
