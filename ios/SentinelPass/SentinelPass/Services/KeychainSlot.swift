import Foundation
import Security

#if canImport(sentinelpass)
import sentinelpass
#endif

/// WBS-821: the iOS half of the platform-keyslot surface (ADR-009 rev 2),
/// mirroring the Rust desktop-macOS pattern (`sentinelpass-core/src/biometric.rs`
/// `mod macos`) and core's `store_vault_dek`/`load_vault_dek`.
///
/// Design: the vault DEK itself is stored in the KEYCHAIN under
/// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` +
/// `kSecAccessControlBiometryCurrentSet`. The OS refuses the item read
/// without a fresh biometric/passcode gesture — the release IS the
/// cryptographic authorization (a UI prompt alone authorizes nothing,
/// ADR-009). On devices with a Secure Enclave the item is hardware-backed.
///
/// The at-rest store is the Keychain item itself: no secret ever lands in
/// UserDefaults, files, or pasteboard. On release, the 32 recovered bytes
/// cross into the bridge ONCE via `sp_slot_open_with_dek` (FFI rule 1:
/// borrowed, never retained) and the local copy is zeroized immediately.
enum KeychainSlot {

    static let service = "com.sentinelpass.vault-slot"
    static let account = "vault-dek"
    static let slotUnavailableSentinel = "sentinelpass.slot-unavailable"

    // MARK: - Enable / Disable

    /// Store the vault's 32-byte DEK under biometric access control.
    /// Call with the DEK obtained from an UNLOCKED vault session.
    /// - Returns: nil on success, or a diagnosable failure string.
    @discardableResult
    static func storeDek(_ dek: Data) -> String? {
        guard dek.count == 32 else { return "DEK must be 32 bytes" }

        SecItemDelete(query()) // idempotent replace

        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.biometryCurrentSet, .privateKeyUsage],
            &accessError
        ) else {
            return "access control creation failed: \(accessError.map { "\(String(describing: $0.takeRetainedValue()))" } ?? "unknown")"
        }

        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: dek,
            kSecAttrAccessControl as String: access
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            return "SecItemAdd failed: \(status)"
        }
        return nil
    }

    /// Whether a slot item exists (no key material involved).
    static func hasSlot() -> Bool {
        SecItemCopyMatching(query() as CFDictionary, nil) == errSecSuccess
    }

    /// Remove the slot item (disable flow).
    static func deleteSlot() {
        SecItemDelete(query() as CFDictionary)
    }

    // MARK: - Release + open

    /**
     * Read the DEK under the OS gate (the system shows the biometric
     * prompt for the ITEM READ) and open the vault through the bridge.
     *
     * - Parameters:
     *   - vaultPath: canonical vault file path (the FFI binding).
     *   - openWithDek: bridge into `sp_slot_open_with_dek` (borrowed bytes,
     *     FFI rule 1). Injected so this file has no direct C-module
     *     dependency in tests; the production closure wraps `import sentinelpass`.
     * - Returns: nil on success, or a failure string. A refused gesture
     *   (errSecUserCanceled / itemNotFound after key invalidation) fails
     *   CLOSED — the user falls back to the master password.
     */
    @discardableResult
    static func unlock(
        vaultPath: String,
        openWithDek: (String, Data) -> Void = openWithDekViaBridge
    ) -> String? {
        var item: CFTypeRef?
        var query = self.query()
        query[kSecReturnData as String] = true
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess else {
            switch status {
            case errSecUserCanceled, errSecAuthDenied:
                return slotUnavailableSentinel // user refused — fail closed
            case errSecItemNotFound:
                return "no platform slot enrolled"
            default:
                return "keychain read failed: \(status)"
            }
        }

        guard let data = item as? Data else {
            return "keychain item was not data"
        }
        defer {
            // Caller-side zeroization of the borrowed copy (FFI rule 1).
            var mutable = data
            mutable.resetBytes(in: 0..<mutable.count)
        }

        guard data.count == 32 else {
            return "keychain DEK has invalid length"
        }

        openWithDek(vaultPath, data)
        return nil
    }

    private static func openWithDekViaBridge(vaultPath: String, dek: Data) {
        #if canImport(sentinelpass)
        let source = "iOS Keychain slot"
        // FFI rule 1: borrowed for the duration of the call only.
        dek.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard let base = raw.baseAddress else { return }
            vaultPath.withCString { pathC in
                source.withCString { sourceC in
                    var handle: SPVaultHandle = 0
                    _ = sp_slot_open_with_dek(
                        pathC,
                        base.assumingMemoryBound(to: UInt8.self),
                        dek.count,
                        sourceC,
                        &handle
                    )
                }
            }
        }
        #endif
    }

    // MARK: - Query

    private static func query() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }
}
