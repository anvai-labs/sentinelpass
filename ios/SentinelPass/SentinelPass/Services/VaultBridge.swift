//
//  VaultBridge.swift
//  SentinelPass
//
//  Bridge to SentinelPass Rust library via C ABI
//

import Foundation

#if canImport(sentinelpass)
import sentinelpass
#endif

/// Bridge class to communicate with the SentinelPass Rust mobile bridge.
///
/// Compiled against ABI v2 (see the copied contract in
/// SentinelPass/Native/include/sentinelpass_bridge.h): the legacy
/// in-process biometric exports (sp_biometric_set_key/has_key/remove_key/
/// unlock) were REMOVED in v2 (WBS-812/821) and are replaced by the
/// platform-keystore slot surface — on iOS, `KeychainSlot` +
/// `sp_slot_open_with_dek` (see `openWithKeychainDek`).
@available(iOS 17.0, macOS 14.0, *)
@MainActor
class VaultBridge {

    private var vaultHandle: SPVaultHandle = 0

    /// A bridge with no open vault; `createVault`/`unlockVault` fill in the
    /// handle.
    init() {}

    /// Take ownership of a handle opened outside this wrapper (rule 7: the
    /// holder MUST eventually destroy it — `lockVault`/`destroyVault` do).
    init(adoptingHandle handle: SPVaultHandle) {
        self.vaultHandle = handle
    }

    /// Open the vault with a raw 32-byte DEK released from the platform
    /// keystore slot (WBS-821 KeychainSlot). The bytes are BORROWED for the
    /// duration of the call only (FFI rule 1 — never retained); the caller
    /// zeroizes its copy.
    /// Returns nil if the bridge refused the open (bad length, IO, crypto).
    static func openWithKeychainDek(vaultPath: String, dek: Data) async -> VaultBridge? {
        return await withCheckedContinuation { (continuation: CheckedContinuation<VaultBridge?, Never>) in
            dek.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
                guard let base = raw.baseAddress else {
                    continuation.resume(returning: nil)
                    return
                }
                vaultPath.withCString { pathC in
                    let source = "iOS Keychain slot"
                    source.withCString { sourceC in
                        var handle: SPVaultHandle = 0
                        let code = sp_slot_open_with_dek(
                            pathC,
                            base.assumingMemoryBound(to: UInt8.self),
                            UInt(dek.count),
                            sourceC,
                            &handle
                        )
                        continuation.resume(returning: code == SPErrorCode_Success
                            ? VaultBridge(adoptingHandle: handle)
                            : nil)
                    }
                }
            }
        }
    }

    // ==========================================================================
    // Vault Management
    // ==========================================================================

    /// Create a new vault or unlock existing vault
    func createVault(vaultPath: String, masterPassword: String) async -> Bool {
        return await withCheckedContinuation { continuation in
            guard vaultPath.cString(using: .utf8) != nil,
                  masterPassword.cString(using: .utf8) != nil else {
                continuation.resume(returning: false)
                return
            }

            vaultPath.withCString { pathC in
                masterPassword.withCString { passwordC in
                    var handle: SPVaultHandle = 0
                    let errorCode = sp_vault_init(pathC, passwordC, &handle)

                    if errorCode == SPErrorCode_Success {
                        self.vaultHandle = handle
                        continuation.resume(returning: true)
                    } else {
                        continuation.resume(returning: false)
                    }
                }
            }
        }
    }

    /// Unlock existing vault
    func unlockVault(vaultPath: String, masterPassword: String) async -> Bool {
        return await withCheckedContinuation { continuation in
            guard vaultPath.cString(using: .utf8) != nil,
                  masterPassword.cString(using: .utf8) != nil else {
                continuation.resume(returning: false)
                return
            }

            vaultPath.withCString { pathC in
                masterPassword.withCString { passwordC in
                    var handle: SPVaultHandle = 0
                    let errorCode = sp_vault_init(pathC, passwordC, &handle)

                    if errorCode == SPErrorCode_Success {
                        self.vaultHandle = handle
                        continuation.resume(returning: true)
                    } else {
                        continuation.resume(returning: false)
                    }
                }
            }
        }
    }

    /// Check if vault is unlocked
    func isUnlocked() async -> Bool {
        return await withCheckedContinuation { continuation in
            var unlocked: Bool = false
            let errorCode = sp_vault_is_unlocked(vaultHandle, &unlocked)
            continuation.resume(returning: errorCode == SPErrorCode_Success && unlocked)
        }
    }

    /// Lock the vault. Locks (drops the in-memory DEK) and then destroys the
    /// handle — ownership rule 7: the holder must destroy; `sp_vault_lock`
    /// alone leaves the registry entry alive, leaking the session.
    func lockVault() {
        if vaultHandle != 0 {
            _ = sp_vault_lock(vaultHandle)
            _ = sp_vault_destroy(vaultHandle)
        }
        vaultHandle = 0
    }

    /// Destroy vault handle
    func destroyVault() {
        if vaultHandle != 0 {
            _ = sp_vault_destroy(vaultHandle)
            vaultHandle = 0
        }
    }

    // ==========================================================================
    // Entry Management
    // ==========================================================================

    /// Add a new entry
    func addEntry(title: String, username: String, password: String, url: String, notes: String) async -> String? {
        return await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            title.withCString { titleC in
                username.withCString { usernameC in
                    password.withCString { passwordC in
                        url.withCString { urlC in
                            notes.withCString { notesC in
                                var entryId: UnsafePointer<CChar>?

                                let result = sp_entry_add(
                                    vaultHandle,
                                    titleC,
                                    usernameC,
                                    passwordC,
                                    urlC,
                                    notesC,
                                    &entryId
                                )

                                guard result == SPErrorCode_Success,
                                      let idPtr = entryId else {
                                    continuation.resume(returning: nil)
                                    return
                                }

                                let entryIdString = String(cString: idPtr)
                                sp_string_free(idPtr)

                                continuation.resume(returning: entryIdString)
                            }
                        }
                    }
                }
            }
        }
    }

    /// Get entry by ID
    func getEntry(id: String) async -> EntryDetails? {
        return await withCheckedContinuation { continuation in
            guard id.cString(using: .utf8) != nil else {
                continuation.resume(returning: nil)
                return
            }

            id.withCString { idC in
                var entry = SPEntry()

                let result = sp_entry_get_by_id(vaultHandle, idC, &entry)

                guard result == SPErrorCode_Success else {
                    continuation.resume(returning: nil)
                    return
                }

                guard let idPtr = entry.id,
                      let titlePtr = entry.title,
                      let usernamePtr = entry.username,
                      let passwordPtr = entry.password else {
                    continuation.resume(returning: nil)
                    return
                }

                let details = EntryDetails(
                    id: String(cString: idPtr),
                    title: String(cString: titlePtr),
                    username: String(cString: usernamePtr),
                    password: String(cString: passwordPtr),
                    url: entry.url != nil ? String(cString: entry.url!) : nil,
                    notes: entry.notes != nil ? String(cString: entry.notes!) : nil,
                    favorite: entry.favorite,
                    createdAt: Date(timeIntervalSince1970: TimeInterval(entry.created_at)),
                    modifiedAt: Date(timeIntervalSince1970: TimeInterval(entry.modified_at))
                )

                // WBS-804 rule 6: release the struct's strings with the
                // dedicated sp_entry_free (releases all six members).
                sp_entry_free(&entry)

                continuation.resume(returning: details)
            }
        }
    }

    /// List all entries
    func listEntries() async -> [EntrySummary] {
        return await withCheckedContinuation { continuation in
            var entriesPointer: UnsafePointer<SPEntrySummary>?
            var count: UInt = 0

            let result = sp_entry_list_all(vaultHandle, &entriesPointer, &count)

            guard result == SPErrorCode_Success,
                  let entries = entriesPointer else {
                continuation.resume(returning: [])
                return
            }

            var summaries: [EntrySummary] = []

            for i in 0..<count {
                let entry = entries[Int(i)]

                guard let idPtr = entry.id,
                      let titlePtr = entry.title,
                      let usernamePtr = entry.username else {
                    continue
                }

                let summary = EntrySummary(
                    id: String(cString: idPtr),
                    title: String(cString: titlePtr),
                    username: String(cString: usernamePtr),
                    favorite: entry.favorite
                )
                summaries.append(summary)
            }

            // WBS-804 rule 5: sp_entry_list_free releases EVERY element's
            // strings and the backing array — do not also sp_string_free
            // the members (double free) or sp_bytes_free the array.
            sp_entry_list_free(UnsafeMutablePointer(mutating: entries), count)

            continuation.resume(returning: summaries)
        }
    }

    /// Search entries
    func searchEntries(query: String) async -> [EntrySummary] {
        return await withCheckedContinuation { continuation in
            guard query.cString(using: .utf8) != nil else {
                continuation.resume(returning: [])
                return
            }

            query.withCString { queryC in
                var entriesPointer: UnsafePointer<SPEntrySummary>?
                var count: UInt = 0

                let result = sp_entry_search(vaultHandle, queryC, &entriesPointer, &count)

                guard result == SPErrorCode_Success,
                      let entries = entriesPointer else {
                    continuation.resume(returning: [])
                    return
                }

                var summaries: [EntrySummary] = []

                for i in 0..<count {
                    let entry = entries[Int(i)]

                    guard let idPtr = entry.id,
                          let titlePtr = entry.title,
                          let usernamePtr = entry.username else {
                        continue
                    }

                    let summary = EntrySummary(
                        id: String(cString: idPtr),
                        title: String(cString: titlePtr),
                        username: String(cString: usernamePtr),
                        favorite: entry.favorite
                    )
                    summaries.append(summary)
                }

                // WBS-804 rule 5: sp_entry_list_free releases EVERY element's
                // strings and the backing array — do not also sp_string_free
                // the members (double free) or sp_bytes_free the array.
                sp_entry_list_free(UnsafeMutablePointer(mutating: entries), count)

                continuation.resume(returning: summaries)
            }
        }
    }

    /// Delete entry
    func deleteEntry(id: String) async -> Bool {
        return await withCheckedContinuation { continuation in
            guard id.cString(using: .utf8) != nil else {
                continuation.resume(returning: false)
                return
            }

            id.withCString { idC in
                let result = sp_entry_delete(vaultHandle, idC)
                continuation.resume(returning: result == SPErrorCode_Success)
            }
        }
    }

    /// Update entry — ATOMIC via `sp_entry_update` (WBS-807). The old
    /// delete-then-add workaround lost history and raced concurrent readers;
    /// the v2 ABI provides the real operation.
    func updateEntry(id: String, title: String, username: String, password: String, url: String, notes: String) async -> Bool {
        return await withCheckedContinuation { continuation in
            guard id.cString(using: .utf8) != nil,
                  title.cString(using: .utf8) != nil,
                  username.cString(using: .utf8) != nil,
                  password.cString(using: .utf8) != nil,
                  url.cString(using: .utf8) != nil,
                  notes.cString(using: .utf8) != nil else {
                continuation.resume(returning: false)
                return
            }

            id.withCString { idC in
                title.withCString { titleC in
                    username.withCString { usernameC in
                        password.withCString { passwordC in
                            url.withCString { urlC in
                                notes.withCString { notesC in
                                    let result = sp_entry_update(
                                        vaultHandle,
                                        idC,
                                        titleC,
                                        usernameC,
                                        passwordC,
                                        urlC,
                                        notesC
                                    )
                                    continuation.resume(returning: result == SPErrorCode_Success)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ==========================================================================
    // TOTP
    // ==========================================================================

    /// Generate TOTP code
    func generateTotp(entryId: String) async -> TotpCode? {
        return await withCheckedContinuation { continuation in
            guard entryId.cString(using: .utf8) != nil else {
                continuation.resume(returning: nil)
                return
            }

            entryId.withCString { entryIdC in
                var totpCode = SPTotpCode()

                let result = sp_totp_generate_code(vaultHandle, entryIdC, &totpCode)

                guard result == SPErrorCode_Success,
                      let codePtr = totpCode.code else {
                    continuation.resume(returning: nil)
                    return
                }

                let code = String(cString: codePtr)
                let seconds = totpCode.seconds_remaining

                sp_string_free(codePtr)

                continuation.resume(returning: TotpCode(code: code, secondsRemaining: seconds))
            }
        }
    }

    // ==========================================================================
    // Password Generation
    // ==========================================================================

    /// Generate random password
    static func generatePassword(length: Int, includeSymbols: Bool) async -> String? {
        return await withCheckedContinuation { continuation in
            var password: UnsafePointer<CChar>?

            let result = sp_password_generate(
                UInt(length),
                includeSymbols,
                &password
            )

            guard result == SPErrorCode_Success,
                  let passwordPtr = password else {
                continuation.resume(returning: nil)
                return
            }

            let passwordStr = String(cString: passwordPtr)
            sp_string_free(passwordPtr)

            continuation.resume(returning: passwordStr)
        }
    }

    /// Check password strength
    static func checkPasswordStrength(password: String) async -> PasswordAnalysis? {
        return await withCheckedContinuation { continuation in
            guard password.cString(using: .utf8) != nil else {
                continuation.resume(returning: nil)
                return
            }

            password.withCString { passwordC in
                var analysis = SPPasswordAnalysis()

                let result = sp_password_check_strength(passwordC, &analysis)

                guard result == SPErrorCode_Success else {
                    continuation.resume(returning: nil)
                    return
                }

                let strength = PasswordAnalysis(
                    score: Int(analysis.score),
                    entropyBits: analysis.entropy_bits,
                    crackTimeSeconds: analysis.crack_time_seconds,
                    length: Int(analysis.length),
                    hasLower: analysis.has_lower,
                    hasUpper: analysis.has_upper,
                    hasDigit: analysis.has_digit,
                    hasSymbol: analysis.has_symbol
                )

                continuation.resume(returning: strength)
            }
        }
    }

    // ==========================================================================
    // Biometric / platform slot
    // ==========================================================================
    //
    // ABI v2 removed the in-process biometric exports (sp_biometric_*). The
    // iOS platform slot is Keychain-based: the DEK lives in a
    // kSecAccessControlBiometryCurrentSet Keychain item (Services/
    // KeychainSlot.swift, WBS-821) and the vault is opened through
    // `openWithKeychainDek` above. VaultState exposes the user-facing
    // surface (unlock with the slot; enrollment is an M4 deliverable).
}

// ==========================================================================
// Supporting Types
// ==========================================================================

/// Full entry as delivered by the bridge (`sp_entry_get_by_id`). This type
/// exists ONLY in memory for a detail view — it is never persisted on the
/// Swift side (the vault is the Rust SQLite database; WBS-826 removed the
/// plaintext-mirroring SwiftData model).
struct EntryDetails: Identifiable {
    let id: String
    let title: String
    let username: String
    let password: String
    let url: String?
    let notes: String?
    let favorite: Bool
    let createdAt: Date
    let modifiedAt: Date
}
