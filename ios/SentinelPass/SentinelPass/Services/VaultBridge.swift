//
//  VaultBridge.swift
//  SentinelPass
//
//  Bridge to SentinelPass Rust library via C ABI
//

import Foundation
import LocalAuthentication

#if canImport(sentinelpass)
import sentinelpass
#endif

/// Bridge class to communicate with the SentinelPass Rust mobile bridge
@available(iOS 17.0, macOS 14.0, *)
@MainActor
class VaultBridge {

    private var vaultHandle: SPVaultHandle = 0

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

    /// Lock the vault
    func lockVault() {
        _ = sp_vault_lock(vaultHandle)
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

                // Free strings
                sp_string_free(idPtr)
                sp_string_free(titlePtr)
                sp_string_free(usernamePtr)
                sp_string_free(passwordPtr)
                if entry.url != nil { sp_string_free(entry.url!) }
                if entry.notes != nil { sp_string_free(entry.notes!) }

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

                // Free strings
                sp_string_free(idPtr)
                sp_string_free(titlePtr)
                sp_string_free(usernamePtr)
            }

            // Free array
            entries.withMemoryRebound(to: UInt8.self, capacity: Int(count) * MemoryLayout<SPEntrySummary>.stride) { bytePtr in
                sp_bytes_free(bytePtr, Int(count) * MemoryLayout<SPEntrySummary>.stride)
            }

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

                    // Free strings
                    sp_string_free(idPtr)
                    sp_string_free(titlePtr)
                    sp_string_free(usernamePtr)
                }

                // Free array
                entries.withMemoryRebound(to: UInt8.self, capacity: Int(count) * MemoryLayout<SPEntrySummary>.stride) { bytePtr in
                    sp_bytes_free(bytePtr, Int(count) * MemoryLayout<SPEntrySummary>.stride)
                }

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

    /// Update entry (not in C ABI yet, using delete + add)
    func updateEntry(id: String, title: String, username: String, password: String, url: String, notes: String) async -> Bool {
        // Delete old entry and add updated version
        let deleted = await deleteEntry(id: id)
        guard deleted,
              let _ = await addEntry(title: title, username: username, password: password, url: url, notes: notes) else {
            return false
        }
        return true
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
                Int(length),
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
    // Biometric
    // ==========================================================================

    /// Set biometric key
    func setBiometricKey(keyData: Data) async -> Bool {
        return await withCheckedContinuation { continuation in
            let result = keyData.withUnsafeBytes { bytes in
                sp_biometric_set_key(
                    vaultHandle,
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    keyData.count
                )
            }
            continuation.resume(returning: result == SPErrorCode_Success)
        }
    }

    /// Check if biometric key exists
    func hasBiometricKey() async -> Bool {
        return await withCheckedContinuation { continuation in
            var hasKey: Bool = false
            let result = sp_biometric_has_key(vaultHandle, &hasKey)
            continuation.resume(returning: result == SPErrorCode_Success && hasKey)
        }
    }

    /// Remove biometric key
    func removeBiometricKey() async -> Bool {
        return await withCheckedContinuation { continuation in
            let result = sp_biometric_remove_key(vaultHandle)
            continuation.resume(returning: result == SPErrorCode_Success)
        }
    }

    /// Unlock with biometric
    func unlockWithBiometric() async -> Bool {
        return await withCheckedContinuation { continuation in
            let result = sp_biometric_unlock(vaultHandle)
            continuation.resume(returning: result == SPErrorCode_Success)
        }
    }
}

// ==========================================================================
// Supporting Types
// ==========================================================================

struct EntryDetails {
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
