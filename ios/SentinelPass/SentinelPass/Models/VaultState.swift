//
//  VaultState.swift
//  SentinelPass
//
//  Manages vault state and communicates with the bridge
//
//  WBS-822: the vault lives under the App Group container shared with the
//  credential-provider extension (Services/VaultFile.swift) and gets
//  NSFileProtectionComplete + backup exclusion applied best-effort after
//  creation and on every launch.
//

import Foundation
import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
@MainActor
class VaultState: ObservableObject {
    static let shared = VaultState()

    @Published var isUnlocked: Bool = false
    @Published var hasVault: Bool = false
    @Published var entries: [EntryModel] = []
    @Published var errorMessage: String?
    @Published var isLoading: Bool = false

    private var vaultBridge: VaultBridge?
    private let vaultURL: URL

    private init() {
        // WBS-825: shared App Group container so the credential-provider
        // extension can open the SAME vault (Documents is the unsigned
        // build fallback — see VaultFile.directoryURL).
        self.vaultURL = VaultFile.vaultURL
        self.hasVault = VaultFile.vaultExists
        // Idempotent; the policy is enforced at rest from the first run.
        VaultFile.applyAtRestPolicy()
    }

    // MARK: - Vault Management

    func createVault(masterPassword: String) async throws {
        isLoading = true
        defer { isLoading = false }

        let bridge = VaultBridge()
        let success = await bridge.createVault(
            vaultPath: vaultURL.path,
            masterPassword: masterPassword
        )

        guard success else {
            throw VaultError.creationFailed
        }

        self.vaultBridge = bridge
        self.hasVault = true
        self.isUnlocked = true
        // WBS-822: protect the freshly created database immediately.
        VaultFile.applyAtRestPolicy()
        await loadEntries()
    }

    func unlockVault(masterPassword: String) async throws {
        isLoading = true
        defer { isLoading = false }

        let bridge = VaultBridge()
        let success = await bridge.unlockVault(
            vaultPath: vaultURL.path,
            masterPassword: masterPassword
        )

        guard success else {
            throw VaultError.invalidPassword
        }

        self.vaultBridge = bridge
        self.isUnlocked = true
        await loadEntries()
    }

    /// WBS-821/823: unlock via the Keychain platform slot. The OS raises
    /// the biometric/passcode prompt for the KEYCHAIN ITEM READ — the
    /// release IS the cryptographic authorization (ADR-009), the UI here
    /// only waits. Runs off the main actor because the keychain read
    /// blocks until the user answers the system prompt.
    func unlockWithKeychainSlot() async throws {
        isLoading = true
        defer { isLoading = false }

        let path = vaultURL.path
        let result = await Task.detached(priority: .userInitiated) {
            KeychainSlot.unlock(vaultPath: path)
        }.value

        switch result {
        case .opened(let handle):
            self.vaultBridge = VaultBridge(adoptingHandle: handle)
            self.isUnlocked = true
            await loadEntries()
        case .failed(let message):
            throw VaultError.slotUnlockFailed(message)
        }
    }

    func lockVault() {
        vaultBridge?.lockVault()
        vaultBridge = nil
        isUnlocked = false
        entries.removeAll()
    }

    // MARK: - Entry Management

    func loadEntries() async {
        guard let bridge = vaultBridge else { return }

        let summaries = await bridge.listEntries()
        entries = summaries.map { summary in
            EntryModel(
                id: summary.id,
                title: summary.title,
                username: summary.username,
                favorite: summary.favorite
            )
        }
    }

    /// Full entry detail (password/url/notes included) for the detail
    /// view — in memory only, never persisted Swift-side (WBS-826).
    func getEntry(id: String) async throws -> EntryDetails {
        guard let bridge = vaultBridge else {
            throw VaultError.vaultLocked
        }

        guard let entry = await bridge.getEntry(id: id) else {
            throw VaultError.entryNotFound
        }

        return entry
    }

    func addEntry(title: String, username: String, password: String, url: String, notes: String) async throws {
        guard let bridge = vaultBridge else {
            throw VaultError.vaultLocked
        }

        guard let _ = await bridge.addEntry(
            title: title,
            username: username,
            password: password,
            url: url,
            notes: notes
        ) else {
            throw VaultError.addEntryFailed
        }

        await loadEntries()
    }

    func updateEntry(id: String, title: String, username: String, password: String, url: String, notes: String) async throws {
        guard let bridge = vaultBridge else {
            throw VaultError.vaultLocked
        }

        let success = await bridge.updateEntry(
            id: id,
            title: title,
            username: username,
            password: password,
            url: url,
            notes: notes
        )

        guard success else {
            throw VaultError.updateEntryFailed
        }

        await loadEntries()
    }

    func deleteEntry(id: String) async throws {
        guard let bridge = vaultBridge else {
            throw VaultError.vaultLocked
        }

        let success = await bridge.deleteEntry(id: id)
        guard success else {
            throw VaultError.deleteEntryFailed
        }

        await loadEntries()
    }

    func searchEntries(query: String) async -> [EntryModel] {
        guard let bridge = vaultBridge else { return [] }

        let summaries = await bridge.searchEntries(query: query)
        return summaries.map { summary in
            EntryModel(
                id: summary.id,
                title: summary.title,
                username: summary.username,
                favorite: summary.favorite
            )
        }
    }

    // MARK: - TOTP

    func generateTotp(entryId: String) async throws -> TotpCode {
        guard let bridge = vaultBridge else {
            throw VaultError.vaultLocked
        }

        guard let totp = await bridge.generateTotp(entryId: entryId) else {
            throw VaultError.totpFailed
        }

        return totp
    }

    // MARK: - Password Generation

    func generatePassword(length: Int, includeSymbols: Bool) async -> String? {
        return await VaultBridge.generatePassword(length: length, includeSymbols: includeSymbols)
    }

    func checkPasswordStrength(password: String) async -> PasswordAnalysis? {
        return await VaultBridge.checkPasswordStrength(password: password)
    }

    // MARK: - Platform Keychain Slot (WBS-821)

    /// Whether a keychain slot is enrolled (no key material involved).
    func hasKeychainSlot() -> Bool {
        KeychainSlot.hasSlot()
    }

    /// Remove the enrolled slot (disable flow).
    func disableKeychainSlot() {
        KeychainSlot.deleteSlot()
    }
}

// MARK: - Errors

enum VaultError: LocalizedError {
    case creationFailed
    case invalidPassword
    case vaultLocked
    case entryNotFound
    case addEntryFailed
    case updateEntryFailed
    case deleteEntryFailed
    case totpFailed
    case slotUnlockFailed(String)

    var errorDescription: String? {
        switch self {
        case .creationFailed:
            return "Failed to create vault"
        case .invalidPassword:
            return "Invalid master password"
        case .vaultLocked:
            return "Vault is locked"
        case .entryNotFound:
            return "Entry not found"
        case .addEntryFailed:
            return "Failed to add entry"
        case .updateEntryFailed:
            return "Failed to update entry"
        case .deleteEntryFailed:
            return "Failed to delete entry"
        case .totpFailed:
            return "TOTP generation failed"
        case .slotUnlockFailed(let message):
            if message == KeychainSlot.slotUnavailableSentinel {
                return "Keychain unlock was refused. Please use your master password."
            }
            return "Keychain slot unlock failed: \(message)"
        }
    }
}
