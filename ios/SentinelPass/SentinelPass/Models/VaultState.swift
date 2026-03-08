//
//  VaultState.swift
//  SentinelPass
//
//  Manages vault state and communicates with the bridge
//

import Foundation
import SwiftUI
import LocalAuthentication

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
        // Vault stored in app's documents directory
        let documentsDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        self.vaultURL = documentsDir.appendingPathComponent("sentinelpass_vault.db")
        self.hasVault = FileManager.default.fileExists(atPath: vaultURL.path)
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

    func getEntry(id: String) async throws -> EntryModel {
        guard let bridge = vaultBridge else {
            throw VaultError.vaultLocked
        }

        guard let entry = await bridge.getEntry(id: id) else {
            throw VaultError.entryNotFound
        }

        return EntryModel(
            id: entry.id,
            title: entry.title,
            username: entry.username,
            password: entry.password,
            url: entry.url,
            notes: entry.notes,
            favorite: entry.favorite,
            createdAt: entry.createdAt,
            modifiedAt: entry.modifiedAt
        )
    }

    func addEntry(title: String, username: String, password: String, url: String, notes: String) async throws {
        guard let bridge = vaultBridge else {
            throw VaultError.vaultLocked
        }

        guard let entryId = await bridge.addEntry(
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

    // MARK: - Biometric

    func enableBiometric() async throws {
        guard let bridge = vaultBridge else {
            throw VaultError.vaultLocked
        }

        // Generate biometric key
        let keyData = generateBiometricKey()
        let success = await bridge.setBiometricKey(keyData: keyData)

        guard success else {
            throw VaultError.biometricFailed
        }
    }

    func disableBiometric() async throws {
        guard let bridge = vaultBridge else {
            throw VaultError.vaultLocked
        }

        let success = await bridge.removeBiometricKey()
        guard success else {
            throw VaultError.biometricFailed
        }
    }

    func hasBiometricKey() async -> Bool {
        guard let bridge = vaultBridge else { return false }
        return await bridge.hasBiometricKey()
    }

    func unlockWithBiometric() async throws {
        guard let bridge = vaultBridge else {
            throw VaultError.vaultLocked
        }

        let success = await bridge.unlockWithBiometric()
        guard success else {
            throw VaultError.biometricFailed
        }

        isUnlocked = true
        await loadEntries()
    }

    // MARK: - Helpers

    private func generateBiometricKey() -> Data {
        // Generate 32 random bytes for biometric key
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        return Data(bytes)
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
    case biometricFailed

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
        case .biometricFailed:
            return "Biometric operation failed"
        }
    }
}
