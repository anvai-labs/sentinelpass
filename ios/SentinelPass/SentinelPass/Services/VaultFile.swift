//
//  VaultFile.swift
//  SentinelPass
//
//  Canonical on-disk location of the mobile vault and its at-rest file
//  policy (WBS-822). Shared by the app AND the credential-provider
//  extension (WBS-825): both targets compile this file so they resolve
//  the SAME vault path.
//

import Foundation

enum VaultFile {

    /// App Group shared between the app and the SentinelPassCredential
    /// extension (declared in both targets' entitlements). The extension
    /// opens the vault through its own bridge instance, so the database
    /// must live in the shared container, not the app's private Documents.
    static let appGroupID = "group.com.sentinelpass"

    static let vaultFileName = "sentinelpass_vault.db"

    /// Directory holding the vault database. The App Group container is
    /// primary; Documents is the fallback for unsigned/simulator builds
    /// where the group container is unavailable (containerURL returns nil
    /// on device without provisioning).
    static var directoryURL: URL {
        if let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) {
            return container
        }
        return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
    }

    static var vaultURL: URL {
        directoryURL.appendingPathComponent(vaultFileName)
    }

    static var vaultExists: Bool {
        FileManager.default.fileExists(atPath: vaultURL.path)
    }

    /**
     * Apply the WBS-822 at-rest policy to the vault database and its
     * SQLite sidecars, best-effort:
     *
     *  - `NSFileProtectionComplete`: the files are unreadable while the
     *    device is locked. The credential-provider extension only ever
     *    runs while the device is unlocked, so Complete does not break it.
     *  - `isExcludedFromBackup`: the vault is device-local. Authenticated
     *    backup/export is a separate deliverable (WBS-827) — the vault
     *    must not silently ride along in iCloud/device backups.
     *
     * Best-effort by design: on iOS the default protection class for
     * app-created files is already Complete Until First User
     * Authentication, so a failed tightening here never DOWNgrades
     * protection; callers treat failure as non-fatal.
     *
     * - Returns: true when every present file was fully processed.
     */
    @discardableResult
    static func applyAtRestPolicy() -> Bool {
        let fm = FileManager.default
        var success = true

        do {
            try fm.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        } catch {
            return false
        }

        if applyFilePolicy(to: directoryURL, isDirectory: true) == false {
            success = false
        }

        let sidecarNames = [vaultFileName, vaultFileName + "-wal", vaultFileName + "-shm"]
        for name in sidecarNames {
            let url = directoryURL.appendingPathComponent(name)
            guard fm.fileExists(atPath: url.path) else { continue }
            if applyFilePolicy(to: url, isDirectory: false) == false {
                success = false
            }
        }
        return success
    }

    private static func applyFilePolicy(to url: URL, isDirectory: Bool) -> Bool {
        let fm = FileManager.default
        var success = true

        // 1. File protection (files only — the class does not apply to dirs).
        if !isDirectory {
            do {
                try fm.setAttributes(
                    [.protectionKey: FileProtectionType.complete],
                    ofItemAtPath: url.path
                )
            } catch {
                success = false
            }
        }

        // 2. Backup exclusion (files and directories).
        var resourceURL = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        do {
            try resourceURL.setResourceValues(values)
        } catch {
            success = false
        }

        return success
    }
}
