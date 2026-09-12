import Foundation

#if canImport(sentinelpass)
import sentinelpass
#endif

/// WBS-827: authenticated backup/export through the ADR-008 `.spbackup`
/// bundle format.
///
/// - CREATE requires an UNLOCKED vault (the bundle binds key material) and
///   refuses to overwrite an existing output — pick a fresh path or delete
///   first.
/// - RESTORE is STATIC and offline-exclusive (ADR-007): every open bridge
///   handle for the target path must be DESTROYED first (`VaultState` does).
///   The flags map 1:1 to core's `RestoreOptions` — the restored state comes
///   back sync-disabled and re-pairs when `disableSync` is set; both
///   overrides are audit-logged by core.
///
/// Both calls return the non-secret JSON metadata on success and throw
/// `BackupError.failed(code)` otherwise; panic containment is the bridge's
/// job (WBS-805).
enum BackupService {

    enum BackupError: Error, LocalizedError {
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .failed(let detail): return "backup operation failed: \(detail)"
            }
        }
    }

    /// Create a `.spbackup` bundle at `outputPath` from the UNLOCKED vault
    /// behind `handle` (ownership rule 7: the caller owns the handle).
    static func create(outputPath: String, handle: SPVaultHandle) throws {
        #if canImport(sentinelpass)
        var code = SPErrorCode_Unknown
        outputPath.withCString { outC in
            var summary: UnsafePointer<CChar>? = nil
            code = sp_backup_create(handle, outC, &summary)
            if code == SPErrorCode_Success, let owned = summary {
                // Metadata only (backup id, counts) — safe to read as a
                // String; the buffer itself is freed per rule 2.
                let _ = String(cString: owned)
                sp_string_free(owned)
            }
        }
        guard code == SPErrorCode_Success else { throw BackupError.failed(String(describing: code)) }
        #else
        throw BackupError.failed("bridge module unavailable")
        #endif
    }

    /// Restore `bundlePath` onto `vaultPath`. See the type doc for the
    /// handle contract and flag semantics.
    static func restore(
        vaultPath: String,
        bundlePath: String,
        masterPassword: String,
        allowReplace: Bool = false,
        allowEpochRewind: Bool = false,
        disableSync: Bool = true
    ) throws {
        #if canImport(sentinelpass)
        var code = SPErrorCode_Unknown
        vaultPath.withCString { pathC in
            bundlePath.withCString { bundleC in
                masterPassword.withCString { pwC in
                    var report: UnsafePointer<CChar>? = nil
                    code = sp_backup_restore(
                        pathC, bundleC, pwC,
                        allowReplace, allowEpochRewind, disableSync,
                        &report
                    )
                    if code == SPErrorCode_Success, let owned = report {
                        let _ = String(cString: owned)
                        sp_string_free(owned)
                    }
                }
            }
        }
        guard code == SPErrorCode_Success else { throw BackupError.failed(String(describing: code)) }
        #else
        throw BackupError.failed("bridge module unavailable")
        #endif
    }
}
