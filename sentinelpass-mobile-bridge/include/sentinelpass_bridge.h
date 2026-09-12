#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * ABI contract version of this build.
 *
 * Bump on ANY breaking change to the exported C ABI (signature changes,
 * struct layout changes, removed symbols) or the JNI contract. Additive,
 * backward-compatible changes (new symbols, new trailing error codes) do not
 * require a bump, but a bump must also raise [`MIN_SUPPORTED_ABI_VERSION`]
 * only when older consumers genuinely cannot interoperate.
 * History: v1 = M1 base surface. v2 = WBS-812/821 removed the legacy
 * in-process biometric exports (sp_biometric_set_key/has_key/remove_key/
 * unlock) and added the platform-slot surface (sp_slot_challenge/has_blob/
 * seal/unlock/open_with_dek) — v1 consumers cannot interoperate.
 */
#define ABI_VERSION 2

/**
 * Oldest consumer ABI version this bridge can still serve.
 */
#define MIN_SUPPORTED_ABI_VERSION 2

/**
 * Base vault surface (init/lock, entry CRUD, TOTP, password tools).
 */
#define FEATURE_BASE (1 << 0)

/**
 * Platform-keystore biometric slot (Android Keystore / iOS Keychain
 * SecAccessControl wrapping the DEK). Advertised since WBS-812/821 (Stage
 * M2): the slot surface is challenge/seal/unlock behind auth-bound keys —
 * a biometric prompt alone still authorizes nothing without the
 * cryptographic operation (ADR-009).
 */
#define FEATURE_PLATFORM_KEYSTORE (1 << 1)

/**
 * Relay-based sync v2 (ADR-006) wired through the bridge. Off until the
 * mobile sync surface is implemented; the CloudKit/Drive paths are removed
 * under WBS-807 and must never be advertised.
 */
#define FEATURE_RELAY_SYNC_V2 (1 << 2)

/**
 * Error codes that can be returned to mobile platforms
 */
typedef enum SPErrorCode {
  SPErrorCode_Success = 0,
  SPErrorCode_InvalidParam = -1,
  SPErrorCode_VaultLocked = -2,
  SPErrorCode_NotFound = -3,
  SPErrorCode_Crypto = -4,
  SPErrorCode_Database = -5,
  SPErrorCode_Io = -6,
  SPErrorCode_AlreadyUnlocked = -7,
  SPErrorCode_InvalidPassword = -8,
  SPErrorCode_NotInitialized = -9,
  SPErrorCode_Biometric = -10,
  SPErrorCode_Totp = -11,
  SPErrorCode_Sync = -12,
  SPErrorCode_OutOfMemory = -13,
  SPErrorCode_AbiUnsupported = -14,
  /**
   * A Rust panic was contained at the FFI/JNI boundary (WBS-805). The
   * operation did NOT complete; out-params are undefined.
   */
  SPErrorCode_Panic = -15,
  SPErrorCode_Unknown = -99,
} SPErrorCode;

/**
 * Vault handle type (opaque u64 for FFI)
 */
typedef uint64_t SPVaultHandle;

/**
 * ABI/feature description reported to consumers (WBS-803).
 */
typedef struct SPBridgeInfo {
  uint32_t abi_version;
  uint32_t min_supported_abi_version;
  uint32_t feature_flags;
  /**
   * Must be zero; reserved for future growth so the struct can gain
   * fields without breaking consumers that zero-initialize it.
   */
  uint32_t reserved;
} SPBridgeInfo;

/**
 * FFI-safe entry representation
 */
typedef struct SPEntry {
  const char *id;
  const char *title;
  const char *username;
  const char *password;
  const char *url;
  const char *notes;
  int64_t created_at;
  int64_t modified_at;
  bool favorite;
} SPEntry;

/**
 * FFI-safe entry summary (for list views)
 */
typedef struct SPEntrySummary {
  const char *id;
  const char *title;
  const char *username;
  bool favorite;
} SPEntrySummary;

/**
 * FFI-safe password analysis result
 */
typedef struct SPPasswordAnalysis {
  int score;
  double entropy_bits;
  double crack_time_seconds;
  unsigned int length;
  bool has_lower;
  bool has_upper;
  bool has_digit;
  bool has_symbol;
} SPPasswordAnalysis;

/**
 * FFI-safe sync status representation
 */
typedef struct SPSyncStatus {
  bool enabled;
  int64_t last_sync_at;
  uint64_t pending_changes;
  const char *device_id;
} SPSyncStatus;

/**
 * FFI-safe TOTP code representation
 */
typedef struct SPTotpCode {
  const char *code;
  uint32_t seconds_remaining;
} SPTotpCode;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Create an authenticated .spbackup bundle from the UNLOCKED vault at
 * `handle`. Refuses to overwrite an existing output. Ownership rule 2:
 * release `out_summary` (JSON, non-secret metadata) with `sp_string_free`.
 */
enum SPErrorCode sp_backup_create(SPVaultHandle handle,
                                  const char *output_path,
                                  const char **out_summary);

/**
 * Restore a .spbackup bundle onto `vault_path` (STATIC, offline-exclusive).
 * CALLER CONTRACT: destroy every open bridge handle for `vault_path` first.
 * `allow_replace` acknowledges replacing an existing target;
 * `allow_epoch_rewind` is the ADR-004 rev 4 supervised override;
 * `disable_sync` acknowledges ADR-008 branch 2 (restored state re-pairs).
 * Ownership rule 2: release `out_report` (JSON) with `sp_string_free`.
 */
enum SPErrorCode sp_backup_restore(const char *vault_path,
                                   const char *bundle_path,
                                   const char *master_password,
                                   bool allow_replace,
                                   bool allow_epoch_rewind,
                                   bool disable_sync,
                                   const char **out_report);

/**
 * Report this build's ABI version and feature flags.
 *
 * Ownership: `out_info` is written by the callee; no allocation is
 * performed and nothing needs freeing.
 */
enum SPErrorCode sp_bridge_info(struct SPBridgeInfo *out_info);

/**
 * Negotiate a consumer's ABI version against this build (WBS-803).
 *
 * `client_abi_version` is the ABI the caller was built against. On success
 * (`Success`) the versions are compatible and `out_info` describes this
 * build; the caller must feature-test `feature_flags` before using optional
 * capabilities. On `AbiUnsupported` the caller MUST refuse to operate; the
 * header contract is versioned as one unit, so an unsupported consumer
 * cannot assume any other symbol's signature. `out_info` (if non-null) is
 * filled even on failure so the caller can report the mismatch.
 */
enum SPErrorCode sp_bridge_negotiate(uint32_t client_abi_version, struct SPBridgeInfo *out_info);

/**
 * Free a byte buffer returned by the bridge, using the same `len` that the
 * producing call output. The buffer is deallocated with the exact layout
 * used at allocation (`Layout::array::<u8>(len)`); passing a different
 * `len` is a caller bug. Never call this on buffers the caller allocated.
 */
void sp_bytes_free(const uint8_t *ptr, uintptr_t len);

/**
 * Add a new entry.
 *
 * Ownership (WBS-804 rule 2): on `Success` the caller MUST release
 * `*out_entry_id` with `sp_string_free`.
 */
enum SPErrorCode sp_entry_add(SPVaultHandle handle,
                              const char *title,
                              const char *username,
                              const char *password,
                              const char *url,
                              const char *notes,
                              const char **out_entry_id);

/**
 * Delete entry
 */
enum SPErrorCode sp_entry_delete(SPVaultHandle handle, const char *entry_id);

/**
 * Free one `SPEntry` returned by `sp_entry_get_by_id`, releasing all six
 * string members. The struct storage itself is caller-provided and is NOT
 * freed here. Safe on null.
 */
void sp_entry_free(struct SPEntry *entry);

/**
 * Get entry by ID.
 *
 * Ownership (WBS-804 rule 6): on `Success` the caller MUST release the
 * strings with `sp_entry_free(&mut entry)`. `url`/`notes` are NULL when the
 * entry has no such field (rule 2); `id`/`title`/`username`/`password` are
 * never NULL on `Success`.
 */
enum SPErrorCode sp_entry_get_by_id(SPVaultHandle handle,
                                    const char *entry_id,
                                    struct SPEntry *out_entry);

/**
 * List all entries.
 *
 * Ownership (WBS-804 rule 5): on `Success` the caller MUST release the
 * array with `sp_entry_list_free(*out_entries, *out_count)`.
 */
enum SPErrorCode sp_entry_list_all(SPVaultHandle handle,
                                   const struct SPEntrySummary **out_entries,
                                   uintptr_t *out_count);

/**
 * Free an `SPEntrySummary` array returned by `sp_entry_list_all` /
 * `sp_entry_search`, releasing every element's strings and the backing
 * array (allocated under `Layout::array::<EntrySummary>(count)`). Safe on
 * null or `count == 0`.
 */
void sp_entry_list_free(struct SPEntrySummary *entries, uintptr_t count);

/**
 * Search entries.
 *
 * Ownership (WBS-804 rule 5): on `Success` the caller MUST release the
 * array with `sp_entry_list_free(*out_entries, *out_count)`.
 */
enum SPErrorCode sp_entry_search(SPVaultHandle handle,
                                 const char *query,
                                 const struct SPEntrySummary **out_entries,
                                 uintptr_t *out_count);

/**
 * Update an existing entry (WBS-807: ATOMIC update).
 *
 * A null argument means "leave this field unchanged"; a non-null empty
 * string clears `url`/`notes`. One call, one transaction — the caller never
 * needs delete-then-add (which would lose history and race concurrent
 * readers).
 */
enum SPErrorCode sp_entry_update(SPVaultHandle handle,
                                 const char *entry_id,
                                 const char *title,
                                 const char *username,
                                 const char *password,
                                 const char *url,
                                 const char *notes);

/**
 * Check password strength.
 *
 * Ownership: `out_analysis` is plain data written by the callee; nothing to
 * free (WBS-804 rule 4).
 */
enum SPErrorCode sp_password_check_strength(const char *password,
                                            struct SPPasswordAnalysis *out_analysis);

/**
 * Generate a password (8..=128 chars).
 *
 * Ownership (WBS-804 rule 2): on `Success` the caller MUST release
 * `*out_password` with `sp_string_free`.
 */
enum SPErrorCode sp_password_generate(uintptr_t length,
                                      bool include_symbols,
                                      const char **out_password);

/**
 * Draw a fresh 32-byte challenge (hex) for the platform's auth-bound key to
 * sign. Ownership rule 2: release `out_hex` with `sp_string_free`.
 */
enum SPErrorCode sp_slot_challenge(const char **out_hex);

/**
 * Preflight: whether `blob_json` is a recognized v1 slot blob. No key
 * material involved; `out_has` is written on `Success`.
 */
enum SPErrorCode sp_slot_has_blob(const char *blob_json, bool *out_has);

/**
 * iOS Keychain pattern (WBS-821, `biometric.rs mod macos` analog): Swift
 * reads the DEK from the `kSecAccessControlBiometryCurrentSet`-gated
 * Keychain item (the OS-gated release IS the authorization) and passes the
 * 32 bytes here to open the vault. `dek` is BORROWED (rule 1: never
 * retained; the caller zeroizes its copy). Ownership rule 7 on the
 * returned handle.
 */
enum SPErrorCode sp_slot_open_with_dek(const char *vault_path,
                                       const uint8_t *dek,
                                       uintptr_t dek_len,
                                       const char *source,
                                       SPVaultHandle *out_handle);

/**
 * Seal the vault DEK under the platform signature (ENABLE).
 *
 * `challenge`/`sig_a`/`sig_b` are hex strings from the host platform: the
 * challenge the auth-bound key signed and TWO byte-identical signatures
 * (deterministic scheme). `binding` is the caller-stable vault identity.
 * Ownership rule 2: on `Success` release `out_blob` (the NON-SECRET
 * at-rest blob JSON) with `sp_string_free`.
 */
enum SPErrorCode sp_slot_seal(SPVaultHandle handle,
                              const char *challenge,
                              const char *sig_a,
                              const char *sig_b,
                              const char *binding,
                              const char **out_blob);

/**
 * Release the DEK from the slot blob with a fresh platform signature over
 * the blob's challenge and OPEN the vault (UNLOCK). Fails closed on any
 * mismatch. Ownership rule 7: the returned handle must be destroyed.
 */
enum SPErrorCode sp_slot_unlock(const char *vault_path,
                                const char *blob_json,
                                const char *sig,
                                const char *binding,
                                SPVaultHandle *out_handle);

/**
 * Free a string returned by the bridge (out-strings, `SPTotpCode.code`,
 * `SyncStatus.device_id`). Safe on null. Must be called exactly once per
 * bridge-allocated string; never on strings the caller allocated.
 */
void sp_string_free(const char *ptr);

/**
 * Get sync status.
 *
 * Ownership (WBS-804 rule 4): on `Success` the caller MUST release
 * `out_status.device_id` with `sp_string_free` (NULL when no device is
 * registered — rule 2). Sync stays disabled until the mobile relay sync v2
 * surface is wired (ADR-006/ADR-009; the CloudKit/Drive placeholders were
 * removed under WBS-807).
 */
enum SPErrorCode sp_sync_get_status(SPVaultHandle handle, struct SPSyncStatus *out_status);

/**
 * Generate TOTP code.
 *
 * Ownership (WBS-804 rule 4): on `Success` the caller MUST release
 * `out_code.code` with `sp_string_free`.
 */
enum SPErrorCode sp_totp_generate_code(SPVaultHandle handle,
                                       const char *entry_id,
                                       struct SPTotpCode *out_code);

/**
 * Destroy a vault
 */
enum SPErrorCode sp_vault_destroy(SPVaultHandle handle);

/**
 * Initialize or unlock a vault
 */
enum SPErrorCode sp_vault_init(const char *vault_path,
                               const char *master_password,
                               SPVaultHandle *out_handle);

/**
 * Check if vault is unlocked
 */
enum SPErrorCode sp_vault_is_unlocked(SPVaultHandle handle, bool *out_unlocked);

/**
 * Lock the vault
 */
enum SPErrorCode sp_vault_lock(SPVaultHandle handle);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
