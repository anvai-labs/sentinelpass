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
 */
#define ABI_VERSION 1

/**
 * Oldest consumer ABI version this bridge can still serve.
 */
#define MIN_SUPPORTED_ABI_VERSION 1

/**
 * Base vault surface (init/lock, entry CRUD, TOTP, password tools).
 */
#define FEATURE_BASE (1 << 0)

/**
 * Platform-keystore biometric slot (Android Keystore / iOS Keychain
 * SecAccessControl wrapping the DEK). Off until WBS-812/821 land — a
 * biometric prompt alone must never be reported as sufficient (ADR-009:
 * a UI prompt authorizes nothing unless it authorizes the cryptographic
 * operation).
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
 * Handle to Drive sync manager (C FFI)
 */
typedef uintptr_t DriveSyncCHandle;

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
 * Handle to iCloud sync manager (opaque pointer)
 */
typedef uintptr_t ICloudSyncHandle;

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
typedef struct SyncStatus {
  bool enabled;
  int64_t last_sync_at;
  uint64_t pending_changes;
  const char *device_id;
} SyncStatus;

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

#if defined(__ANDROID__)
/**
 * Initialize Drive sync (JNI)
 *
 * # Safety
 * - `env` must be a valid JNI environment pointer
 * - `_ctx` is the Android context (unused in Rust)
 * - `device_id` is a JNI string reference
 *
 * Returns a handle to the sync manager
 */
jlong Java_com_sentinelpass_DriveSync_nativeInit(JNIEnv env, jobject _ctx, jstring device_id);
#endif

#if defined(__ANDROID__)
/**
 * Prepare sync files for upload (JNI)
 *
 * # Safety
 * - `env` must be a valid JNI environment pointer
 * - `json_blobs` is a JNI string reference (JSON array of SyncEntryBlob)
 *
 * Returns a JSON string of DriveFile objects
 */
jstring Java_com_sentinelpass_DriveSync_nativePrepareUpload(JNIEnv env,
                                                            jobject _obj,
                                                            jlong _handle,
                                                            jstring json_blobs);
#endif

#if defined(__ANDROID__)
/**
 * Process downloaded sync files (JNI)
 *
 * # Safety
 * - `env` must be a valid JNI environment pointer
 * - `json_files` is a JNI string reference (JSON array of DriveFile)
 *
 * Returns a JSON string of SyncEntryBlob objects
 */
jstring Java_com_sentinelpass_DriveSync_nativeProcessDownload(JNIEnv env,
                                                              jobject _obj,
                                                              jlong _handle,
                                                              jstring json_files);
#endif

#if defined(__ANDROID__)
/**
 * Update sync state after successful sync (JNI)
 */
jint Java_com_sentinelpass_DriveSync_nativeUpdateState(JNIEnv _env,
                                                       jobject _obj,
                                                       jlong _handle,
                                                       jlong last_sync,
                                                       jstring page_token);
#endif

enum SPErrorCode sp_biometric_has_key(SPVaultHandle handle, bool *out_has_key);

enum SPErrorCode sp_biometric_remove_key(SPVaultHandle handle);

enum SPErrorCode sp_biometric_set_key(SPVaultHandle handle,
                                      const uint8_t *key_data,
                                      uintptr_t key_data_len);

enum SPErrorCode sp_biometric_unlock(SPVaultHandle handle);

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
 * Initialize Drive sync (C FFI)
 *
 * # Safety
 * - `device_id` must be a valid null-terminated UTF-8 string
 * - `out_handle` must point to valid memory
 */
int sp_drive_sync_init(const char *device_id, DriveSyncCHandle *out_handle);

/**
 * Prepare sync files for upload (C FFI)
 *
 * # Safety
 * - `json_blobs` must be a valid null-terminated UTF-8 string (JSON array of SyncEntryBlob)
 * - `out_json` must be either null or point to valid memory for output
 */
int sp_drive_sync_prepare_upload(DriveSyncCHandle _handle, const char *json_blobs, char **out_json);

/**
 * Process downloaded sync files (C FFI)
 *
 * # Safety
 * - `json_files` must be a valid null-terminated UTF-8 string (JSON array of DriveFile)
 * - `out_json` must be either null or point to valid memory for output
 */
int sp_drive_sync_process_download(DriveSyncCHandle _handle,
                                   const char *json_files,
                                   char **out_json);

/**
 * Update sync state after successful sync (C FFI)
 */
int sp_drive_sync_update_state(DriveSyncCHandle _handle,
                               int64_t last_sync,
                               const char *_page_token);

/**
 * Add a new entry
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
 * Get entry by ID
 */
enum SPErrorCode sp_entry_get_by_id(SPVaultHandle handle,
                                    const char *entry_id,
                                    struct SPEntry *out_entry);

/**
 * List all entries
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
 * Search entries
 */
enum SPErrorCode sp_entry_search(SPVaultHandle handle,
                                 const char *query,
                                 const struct SPEntrySummary **out_entries,
                                 uintptr_t *out_count);

/**
 * Initialize iCloud sync
 *
 * # Safety
 * - `device_id` must be a valid null-terminated UTF-8 string
 * - `container_name` can be null (uses default)
 * - `out_handle` must point to valid memory
 */
int32_t sp_icloud_sync_init(const char *device_id,
                            const char *container_name,
                            ICloudSyncHandle *out_handle);

/**
 * Prepare sync records for upload
 *
 * # Safety
 * - `json_blobs` must be a valid null-terminated UTF-8 string (JSON array of SyncEntryBlob)
 * - `out_json` must be either null or point to valid memory for output
 * - Returns a JSON string that must be freed with `sp_string_free`
 */
int32_t sp_icloud_sync_prepare_upload(ICloudSyncHandle handle,
                                      const char *json_blobs,
                                      char **out_json);

/**
 * Process downloaded sync records
 *
 * # Safety
 * - `json_records` must be a valid null-terminated UTF-8 string (JSON array of CloudKitRecord)
 * - `out_json` must be either null or point to valid memory for output
 * - Returns a JSON string that must be freed with `sp_string_free`
 */
int32_t sp_icloud_sync_process_download(ICloudSyncHandle handle,
                                        const char *json_records,
                                        char **out_json);

/**
 * Update sync state after successful sync
 */
int32_t sp_icloud_sync_update_state(ICloudSyncHandle handle,
                                    int64_t last_sync,
                                    uint64_t server_sequence);

/**
 * Check password strength
 */
enum SPErrorCode sp_password_check_strength(const char *password,
                                            struct SPPasswordAnalysis *out_analysis);

/**
 * Generate password
 */
enum SPErrorCode sp_password_generate(uintptr_t length,
                                      bool include_symbols,
                                      const char **out_password);

/**
 * Free a string returned by the bridge (out-strings, `SPTotpCode.code`,
 * `SyncStatus.device_id`). Safe on null. Must be called exactly once per
 * bridge-allocated string; never on strings the caller allocated.
 */
void sp_string_free(const char *ptr);

/**
 * Apply downloaded entries (entries_json is JSON string)
 */
enum SPErrorCode sp_sync_apply_entries(SPVaultHandle handle,
                                       const uint8_t *entries_json,
                                       uintptr_t entries_len,
                                       uint64_t *out_applied);

/**
 * Collect entries pending sync (returns JSON bytes)
 */
enum SPErrorCode sp_sync_collect_pending(SPVaultHandle handle,
                                         const uint8_t **out_bytes,
                                         uintptr_t *out_len);

/**
 * Get sync status
 */
enum SPErrorCode sp_sync_get_status(SPVaultHandle handle, struct SyncStatus *out_status);

/**
 * Prepare entries for CloudKit upload (returns JSON bytes of CloudKit records)
 */
enum SPErrorCode sp_sync_prepare_cloudkit(SPVaultHandle handle,
                                          const char *device_id,
                                          const uint8_t **out_bytes,
                                          uintptr_t *out_len);

/**
 * Prepare entries for Google Drive upload (returns JSON bytes of Drive files)
 */
enum SPErrorCode sp_sync_prepare_drive(SPVaultHandle handle,
                                       const char *device_id,
                                       const uint8_t **out_bytes,
                                       uintptr_t *out_len);

/**
 * Generate TOTP code
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
