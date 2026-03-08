#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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
  SPErrorCode_Unknown = -99,
} SPErrorCode;

/**
 * Vault handle type (opaque u64 for FFI)
 */
typedef uint64_t SPVaultHandle;

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
sp jlong Java_com_sentinelpass_DriveSync_nativeInit(JNIEnv Env, jobject Ctx, jstring DeviceId);

/**
 * Prepare sync files for upload (JNI)
 *
 * # Safety
 * - `env` must be a valid JNI environment pointer
 * - `json_blobs` is a JNI string reference (JSON array of SyncEntryBlob)
 *
 * Returns a JSON string of DriveFile objects
 */
sp
jstring Java_com_sentinelpass_DriveSync_nativePrepareUpload(JNIEnv Env,
                                                            jobject Obj,
                                                            jlong Handle,
                                                            jstring JsonBlobs);

/**
 * Process downloaded sync files (JNI)
 *
 * # Safety
 * - `env` must be a valid JNI environment pointer
 * - `json_files` is a JNI string reference (JSON array of DriveFile)
 *
 * Returns a JSON string of SyncEntryBlob objects
 */
sp
jstring Java_com_sentinelpass_DriveSync_nativeProcessDownload(JNIEnv Env,
                                                              jobject Obj,
                                                              jlong Handle,
                                                              jstring JsonFiles);

/**
 * Update sync state after successful sync (JNI)
 */
sp
jint Java_com_sentinelpass_DriveSync_nativeUpdateState(JNIEnv Env,
                                                       jobject Obj,
                                                       jlong Handle,
                                                       jlong LastSync,
                                                       jstring PageToken);

sp enum SPErrorCode sp_biometric_has_key(SPVaultHandle Handle, bool *OutHasKey);

sp enum SPErrorCode sp_biometric_remove_key(SPVaultHandle Handle);

sp
enum SPErrorCode sp_biometric_set_key(SPVaultHandle Handle,
                                      const uint8_t *KeyData,
                                      uintptr_t KeyDataLen);

sp enum SPErrorCode sp_biometric_unlock(SPVaultHandle Handle);

sp void sp_bytes_free(const uint8_t *Ptr, uintptr_t Len);

/**
 * Initialize Drive sync (C FFI)
 *
 * # Safety
 * - `device_id` must be a valid null-terminated UTF-8 string
 * - `out_handle` must point to valid memory
 */
sp int sp_drive_sync_init(const char *DeviceId, DriveSyncCHandle *OutHandle);

/**
 * Prepare sync files for upload (C FFI)
 *
 * # Safety
 * - `json_blobs` must be a valid null-terminated UTF-8 string (JSON array of SyncEntryBlob)
 * - `out_json` must be either null or point to valid memory for output
 */
sp int sp_drive_sync_prepare_upload(DriveSyncCHandle Handle, const char *JsonBlobs, char **OutJson);

/**
 * Process downloaded sync files (C FFI)
 *
 * # Safety
 * - `json_files` must be a valid null-terminated UTF-8 string (JSON array of DriveFile)
 * - `out_json` must be either null or point to valid memory for output
 */
sp
int sp_drive_sync_process_download(DriveSyncCHandle Handle,
                                   const char *JsonFiles,
                                   char **OutJson);

/**
 * Update sync state after successful sync (C FFI)
 */
sp int sp_drive_sync_update_state(DriveSyncCHandle Handle, int64_t LastSync, const char *PageToken);

/**
 * Add a new entry
 */
sp
enum SPErrorCode sp_entry_add(SPVaultHandle Handle,
                              const char *Title,
                              const char *Username,
                              const char *Password,
                              const char *Url,
                              const char *Notes,
                              const char **OutEntryId);

/**
 * Delete entry
 */
sp enum SPErrorCode sp_entry_delete(SPVaultHandle Handle, const char *EntryId);

/**
 * Get entry by ID
 */
sp
enum SPErrorCode sp_entry_get_by_id(SPVaultHandle Handle,
                                    const char *EntryId,
                                    struct SPEntry *OutEntry);

/**
 * List all entries
 */
sp
enum SPErrorCode sp_entry_list_all(SPVaultHandle Handle,
                                   const struct SPEntrySummary **OutEntries,
                                   uintptr_t *OutCount);

/**
 * Search entries
 */
sp
enum SPErrorCode sp_entry_search(SPVaultHandle Handle,
                                 const char *Query,
                                 const struct SPEntrySummary **OutEntries,
                                 uintptr_t *OutCount);

/**
 * Initialize iCloud sync
 *
 * # Safety
 * - `device_id` must be a valid null-terminated UTF-8 string
 * - `container_name` can be null (uses default)
 * - `out_handle` must point to valid memory
 */
sp
int32_t sp_icloud_sync_init(const char *DeviceId,
                            const char *ContainerName,
                            ICloudSyncHandle *OutHandle);

/**
 * Prepare sync records for upload
 *
 * # Safety
 * - `json_blobs` must be a valid null-terminated UTF-8 string (JSON array of SyncEntryBlob)
 * - `out_json` must be either null or point to valid memory for output
 * - Returns a JSON string that must be freed with `sp_string_free`
 */
sp
int32_t sp_icloud_sync_prepare_upload(ICloudSyncHandle Handle,
                                      const char *JsonBlobs,
                                      char **OutJson);

/**
 * Process downloaded sync records
 *
 * # Safety
 * - `json_records` must be a valid null-terminated UTF-8 string (JSON array of CloudKitRecord)
 * - `out_json` must be either null or point to valid memory for output
 * - Returns a JSON string that must be freed with `sp_string_free`
 */
sp
int32_t sp_icloud_sync_process_download(ICloudSyncHandle Handle,
                                        const char *JsonRecords,
                                        char **OutJson);

/**
 * Update sync state after successful sync
 */
sp
int32_t sp_icloud_sync_update_state(ICloudSyncHandle Handle,
                                    int64_t LastSync,
                                    uint64_t ServerSequence);

/**
 * Check password strength
 */
sp
enum SPErrorCode sp_password_check_strength(const char *Password,
                                            struct SPPasswordAnalysis *OutAnalysis);

/**
 * Generate password
 */
sp
enum SPErrorCode sp_password_generate(uintptr_t Length,
                                      bool IncludeSymbols,
                                      const char **OutPassword);

sp void sp_string_free(const char *Ptr);

/**
 * Apply downloaded entries (entries_json is JSON string)
 */
sp
enum SPErrorCode sp_sync_apply_entries(SPVaultHandle Handle,
                                       const uint8_t *EntriesJson,
                                       uintptr_t EntriesLen,
                                       uint64_t *OutApplied);

/**
 * Collect entries pending sync (returns JSON bytes)
 */
sp
enum SPErrorCode sp_sync_collect_pending(SPVaultHandle Handle,
                                         const uint8_t **OutBytes,
                                         uintptr_t *OutLen);

/**
 * Get sync status
 */
sp enum SPErrorCode sp_sync_get_status(SPVaultHandle Handle, struct SyncStatus *OutStatus);

/**
 * Prepare entries for CloudKit upload (returns JSON bytes of CloudKit records)
 */
sp
enum SPErrorCode sp_sync_prepare_cloudkit(SPVaultHandle Handle,
                                          const char *DeviceId,
                                          const uint8_t **OutBytes,
                                          uintptr_t *OutLen);

/**
 * Prepare entries for Google Drive upload (returns JSON bytes of Drive files)
 */
sp
enum SPErrorCode sp_sync_prepare_drive(SPVaultHandle Handle,
                                       const char *DeviceId,
                                       const uint8_t **OutBytes,
                                       uintptr_t *OutLen);

/**
 * Generate TOTP code
 */
sp
enum SPErrorCode sp_totp_generate_code(SPVaultHandle Handle,
                                       const char *EntryId,
                                       struct SPTotpCode *OutCode);

/**
 * Destroy a vault
 */
sp enum SPErrorCode sp_vault_destroy(SPVaultHandle Handle);

/**
 * Initialize or unlock a vault
 */
sp
enum SPErrorCode sp_vault_init(const char *VaultPath,
                               const char *MasterPassword,
                               SPVaultHandle *OutHandle);

/**
 * Check if vault is unlocked
 */
sp enum SPErrorCode sp_vault_is_unlocked(SPVaultHandle Handle, bool *OutUnlocked);

/**
 * Lock the vault
 */
sp enum SPErrorCode sp_vault_lock(SPVaultHandle Handle);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
