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
 * FFI-safe TOTP code
 */
typedef struct SPTotpCode {
  const char *code;
  uint32_t seconds_remaining;
} SPTotpCode;

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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize a new vault or unlock existing vault
 *
 * # Safety
 * - `vault_path` must be a valid pointer to a C string
 * - `master_password` must be a valid pointer to a C string
 * - `out_handle` must be a valid pointer to a SPVaultHandle
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_vault_init(const char *vault_path,
                          const char *master_password,
                          SPVaultHandle *out_handle);

/**
 * Check if vault is unlocked
 *
 * # Safety
 * - `handle` must be a valid vault handle
 * - `out_unlocked` must be a valid pointer to bool
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_vault_is_unlocked(SPVaultHandle handle,
                                bool *out_unlocked);

/**
 * Lock the vault
 *
 * # Safety
 * - `handle` must be a valid vault handle
 */
void sp_vault_lock(SPVaultHandle handle);

/**
 * Destroy vault handle and free resources
 *
 * # Safety
 * - `handle` must be a valid vault handle
 */
void sp_vault_destroy(SPVaultHandle handle);

/**
 * Add entry to vault
 *
 * # Safety
 * - `handle` must be a valid vault handle
 * - `entry` must be a valid pointer to SPEntry
 * - `out_id` must be a valid pointer to a string pointer
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_entry_add(SPVaultHandle handle,
                        const SPEntry *entry,
                        const char **out_id);

/**
 * Get entry by ID
 *
 * # Safety
 * - `handle` must be a valid vault handle
 * - `id` must be a valid pointer to a C string
 * - `out_entry` must be a valid pointer to SPEntry
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_entry_get_by_id(SPVaultHandle handle,
                               const char *id,
                               SPEntry *out_entry);

/**
 * Update entry
 *
 * # Safety
 * - `handle` must be a valid vault handle
 * - `entry` must be a valid pointer to SPEntry
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_entry_update(SPVaultHandle handle,
                           const SPEntry *entry);

/**
 * Delete entry
 *
 * # Safety
 * - `handle` must be a valid vault handle
 * - `id` must be a valid pointer to a C string
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_entry_delete(SPVaultHandle handle,
                           const char *id);

/**
 * List all entries
 *
 * # Safety
 * - `handle` must be a valid vault handle
 * - `out_entries` must be a valid pointer to a SPEntrySummary const pointer
 * - `out_count` must be a valid pointer to size_t
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_entry_list_all(SPVaultHandle handle,
                              const SPEntrySummary **out_entries,
                              size_t *out_count);

/**
 * Search entries
 *
 * # Safety
 * - `handle` must be a valid vault handle
 * - `query` must be a valid pointer to a C string
 * - `out_entries` must be a valid pointer to a SPEntrySummary const pointer
 * - `out_count` must be a valid pointer to size_t
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_entry_search(SPVaultHandle handle,
                           const char *query,
                           const SPEntrySummary **out_entries,
                           size_t *out_count);

/**
 * Generate TOTP code
 *
 * # Safety
 * - `handle` must be a valid vault handle
 * - `entry_id` must be a valid pointer to a C string
 * - `out_code` must be a valid pointer to SPTotpCode
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_totp_generate_code(SPVaultHandle handle,
                                  const char *entry_id,
                                  SPTotpCode *out_code);

/**
 * Generate password
 *
 * # Safety
 * - `length` must be >= 8 and <= 64
 * - `include_symbols` must be a valid boolean
 * - `out_password` must be a valid pointer to a const char pointer
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_password_generate(size_t length,
                                bool include_symbols,
                                const char **out_password);

/**
 * Check password strength
 *
 * # Safety
 * - `password` must be a valid pointer to a C string
 * - `out_analysis` must be a valid pointer to SPPasswordAnalysis
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_password_check_strength(const char *password,
                                      SPPasswordAnalysis *out_analysis);

/**
 * Set biometric key
 *
 * # Safety
 * - `handle` must be a valid vault handle
 * - `key_data` must be a valid pointer to bytes
 * - `key_len` must be the length of key_data
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_biometric_set_key(SPVaultHandle handle,
                                const uint8_t *key_data,
                                size_t key_len);

/**
 * Check if biometric key exists
 *
 * # Safety
 * - `handle` must be a valid vault handle
 * - `out_has_key` must be a valid pointer to bool
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_biometric_has_key(SPVaultHandle handle,
                                bool *out_has_key);

/**
 * Remove biometric key
 *
 * # Safety
 * - `handle` must be a valid vault handle
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_biometric_remove_key(SPVaultHandle handle);

/**
 * Unlock vault with biometric
 *
 * # Safety
 * - `handle` must be a valid vault handle
 *
 * Returns SPErrorCode_Success on success
 */
SPErrorCode sp_biometric_unlock(SPVaultHandle handle);

/**
 * Free string allocated by Rust
 *
 * # Safety
 * - `s` must be a string pointer allocated by Rust functions
 */
void sp_string_free(const char *s);

/**
 * Free bytes allocated by Rust
 *
 * # Safety
 * - `bytes` must be a byte pointer allocated by Rust functions
 * - `len` must be the length of the bytes
 */
void sp_bytes_free(const uint8_t *bytes, size_t len);

#ifdef __cplusplus
}
#endif
