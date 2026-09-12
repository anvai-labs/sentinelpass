package com.sentinelpass

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Bridge to SentinelPass Rust library via JNI
 * Handles all native library calls and manages vault handles
 */
class VaultBridge(private val context: Context) {

    companion object {
        private const val TAG = "VaultBridge"
        private val json = Json { ignoreUnknownKeys = true }

        /**
         * ABI contract version this Kotlin facade was built against
         * (WBS-803). Must match the bridge's [crate::abi::ABI_VERSION];
         * [init] handshakes and fails closed on mismatch rather than
         * calling across an undefined contract.
         */
        private const val EXPECTED_ABI_VERSION = 1

        init {
            System.loadLibrary("sentinelpass_mobile_bridge")
        }
    }

    private var nativeHandle: Long = 0

    init {
        val abiVersion = nativeAbiVersion()
        if (abiVersion != EXPECTED_ABI_VERSION) {
            throw IllegalStateException(
                "SentinelPass bridge ABI mismatch: library reports $abiVersion, " +
                    "app was built for $EXPECTED_ABI_VERSION. Refusing to operate."
            )
        }
    }

    // Error codes matching Rust ErrorCode enum
    enum class ErrorCode(val value: Int) {
        SUCCESS(0),
        INVALID_PARAM(-1),
        VAULT_LOCKED(-2),
        NOT_FOUND(-3),
        CRYPTO(-4),
        DATABASE(-5),
        IO(-6),
        ALREADY_UNLOCKED(-7),
        INVALID_PASSWORD(-8),
        NOT_INITIALIZED(-9),
        BIOMETRIC(-10),
        TOTP(-11),
        SYNC(-12),
        OUT_OF_MEMORY(-13),
        ABI_UNSUPPORTED(-14),
        PANIC(-15),
        UNKNOWN(-99);

        companion object {
            fun fromValue(value: Int): ErrorCode {
                return values().firstOrNull { it.value == value } ?: UNKNOWN
            }
        }
    }

    // ==========================================================================
    // Vault Management
    // ==========================================================================

    /**
     * Create a new vault or unlock existing vault
     * Returns true on success, false on failure
     */
    suspend fun initVault(vaultPath: String, masterPassword: String): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val handle = nativeInit(vaultPath, masterPassword)
                if (handle != 0L) {
                    nativeHandle = handle
                    true
                } else {
                    false
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to initialize vault", e)
                false
            }
        }
    }

    /**
     * Check if vault is unlocked
     */
    suspend fun isUnlocked(): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                nativeIsUnlocked(nativeHandle)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to check unlock status", e)
                false
            }
        }
    }

    /**
     * Lock the vault
     */
    suspend fun lockVault(): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val handle = nativeHandle
                val result = nativeLock(handle)
                if (result == ErrorCode.SUCCESS.value) {
                    // WBS-804 review fix: locking does NOT destroy the native
                    // vault — destroy the handle explicitly so the registry
                    // entry and its VaultManager (open SQLite handle) are
                    // freed instead of leaking on every lock->unlock cycle.
                    nativeDestroy(handle)
                    nativeHandle = 0
                    true
                } else {
                    false
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to lock vault", e)
                false
            }
        }
    }

    /**
     * Destroy vault handle
     */
    fun destroyVault() {
        try {
            if (nativeHandle != 0L) {
                nativeDestroy(nativeHandle)
                nativeHandle = 0
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to destroy vault", e)
        }
    }

    // ==========================================================================
    // Entry Management
    // ==========================================================================

    /**
     * Add a new entry
     * Returns entry ID on success, null on failure
     */
    suspend fun addEntry(
        title: String,
        username: String,
        password: String,
        url: String = "",
        notes: String = ""
    ): String? {
        return withContext(Dispatchers.IO) {
            try {
                nativeAddEntry(nativeHandle, title, username, password, url, notes)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to add entry", e)
                null
            }
        }
    }

    /**
     * Get entry by ID
     * Returns Entry as JSON string, null on failure
     */
    suspend fun getEntry(entryId: String): Entry? {
        return withContext(Dispatchers.IO) {
            try {
                val jsonString = nativeGetEntry(nativeHandle, entryId)
                if (jsonString != null) {
                    json.decodeFromString<Entry>(jsonString)
                } else {
                    null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to get entry", e)
                null
            }
        }
    }

    /**
     * List all entries
     * Returns list of EntrySummary, empty on failure
     */
    suspend fun listEntries(): List<EntrySummary> {
        return withContext(Dispatchers.IO) {
            try {
                val jsonString = nativeListEntries(nativeHandle)
                if (jsonString != null) {
                    json.decodeFromString<List<EntrySummary>>(jsonString)
                } else {
                    emptyList()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to list entries", e)
                emptyList()
            }
        }
    }

    /**
     * Search entries
     */
    suspend fun searchEntries(query: String): List<EntrySummary> {
        return withContext(Dispatchers.IO) {
            try {
                val jsonString = nativeSearchEntries(nativeHandle, query)
                if (jsonString != null) {
                    json.decodeFromString<List<EntrySummary>>(jsonString)
                } else {
                    emptyList()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to search entries", e)
                emptyList()
            }
        }
    }

    /**
     * Delete entry
     */
    suspend fun deleteEntry(entryId: String): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val result = nativeDeleteEntry(nativeHandle, entryId)
                result == ErrorCode.SUCCESS.value
            } catch (e: Exception) {
                Log.e(TAG, "Failed to delete entry", e)
                false
            }
        }
    }

    /**
     * Update an existing entry (WBS-807: ATOMIC — one native call, one
     * vault write). A `null` field is left unchanged; an empty `url`/`notes`
     * clears that field. Replaces the old delete-then-add workaround in
     * [com.sentinelpass.data.VaultState], which lost entry history and could
     * race concurrent readers.
     */
    suspend fun updateEntry(
        entryId: String,
        title: String? = null,
        username: String? = null,
        password: String? = null,
        url: String? = null,
        notes: String? = null
    ): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val result = nativeUpdateEntry(
                    nativeHandle, entryId, title, username, password, url, notes
                )
                result == ErrorCode.SUCCESS.value
            } catch (e: Exception) {
                Log.e(TAG, "Failed to update entry", e)
                false
            }
        }
    }

    // ==========================================================================
    // TOTP
    // ==========================================================================

    /**
     * Generate TOTP code
     * Returns code string, null on failure
     */
    suspend fun generateTotp(entryId: String): TotpCode? {
        return withContext(Dispatchers.IO) {
            try {
                val codeString = nativeGenerateTotp(nativeHandle, entryId)
                if (codeString != null) {
                    // Format: "code,seconds_remaining"
                    val parts = codeString.split(",")
                    if (parts.size == 2) {
                        TotpCode(
                            code = parts[0],
                            secondsRemaining = parts[1].toUIntOrNull() ?: 30u
                        )
                    } else {
                        TotpCode(codeString, 30u)
                    }
                } else {
                    null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to generate TOTP", e)
                null
            }
        }
    }

    // ==========================================================================
    // Password Generation
    // ==========================================================================

    /**
     * Generate random password
     */
    suspend fun generatePassword(length: Int, includeSymbols: Boolean): String? {
        return withContext(Dispatchers.IO) {
            try {
                nativeGeneratePassword(nativeHandle, length, includeSymbols)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to generate password", e)
                null
            }
        }
    }

    /**
     * Check password strength
     * Returns "score,description" format, null on failure
     */
    suspend fun checkStrength(password: String): PasswordAnalysis? {
        return withContext(Dispatchers.IO) {
            try {
                val resultString = nativeCheckStrength(nativeHandle, password)
                if (resultString != null) {
                    // Format: "score,description"
                    val parts = resultString.split(",")
                    if (parts.size >= 2) {
                        PasswordAnalysis(
                            score = parts[0].toIntOrNull() ?: 0,
                            description = parts[1]
                        )
                    } else {
                        null
                    }
                } else {
                    null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to check password strength", e)
                null
            }
        }
    }

    // ==========================================================================
    // Biometric
    // ==========================================================================

    /**
     * Check if biometric key exists
     */
    suspend fun hasBiometricKey(): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                nativeBiometricHasKey(nativeHandle)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to check biometric key", e)
                false
            }
        }
    }

    /**
     * Remove biometric key
     */
    suspend fun removeBiometricKey(): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val result = nativeBiometricRemoveKey(nativeHandle)
                result == ErrorCode.SUCCESS.value
            } catch (e: Exception) {
                Log.e(TAG, "Failed to remove biometric key", e)
                false
            }
        }
    }

    /**
     * Unlock with biometric
     */
    suspend fun unlockWithBiometric(): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val result = nativeBiometricUnlock(nativeHandle)
                result == ErrorCode.SUCCESS.value
            } catch (e: Exception) {
                Log.e(TAG, "Failed to unlock with biometric", e)
                false
            }
        }
    }

    // ==========================================================================
    // JNI Declarations
    // ==========================================================================

    /**
     * ABI contract version reported by the loaded bridge library (WBS-803).
     * Checked against [EXPECTED_ABI_VERSION] in the instance init block.
     */
    private external fun nativeAbiVersion(): Int

    private external fun nativeInit(
        vaultPath: String,
        masterPassword: String
    ): Long

    private external fun nativeDestroy(handle: Long)

    private external fun nativeIsUnlocked(handle: Long): Boolean

    private external fun nativeLock(handle: Long): Int

    private external fun nativeAddEntry(
        handle: Long,
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String
    ): String?

    private external fun nativeGetEntry(
        handle: Long,
        entryId: String
    ): String?

    private external fun nativeListEntries(
        handle: Long
    ): String?

    private external fun nativeSearchEntries(
        handle: Long,
        query: String
    ): String?

    private external fun nativeDeleteEntry(
        handle: Long,
        entryId: String
    ): Int

    private external fun nativeUpdateEntry(
        handle: Long,
        entryId: String,
        title: String?,
        username: String?,
        password: String?,
        url: String?,
        notes: String?
    ): Int

    private external fun nativeGenerateTotp(
        handle: Long,
        entryId: String
    ): String?

    private external fun nativeGeneratePassword(
        handle: Long,
        length: Int,
        includeSymbols: Boolean
    ): String?

    private external fun nativeCheckStrength(
        handle: Long,
        password: String
    ): String?

    private external fun nativeBiometricHasKey(
        handle: Long
    ): Boolean

    private external fun nativeBiometricRemoveKey(
        handle: Long
    ): Int

    private external fun nativeBiometricUnlock(
        handle: Long
    ): Int
}

// ==========================================================================
// Data Models
// ==========================================================================

@Serializable
data class Entry(
    val id: String? = null,
    val title: String,
    val username: String,
    val password: String,
    val url: String? = null,
    val notes: String? = null,
    val createdAt: String? = null,
    val modifiedAt: String? = null,
    val favorite: Boolean = false
)

@Serializable
data class EntrySummary(
    val id: String,
    val title: String,
    val username: String,
    val favorite: Boolean = false
)

data class TotpCode(
    val code: String,
    val secondsRemaining: UInt
)

data class PasswordAnalysis(
    val score: Int,
    val description: String
) {
    val strengthColor: Int
        get() = when (score) {
            0, 1 -> android.graphics.Color.parseColor("#EF4444") // Red
            2 -> android.graphics.Color.parseColor("#F97316") // Orange
            3 -> android.graphics.Color.parseColor("#EAB308") // Yellow
            else -> android.graphics.Color.parseColor("#22C55E") // Green
        }

    val strengthText: String
        get() = when (score) {
            0, 1 -> "Very Weak"
            2 -> "Weak"
            3 -> "Fair"
            else -> "Strong"
        }
}
