package com.sentinelpass.data

import android.content.Context
import android.content.SharedPreferences
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sentinelpass.Entry
import com.sentinelpass.EntrySummary
import com.sentinelpass.PasswordAnalysis
import com.sentinelpass.TotpCode
import com.sentinelpass.VaultBridge
import com.sentinelpass.slot.BiometricKeystore
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID

/**
 * Manages vault state and operations
 * Single instance accessible via VaultState.current
 */
class VaultState private constructor(private val context: Context) : ViewModel() {

    private val vaultFile: File
        get() = File(context.filesDir, "sentinelpass_vault.db")

    private val prefs: SharedPreferences
        get() = context.getSharedPreferences("sentinelpass", Context.MODE_PRIVATE)

    private var vaultBridge: VaultBridge? = null

    // UI State
    private val _uiState = MutableStateFlow(VaultUiState())
    val uiState: StateFlow<VaultUiState> = _uiState.asStateFlow()

    // Entries list
    private val _entries = MutableStateFlow<List<EntrySummary>>(emptyList())
    val entries: StateFlow<List<EntrySummary>> = _entries.asStateFlow()

    // Auto-lock timer
    private var autoLockJob: kotlinx.coroutines.Job? = null
    private val autoLockDelayMillis = 5 * 60 * 1000L // 5 minutes

    init {
        _uiState.value = _uiState.value.copy(
            hasVault = vaultFile.exists()
        )
    }

    // ==========================================================================
    // Vault Management
    // ==========================================================================

    /**
     * Create a new vault
     */
    fun createVault(masterPassword: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)

            val result = withContext(Dispatchers.IO) {
                try {
                    val bridge = VaultBridge(context)
                    val success = bridge.initVault(vaultFile.absolutePath, masterPassword)
                    if (success) {
                        vaultBridge = bridge
                        prefs.edit().putBoolean("vault_created", true).apply()
                    }
                    success
                } catch (e: IllegalStateException) {
                    // Bridge refused to operate (ABI handshake / library load
                    // failure) — fail closed into UI error state, no crash.
                    android.util.Log.e("VaultState", "Bridge unavailable", e)
                    false
                }
            }

            _uiState.value = _uiState.value.copy(
                isLoading = false,
                isUnlocked = result,
                hasVault = result
            )

            if (result) {
                loadEntries()
            }
        }
    }

    /**
     * Unlock existing vault
     */
    fun unlockVault(masterPassword: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)

            val result = withContext(Dispatchers.IO) {
                try {
                    val bridge = VaultBridge(context)
                    val success = bridge.initVault(vaultFile.absolutePath, masterPassword)
                    if (success) {
                        vaultBridge = bridge
                    }
                    success
                } catch (e: IllegalStateException) {
                    android.util.Log.e("VaultState", "Bridge unavailable", e)
                    false
                }
            }

            _uiState.value = _uiState.value.copy(
                isLoading = false,
                isUnlocked = result,
                error = if (!result) "Invalid master password" else null
            )

            if (result) {
                loadEntries()
            }
        }
    }

    /**
     * Unlock with biometric (WBS-812): routes to the Keystore-bound slot.
     * `activity` hosts the BiometricPrompt; pass it from the Compose tree
     * (`LocalContext.current`). Requires an enrolled platform slot —
     * otherwise this fails closed to the master-password path.
     */
    fun unlockWithBiometric(activity: FragmentActivity) {
        if (!hasPlatformSlotBlob()) {
            _uiState.value = _uiState.value.copy(
                error = "Biometric unlock is not enrolled"
            )
            return
        }
        unlockWithBiometricSlot(activity)
    }

    /**
     * Lock the vault
     */
    fun lockVault() {
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                vaultBridge?.lockVault()
            }
            vaultBridge = null
            _uiState.value = VaultUiState(hasVault = true)
            _entries.value = emptyList()
        }
    }

    // ==========================================================================
    // Entry Management
    // ==========================================================================

    /**
     * Load all entries from vault
     */
    fun loadEntries() {
        viewModelScope.launch {
            val entries = withContext(Dispatchers.IO) {
                vaultBridge?.listEntries() ?: emptyList()
            }
            _entries.value = entries
        }
    }

    /**
     * Get full entry details by ID
     */
    suspend fun getEntry(id: String): Entry? {
        return withContext(Dispatchers.IO) {
            vaultBridge?.getEntry(id)
        }
    }

    /**
     * Add new entry
     */
    fun addEntry(
        title: String,
        username: String,
        password: String,
        url: String = "",
        notes: String = ""
    ) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)

            val result = withContext(Dispatchers.IO) {
                vaultBridge?.addEntry(title, username, password, url, notes)
            }

            _uiState.value = _uiState.value.copy(
                isLoading = false,
                error = if (result == null) "Failed to add entry" else null
            )

            if (result != null) {
                loadEntries()
            }
        }
    }

    /**
     * Update entry atomically (WBS-807): one native call via
     * [VaultBridge.updateEntry] — replaces the previous delete-then-add
     * workaround that lost entry history (created/entry id) and could race
     * concurrent readers (TD-MOB-04).
     */
    fun updateEntry(
        id: String,
        title: String,
        username: String,
        password: String,
        url: String = "",
        notes: String = ""
    ) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)

            val result = vaultBridge?.updateEntry(
                entryId = id,
                title = title,
                username = username,
                password = password,
                url = url,
                notes = notes
            )

            _uiState.value = _uiState.value.copy(
                isLoading = false,
                error = if (result != true) "Failed to update entry" else null
            )

            if (result == true) {
                loadEntries()
            }
        }
    }

    // ==========================================================================
    // Platform slot (WBS-812): Keystore-bound biometric unlock
    // ==========================================================================

    private val slotJson = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }

    private val slotBlobFile: java.io.File
        get() = java.io.File(context.filesDir, "platform_slot.blob")

    fun hasPlatformSlotBlob(): Boolean = slotBlobFile.exists()

    /**
     * ENABLE the Keystore-bound slot (vault must be unlocked). Draws a
     * challenge from the bridge, signs it TWICE through the auth-bound
     * Keystore key (two BiometricPrompt gates — the CryptoObject makes the
     * prompt the crypto authorization), seals the DEK, and persists the
     * NON-SECRET blob in app-private FILE storage (never SharedPreferences).
     */
    fun enableBiometricSlot(activity: FragmentActivity) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)
            val ok = withContext(Dispatchers.IO) {
                try {
                    if (vaultBridge == null) return@withContext false
                    BiometricKeystore.ensureKey()
                    val binding = vaultFile.absolutePath

                    val challenge = vaultBridge?.slotChallenge() ?: return@withContext false
                    val sigA = BiometricKeystore.signHex(activity, challenge, "Enable biometric unlock (1 of 2)")
                        ?: return@withContext false
                    val sigB = BiometricKeystore.signHex(activity, challenge, "Enable biometric unlock (2 of 2)")
                        ?: return@withContext false

                    val blob = vaultBridge?.slotSeal(challenge, sigA, sigB, binding)
                        ?: return@withContext false
                    if (!vaultBridge!!.slotHasBlob(blob)) return@withContext false

                    slotBlobFile.writeText(blob)
                    true
                } catch (e: Exception) {
                    android.util.Log.e("VaultState", "Failed to enable platform slot", e)
                    false
                }
            }
            _uiState.value = _uiState.value.copy(
                isLoading = false,
                error = if (!ok) "Failed to enable biometric unlock" else null
            )
        }
    }

    /**
     * DISABLE: delete the at-rest blob AND the Keystore key, in that order —
     * losing the blob alone leaves a live key with nothing to open (harmless),
     * but losing the key alone would leave an unopenable blob (fail-closed
     * noise). Order matters for hygiene, not safety.
     */
    fun disableBiometricSlot() {
        slotBlobFile.delete()
        BiometricKeystore.deleteKey()
    }

    /**
     * UNLOCK from the platform slot: signs the blob's challenge through the
     * auth-bound key (ONE gate) and lets the bridge open the vault with the
     * released DEK. Any refusal/cancellation fails closed to the master-
     * password screen.
     */
    fun unlockWithBiometricSlot(activity: FragmentActivity) {
        viewModelScope.launch {
            if (!hasPlatformSlotBlob()) return@launch
            _uiState.value = _uiState.value.copy(isLoading = true)
            val ok = withContext(Dispatchers.IO) {
                try {
                    val blob = slotBlobFile.readText()
                    val binding = vaultFile.absolutePath
                    // Hello semantics (WBS-710 precedent): the gate signs the
                    // BLOB'S STORED challenge — reproducing the enable-time
                    // signature is what reconstructs the wrap key. A fresh
                    // challenge would produce an unusable signature; the GCM
                    // tag would (correctly) refuse it.
                    val challenge = slotJson.decodeFromString<SlotBlob>(blob).challengeHex
                    val sig = BiometricKeystore.signHex(activity, challenge, "Unlock SentinelPass")
                        ?: return@withContext false
                    vaultBridge?.slotUnlock(binding, blob, sig, binding) == true
                } catch (e: Exception) {
                    android.util.Log.e("VaultState", "Slot unlock failed", e)
                    false
                }
            }
            _uiState.value = _uiState.value.copy(
                isLoading = false,
                isUnlocked = ok,
                error = if (!ok) "Biometric unlock failed" else null
            )
            if (ok) loadEntries()
        }
    }

    /**
     * Delete entry
     */
    fun deleteEntry(id: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)

            val result = withContext(Dispatchers.IO) {
                vaultBridge?.deleteEntry(id) ?: false
            }

            _uiState.value = _uiState.value.copy(
                isLoading = false,
                error = if (!result) "Failed to delete entry" else null
            )

            if (result) {
                loadEntries()
            }
        }
    }

    /**
     * Search entries
     */
    suspend fun searchEntries(query: String): List<EntrySummary> {
        return withContext(Dispatchers.IO) {
            vaultBridge?.searchEntries(query) ?: emptyList()
        }
    }

    // ==========================================================================
    // TOTP
    // ==========================================================================

    /**
     * Generate TOTP code for entry
     */
    suspend fun generateTotp(entryId: String): TotpCode? {
        return withContext(Dispatchers.IO) {
            vaultBridge?.generateTotp(entryId)
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
            vaultBridge?.generatePassword(length, includeSymbols)
        }
    }

    /**
     * Check password strength
     */
    suspend fun checkPasswordStrength(password: String): PasswordAnalysis? {
        return withContext(Dispatchers.IO) {
            vaultBridge?.checkStrength(password)
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
            hasPlatformSlotBlob()
        }
    }

    // ==========================================================================
    // Auto-Lock
    // ==========================================================================

    /**
     * Schedule auto-lock after delay
     */
    fun scheduleAutoLock() {
        autoLockJob?.cancel()
        autoLockJob = viewModelScope.launch {
            delay(autoLockDelayMillis)
            if (_uiState.value.isUnlocked) {
                lockVault()
            }
        }
    }

    /**
     * Check and execute auto-lock if scheduled
     */
    fun checkAutoLock() {
        // Auto-lock is handled by the scheduleAutoLock coroutine
        // This is called when app returns from foreground
    }

    override fun onCleared() {
        super.onCleared()
        vaultBridge?.destroyVault()
    }

    companion object {
        @Volatile
        private var INSTANCE: VaultState? = null

        fun initialize(context: Context) {
            if (INSTANCE == null) {
                INSTANCE = VaultState(context.applicationContext)
            }
        }

        val current: VaultState
            get() = INSTANCE ?: throw IllegalStateException("VaultState not initialized")
    }
}

/** Parsed subset of the NON-SECRET platform-slot blob (WBS-812). */
@kotlinx.serialization.Serializable
private data class SlotBlob(
    val version: Int,
    @kotlinx.serialization.SerialName("key_name") val keyName: String,
    @kotlinx.serialization.SerialName("challenge_hex") val challengeHex: String
)

/**
 * UI State for vault
 */
data class VaultUiState(
    val hasVault: Boolean = false,
    val isUnlocked: Boolean = false,
    val isLoading: Boolean = false,
    val error: String? = null
)
