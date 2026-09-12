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
     * Unlock with biometric
     */
    fun unlockWithBiometric() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)

            val result = withContext(Dispatchers.IO) {
                vaultBridge?.unlockWithBiometric() ?: false
            }

            _uiState.value = _uiState.value.copy(
                isLoading = false,
                isUnlocked = result,
                error = if (!result) "Biometric unlock failed" else null
            )

            if (result) {
                loadEntries()
            }
        }
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
            vaultBridge?.hasBiometricKey() ?: false
        }
    }

    /**
     * Remove biometric key
     */
    fun disableBiometric() {
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                vaultBridge?.removeBiometricKey()
            }
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

/**
 * UI State for vault
 */
data class VaultUiState(
    val hasVault: Boolean = false,
    val isUnlocked: Boolean = false,
    val isLoading: Boolean = false,
    val error: String? = null
)
