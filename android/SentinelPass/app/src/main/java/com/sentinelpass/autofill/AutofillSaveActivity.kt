package com.sentinelpass.autofill

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.sentinelpass.data.VaultState
import com.sentinelpass.ui.enablePrivacyCover
import kotlinx.coroutines.launch

/**
 * WBS-813: transparent confirmation surface for credentials the user just
 * submitted in ANOTHER app (launched by [SentinelPassAutofillService.onSaveRequest]).
 *
 * Requires the vault to be unlocked before storing; if locked, the master
 * password is prompted in this same activity first. The captured values
 * travel only through the in-memory launch intent (standard autofill-save
 * practice) — they are never written to disk or logged, the activity is
 * excluded from recents, and FLAG_SECURE is always on.
 *
 * For web saves the entry URL is stored as https://<domain> so future fills
 * match it; for app saves the URL stays empty — the package→domain
 * heuristic is NOT persisted, because storing a guessed URL would make the
 * entry surface on the wrong web origin later.
 */
class AutofillSaveActivity : ComponentActivity() {

    companion object {
        const val EXTRA_USERNAME = "com.sentinelpass.autofill.SAVE_USERNAME"
        const val EXTRA_PASSWORD = "com.sentinelpass.autofill.SAVE_PASSWORD"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enablePrivacyCover()

        val username = intent.getStringExtra(EXTRA_USERNAME).orEmpty()
        val password = intent.getStringExtra(EXTRA_PASSWORD).orEmpty()
        val webDomain = intent.getStringExtra(AutofillResponseBuilder.EXTRA_WEB_DOMAIN)
        val appPackage = intent.getStringExtra(AutofillResponseBuilder.EXTRA_APP_PACKAGE)

        setContent {
            MaterialTheme {
                Surface(color = MaterialTheme.colorScheme.surface.copy(alpha = 0.97f)) {
                    AutofillSaveScreen(
                        vaultState = VaultState.current,
                        capturedUsername = username,
                        capturedPassword = password,
                        webDomain = webDomain,
                        appPackage = appPackage,
                        onDone = { saved ->
                            if (saved) {
                                Toast.makeText(this, "Credentials saved", Toast.LENGTH_SHORT).show()
                            }
                            finish()
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun AutofillSaveScreen(
    vaultState: VaultState,
    capturedUsername: String,
    capturedPassword: String,
    webDomain: String?,
    appPackage: String?,
    onDone: (saved: Boolean) -> Unit
) {
    val scope = rememberCoroutineScope()

    var unlockedNow by remember { mutableStateOf(vaultState.uiState.value.isUnlocked) }
    var masterPassword by remember { mutableStateOf("") }
    var unlockError by remember { mutableStateOf<String?>(null) }
    var unlocking by remember { mutableStateOf(false) }

    val defaultTitle = webDomain ?: appPackage ?: "Saved credential"
    var title by remember { mutableStateOf(defaultTitle) }
    var username by remember { mutableStateOf(capturedUsername) }
    var password by remember { mutableStateOf(capturedPassword) }
    var showPassword by remember { mutableStateOf(false) }
    var saving by remember { mutableStateOf(false) }
    var saveError by remember { mutableStateOf<String?>(null) }

    if (!unlockedNow) {
        // ---- Step 1: unlock (same activity, per WBS-813) ------------------
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("Save to SentinelPass", style = MaterialTheme.typography.titleLarge)
            Text(
                "Unlock the vault to save credentials for ${webDomain ?: appPackage ?: "this app"}",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedTextField(
                value = masterPassword,
                onValueChange = { masterPassword = it },
                label = { Text("Master Password") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true,
                enabled = !unlocking,
                modifier = Modifier.fillMaxWidth()
            )
            if (unlockError != null) {
                Text(
                    unlockError ?: "",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { onDone(false) }, enabled = !unlocking) { Text("Cancel") }
                Button(
                    onClick = {
                        unlocking = true
                        unlockError = null
                        scope.launch {
                            val ok = vaultState.unlockVaultAwait(masterPassword)
                            unlocking = false
                            if (ok) unlockedNow = true else unlockError = "Invalid master password"
                        }
                    },
                    enabled = masterPassword.isNotEmpty() && !unlocking
                ) {
                    if (unlocking) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Text("Unlock")
                    }
                }
            }
        }
        return
    }

    // ---- Step 2: confirm and store ------------------------------------------
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Save credential", style = MaterialTheme.typography.titleLarge)
        Text(
            "For ${webDomain ?: appPackage ?: "unknown target"}",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        OutlinedTextField(
            value = title,
            onValueChange = { title = it },
            label = { Text("Name") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = username,
            onValueChange = { username = it },
            label = { Text("Username") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            visualTransformation = if (showPassword) VisualTransformation.None
            else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            singleLine = true,
            trailingIcon = {
                IconButton(onClick = { showPassword = !showPassword }) {
                    Icon(
                        if (showPassword) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        contentDescription = "Toggle password visibility"
                    )
                }
            },
            modifier = Modifier.fillMaxWidth()
        )

        if (saveError != null) {
            Text(
                saveError ?: "",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = { onDone(false) }, enabled = !saving) { Text("Don't save") }
            Button(
                onClick = {
                    if (username.isBlank() || password.isBlank()) {
                        saveError = "Username and password are required"
                        return@Button
                    }
                    saving = true
                    saveError = null
                    scope.launch {
                        // Web targets persist https://<domain> (so fills match
                        // later); app targets persist no URL (the
                        // package→domain mapping is heuristic, not fact).
                        val url = webDomain?.let { "https://$it" }.orEmpty()
                        val id = vaultState.addEntryAwait(
                            title = title.ifBlank { defaultTitle },
                            username = username,
                            password = password,
                            url = url,
                            notes = ""
                        )
                        saving = false
                        if (id != null) onDone(true) else saveError = "Failed to save credentials"
                    }
                },
                enabled = !saving
            ) {
                if (saving) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text("Save")
                }
            }
        }
    }
}
