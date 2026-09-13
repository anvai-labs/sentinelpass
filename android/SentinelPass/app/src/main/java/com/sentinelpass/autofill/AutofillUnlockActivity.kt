package com.sentinelpass.autofill

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.autofill.AutofillManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.sentinelpass.Entry
import com.sentinelpass.data.VaultState
import com.sentinelpass.ui.enablePrivacyCover
import kotlinx.coroutines.launch

/**
 * WBS-813: transparent activity behind the autofill AUTH dataset.
 *
 * Flow: the system launches this activity when the user taps the auth
 * dataset. If the vault is locked, the master password is prompted here;
 * afterwards (or immediately if already unlocked) a picker lists entries
 * matching the fill target — falling back to a searchable full-vault list.
 * The chosen entry is returned as a FillResponse via
 * [AutofillManager.EXTRA_AUTHENTICATION_RESULT]; cancellation simply
 * finishes with RESULT_CANCELED (the framework default).
 *
 * The master-password field here is never autofilled by our own service
 * (self-fill guard in [FormParser]).
 *
 * NOTE: biometric (platform-slot) unlock is deliberately NOT offered in the
 * autofill path yet — the slot flow needs a FragmentActivity +
 * BiometricPrompt round trip inside a translucent overlay; master-password
 * unlock keeps this surface small. Not a security regression: the vault
 * stays locked unless the user explicitly unlocks it here.
 */
class AutofillUnlockActivity : ComponentActivity() {

    private val webDomain: String? by lazy {
        intent.getStringExtra(AutofillResponseBuilder.EXTRA_WEB_DOMAIN)
    }
    private val appPackage: String? by lazy {
        intent.getStringExtra(AutofillResponseBuilder.EXTRA_APP_PACKAGE)
    }
    @Suppress("DEPRECATION")
    private val usernameId: android.view.autofill.AutofillId? by lazy {
        intent.getParcelableExtra(AutofillResponseBuilder.EXTRA_USERNAME_ID)
    }
    @Suppress("DEPRECATION")
    private val passwordId: android.view.autofill.AutofillId? by lazy {
        intent.getParcelableExtra(AutofillResponseBuilder.EXTRA_PASSWORD_ID)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Always-on concealment: this overlay can display vault usernames.
        enablePrivacyCover()

        setContent {
            MaterialTheme {
                Surface(color = MaterialTheme.colorScheme.surface.copy(alpha = 0.97f)) {
                    AutofillAuthScreen(
                        vaultState = VaultState.current,
                        webDomain = webDomain,
                        appPackage = appPackage,
                        onEntryChosen = ::respondWithEntry,
                        onDismiss = ::finish
                    )
                }
            }
        }
    }

    /** Build the final response for the picked entry and hand it back. */
    private fun respondWithEntry(entry: Entry) {
        if (usernameId == null && passwordId == null) {
            finish()
            return
        }
        val response = AutofillResponseBuilder.buildMatchedResponse(
            this, listOf(entry), usernameId, passwordId
        )
        if (response == null) {
            finish()
            return
        }
        val result = Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)
        setResult(Activity.RESULT_OK, result)
        finish()
    }
}

@Composable
private fun AutofillAuthScreen(
    vaultState: VaultState,
    webDomain: String?,
    appPackage: String?,
    onEntryChosen: (Entry) -> Unit,
    onDismiss: () -> Unit
) {
    val scope = rememberCoroutineScope()
    val targetLabel = webDomain ?: appPackage ?: "this app"

    var unlockedNow by remember { mutableStateOf(vaultState.uiState.value.isUnlocked) }
    var masterPassword by remember { mutableStateOf("") }
    var unlockError by remember { mutableStateOf<String?>(null) }
    var unlocking by remember { mutableStateOf(false) }

    var matched by remember { mutableStateOf<List<Entry>>(emptyList()) }
    var searchQuery by remember { mutableStateOf("") }
    var searchResults by remember { mutableStateOf<List<Entry>?>(null) }

    if (!unlockedNow) {
        // ---- Step 1: master password unlock -------------------------------
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("SentinelPass", style = MaterialTheme.typography.titleLarge)
            Text(
                "Unlock to fill $targetLabel",
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
                TextButton(onClick = onDismiss, enabled = !unlocking) { Text("Cancel") }
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

    // ---- Step 2: pick an entry --------------------------------------------
    // Initial list: confident target matches; empty → use the search box.
    LaunchedEffect(Unit) {
        matched = AutofillResponseBuilder.selectMatchingEntries(vaultState, webDomain, appPackage)
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text("Fill for $targetLabel", style = MaterialTheme.typography.titleMedium)

        OutlinedTextField(
            value = searchQuery,
            onValueChange = { query ->
                searchQuery = query
                scope.launch {
                    // Search returns summaries; resolve full details so the
                    // list is one type and a tap needs no extra fetch.
                    searchResults =
                        if (query.isBlank()) null
                        else vaultState.searchEntries(query).mapNotNull { vaultState.getEntry(it.id) }
                }
            },
            label = { Text("Search all vault entries") },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )

        val listing: List<Entry> = searchResults ?: matched
        if (listing.isEmpty()) {
            Text(
                if (searchResults != null) "No entries match your search."
                else "No confident matches — search the vault above.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 320.dp)
            ) {
                items(listing, key = { it.id ?: it.title }) { entry ->
                    ListItem(
                        headlineContent = { Text(entry.title) },
                        supportingContent = { Text(entry.username) },
                        modifier = Modifier.clickable { onEntryChosen(entry) }
                    )
                }
            }
        }

        TextButton(onClick = onDismiss) { Text("Cancel") }
    }
}
