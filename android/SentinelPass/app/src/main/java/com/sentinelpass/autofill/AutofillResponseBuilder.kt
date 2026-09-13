package com.sentinelpass.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.service.autofill.SaveInfo
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.sentinelpass.Entry
import com.sentinelpass.EntrySummary
import com.sentinelpass.R
import com.sentinelpass.data.VaultState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * WBS-813: shared FillResponse/Dataset construction for the autofill
 * service AND the authentication/selection activities (the system requires
 * the activity launched from an auth dataset to hand back a fully built
 * [FillResponse] via [AutofillManager.EXTRA_AUTHENTICATION_RESULT], so the
 * building logic cannot live in the service alone).
 */
internal object AutofillResponseBuilder {

    // Intent extras exchanged between the service and the auth/picker
    // activities. Values are identifiers and domains only — entry secrets
    // are fetched from the vault at response-build time, never shipped
    // through the auth intent.
    const val EXTRA_WEB_DOMAIN = "com.sentinelpass.autofill.WEB_DOMAIN"
    const val EXTRA_APP_PACKAGE = "com.sentinelpass.autofill.APP_PACKAGE"
    const val EXTRA_USERNAME_ID = "com.sentinelpass.autofill.USERNAME_ID"
    const val EXTRA_PASSWORD_ID = "com.sentinelpass.autofill.PASSWORD_ID"

    /**
     * A Dataset that fills the username/password fields from [entry].
     * Each value gets its own setValue so password-only or username-only
     * forms still fill their available half.
     *
     * The RemoteViews presentation variants are "deprecated" only in the
     * sense that API 34 added a `Presentations` replacement — which does
     * not exist below API 34, so the RemoteViews path is the correct
     * minSdk-26 implementation, not legacy debt.
     */
    @Suppress("DEPRECATION")
    fun buildDataset(
        context: Context,
        entry: Entry,
        usernameId: AutofillId?,
        passwordId: AutofillId?
    ): Dataset? {
        if (usernameId == null && passwordId == null) return null
        val presentation = RemoteViews(context.packageName, R.layout.item_autofill_dataset)
        presentation.setTextViewText(R.id.autofill_entry_title, entry.title)
        presentation.setTextViewText(R.id.autofill_entry_username, entry.username)

        val builder = Dataset.Builder()
        if (usernameId != null) {
            builder.setValue(usernameId, AutofillValue.forText(entry.username), presentation)
        }
        if (passwordId != null) {
            builder.setValue(passwordId, AutofillValue.forText(entry.password), presentation)
        }
        return builder.build()
    }

    /**
     * The response offered while the vault is UNLOCKED and entries matched
     * the target with confidence.
     */
    fun buildMatchedResponse(
        context: Context,
        entries: List<Entry>,
        usernameId: AutofillId?,
        passwordId: AutofillId?
    ): FillResponse? {
        if (usernameId == null && passwordId == null) return null
        val response = FillResponse.Builder()
        var added = 0
        for (entry in entries) {
            val dataset = buildDataset(context, entry, usernameId, passwordId) ?: continue
            response.addDataset(dataset)
            added++
        }
        if (added == 0) return null
        buildSaveInfo(usernameId, passwordId)?.let { response.setSaveInfo(it) }
        return response.build()
    }

    /**
     * The single authentication dataset: tapping it launches [authIntent]
     * (the unlock/search activity), which replies with the final
     * [FillResponse] through [AutofillManager.EXTRA_AUTHENTICATION_RESULT].
     *
     * The PendingIntent MUST be mutable on S+ — the system attaches the
     * autofill context to it before launching.
     *
     * RemoteViews presentation: see the minSdk-26 note on [buildDataset].
     */
    @Suppress("DEPRECATION")
    fun buildAuthResponse(
        context: Context,
        authIntent: Intent,
        label: String,
        usernameId: AutofillId?,
        passwordId: AutofillId?
    ): FillResponse? {
        val ids = listOfNotNull(usernameId, passwordId)
        if (ids.isEmpty()) return null

        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            authIntent,
            PendingIntent.FLAG_MUTABLE
        )

        val presentation = RemoteViews(context.packageName, R.layout.item_autofill_dataset)
        presentation.setTextViewText(R.id.autofill_entry_title, label)
        presentation.setTextViewText(R.id.autofill_entry_username, "SentinelPass")

        // setAuthentication takes an IntentSender; PendingIntent is the
        // factory for one, not a subtype.
        return FillResponse.Builder()
            .setAuthentication(ids.toTypedArray(), pendingIntent.intentSender, presentation)
            .build()
    }

    /**
     * Save hint for the fields we filled, so the system can offer to save
     * updated credentials after the user submits the form. On API 26/27
     * SAVE_DATA_TYPE_USERNAME does not exist; PASSWORD alone is used there
     * (the username is attached as an optional id regardless).
     */
    private fun buildSaveInfo(usernameId: AutofillId?, passwordId: AutofillId?): SaveInfo? {
        val required = passwordId ?: usernameId ?: return null
        val optional = listOfNotNull(usernameId, passwordId).filter { it != required }
        val dataType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            SaveInfo.SAVE_DATA_TYPE_PASSWORD or SaveInfo.SAVE_DATA_TYPE_USERNAME
        } else {
            SaveInfo.SAVE_DATA_TYPE_PASSWORD
        }
        val builder = SaveInfo.Builder(dataType, arrayOf(required))
        if (optional.isNotEmpty()) {
            builder.setOptionalIds(optional.toTypedArray())
        }
        return builder.build()
    }

    /**
     * Fetch full entry details and match against the fill target. Vault
     * summaries carry no URL, so each candidate is decrypted via
     * [VaultState.getEntry] — bounded by
     * [AutofillDomainMatcher.MAX_DETAIL_FETCH] (bigger vaults skip straight
     * to the authenticated picker, keeping the fill path inside the system
     * deadline). Shared by the service's direct-match path and the unlock
     * activity's picker so both surfaces apply the SAME matching rules.
     */
    suspend fun selectMatchingEntries(
        vaultState: VaultState,
        webDomain: String?,
        appPackage: String?
    ): List<Entry> {
        if (webDomain.isNullOrBlank() && appPackage.isNullOrBlank()) return emptyList()
        val summaries: List<EntrySummary> = withContext(Dispatchers.IO) {
            vaultState.listEntriesNow()
        }
        if (summaries.isEmpty()) return emptyList()
        if (summaries.size > AutofillDomainMatcher.MAX_DETAIL_FETCH) return emptyList()

        val details = summaries.mapNotNull { summary ->
            withContext(Dispatchers.IO) { vaultState.getEntry(summary.id) }
        }
        return AutofillDomainMatcher.selectMatching(
            details, webDomain, appPackage, AutofillDomainMatcher.MAX_DIRECT_MATCHES
        )
    }
}
