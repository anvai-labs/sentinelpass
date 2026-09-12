package com.sentinelpass.autofill

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.util.Log
import com.sentinelpass.data.VaultState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.runBlocking

/**
 * WBS-813: real autofill service.
 *
 * FILL: parses the assisted structure for a username/password pair. When the
 * vault is unlocked, entries that confidently match the target (registrable
 * web domain, or the package→domain heuristic — see
 * [AutofillDomainMatcher]) are offered as datasets. When nothing matches
 * with confidence, or the vault is locked, a single AUTH dataset is offered
 * that opens [AutofillUnlockActivity] (master-password unlock if needed,
 * then search/pick), which replies with the final FillResponse.
 *
 * SAVE: captures the submitted username/password values and hands them to
 * [AutofillSaveActivity] (transparent) for confirmation. If the vault is
 * locked the same activity prompts for the master password before storing.
 *
 * Timing: the system bounds onFillRequest to a few seconds. All vault work
 * below is therefore hard-capped: direct entry-detail fetching stops at
 * [AutofillDomainMatcher.MAX_DETAIL_FETCH] entries and every bridge call
 * runs under [FILL_DEADLINE_MILLIS]. On any failure the service responds
 * with a null FillResponse (system treats it as "nothing to autofill") —
 * it must never crash, block past the deadline, or leak vault contents.
 *
 * Self-fill guard: requests whose fields belong to SentinelPass's own
 * package are refused in [FormParser] (a password manager must not try to
 * autofill or save from its own unlock UI).
 */
class SentinelPassAutofillService : AutofillService() {

    companion object {
        private const val TAG = "SentinelPassAutofill"

        /**
         * Upper bound for all vault work inside a fill request. The platform
         * fill timeout is larger (and undisclosed); staying well under it
         * with a null response on expiry is the fail-closed behavior.
         */
        private const val FILL_DEADLINE_MILLIS = 3_000L

        const val LABEL_UNLOCK = "Unlock SentinelPass to fill"
        const val LABEL_SEARCH = "Search SentinelPass vault"
    }

    /**
     * Called when the system needs to autofill a field.
     */
    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        if (cancellationSignal.isCanceled) return

        val structure: AssistStructure =
            request.fillContexts.lastOrNull()?.structure ?: run {
                callback.onSuccess(null)
                return
            }

        val form = FormParser.parseFillTarget(structure, packageName)
        if (form == null || (form.username == null && form.password == null)) {
            callback.onSuccess(null)
            return
        }

        try {
            val vaultState = VaultState.current
            val response: FillResponse? = runBlocking {
                withTimeoutOrNull(FILL_DEADLINE_MILLIS) {
                    withContext(Dispatchers.IO) { buildFillResponse(vaultState, form) }
                }
            }
            if (cancellationSignal.isCanceled) return
            callback.onSuccess(response)
        } catch (t: Throwable) {
            // VaultState uninitialized, bridge unavailable, timeout — any
            // failure degrades to "no autofill available", never a crash.
            Log.e(TAG, "onFillRequest failed; declining to autofill", t)
            try {
                callback.onSuccess(null)
            } catch (_: Exception) {
                // The system may have torn the session down already.
            }
        }
    }

    /**
     * Called when the user asks to save credentials.
     */
    override fun onSaveRequest(
        request: SaveRequest,
        callback: SaveCallback
    ) {
        try {
            val structure = request.fillContexts.lastOrNull()?.structure
            val form = structure?.let { FormParser.parseSaveForm(it, packageName) }
            if (form?.password.isNullOrBlank()) {
                // Nothing submittable captured — acknowledge without acting.
                acknowledge(callback)
                return
            }

            val intent = Intent(this, AutofillSaveActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(AutofillResponseBuilder.EXTRA_WEB_DOMAIN, form?.webDomain)
                putExtra(AutofillResponseBuilder.EXTRA_APP_PACKAGE, form?.appPackage)
                putExtra(AutofillSaveActivity.EXTRA_USERNAME, form?.username)
                putExtra(AutofillSaveActivity.EXTRA_PASSWORD, form?.password)
            }
            startActivity(intent)
            acknowledge(callback)
        } catch (t: Throwable) {
            Log.e(TAG, "onSaveRequest failed", t)
            acknowledge(callback)
        }
    }

    /**
     * The save UI is our own activity from here on; the framework's save
     * request is complete. API note: the legacy `success()`/`failure()`
     * pair was REMOVED from the compileSdk-34 stubs (but still exists in
     * older platform builds), while `onSuccess()`/`onFailure()` do not
     * exist on all minSdk-26..32 devices — so T+ uses the new methods and
     * older devices reach the legacy ones reflectively (fail-safe: any
     * reflection miss is swallowed; a declined save is not an error the
     * client app can act on anyway).
     */
    private fun acknowledge(callback: SaveCallback, failureMessage: String? = null) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                if (failureMessage != null) callback.onFailure(failureMessage)
                else callback.onSuccess()
            } else {
                if (failureMessage != null) {
                    callback.javaClass
                        .getMethod("failure", CharSequence::class.java)
                        .invoke(callback, failureMessage)
                } else {
                    callback.javaClass.getMethod("success").invoke(callback)
                }
            }
        } catch (_: Exception) {
        }
    }

    // ------------------------------------------------------------------
    // Fill response assembly (runs under the fill deadline)
    // ------------------------------------------------------------------

    private suspend fun buildFillResponse(
        vaultState: VaultState,
        form: FormParser.ParsedFillForm
    ): FillResponse? {
        val unlocked = vaultState.uiState.value.isUnlocked
        val authIntent = Intent(this, AutofillUnlockActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra(AutofillResponseBuilder.EXTRA_WEB_DOMAIN, form.webDomain)
            putExtra(AutofillResponseBuilder.EXTRA_APP_PACKAGE, form.appPackage)
            putExtra(AutofillResponseBuilder.EXTRA_USERNAME_ID, form.username?.autofillId)
            putExtra(AutofillResponseBuilder.EXTRA_PASSWORD_ID, form.password?.autofillId)
        }

        if (!unlocked) {
            return AutofillResponseBuilder.buildAuthResponse(
                this, authIntent, LABEL_UNLOCK,
                form.username?.autofillId, form.password?.autofillId
            )
        }

        // Unlocked: try a confident direct match first.
        val matches = AutofillResponseBuilder.selectMatchingEntries(
            vaultState, form.webDomain, form.appPackage
        )
        val direct = if (matches.isNotEmpty()) {
            AutofillResponseBuilder.buildMatchedResponse(
                this, matches, form.username?.autofillId, form.password?.autofillId
            )
        } else null
        if (direct != null) return direct

        // Unlocked but nothing matched with confidence — offer the
        // authenticated search-all picker rather than guessing.
        return AutofillResponseBuilder.buildAuthResponse(
            this, authIntent, LABEL_SEARCH,
            form.username?.autofillId, form.password?.autofillId
        )
    }
}
