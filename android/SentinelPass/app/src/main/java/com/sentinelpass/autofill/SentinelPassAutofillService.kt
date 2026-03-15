package com.sentinelpass.autofill

import android.annotation.TargetApi
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest

/**
 * Autofill service for SentinelPass
 *
 * This service provides autofill functionality for password fields in apps.
 * Currently a stub implementation - full autofill integration is planned
 * for future development.
 */
@TargetApi(Build.VERSION_CODES.O)
class SentinelPassAutofillService : AutofillService() {

    /**
     * Called when the system needs to autofill a field
     */
    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        // Stub implementation - to be implemented with full vault integration
        // TODO: Implement autofill suggestions from vault
    }

    /**
     * Called when the user asks to save credentials
     */
    override fun onSaveRequest(
        request: SaveRequest,
        callback: SaveCallback
    ) {
        // Stub implementation - to be implemented with full vault integration
        // TODO: Implement credential save flow
    }
}
