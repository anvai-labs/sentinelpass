package com.sentinelpass.ui

import android.app.Activity
import android.view.WindowManager

/**
 * WBS-814: privacy cover for screenshot/recents concealment.
 *
 * FLAG_SECURE makes the window's surface non-capturable: the system shows a
 * blank surface in the recents thumbnail and blocks screenshots. Toggling
 * in onPause/onResume covers exactly the window where the app's content
 * could leak (recents snapshot, app-switch animation) while keeping
 * in-app screenshots impossible anyway whenever the cover is on.
 */
fun Activity.enablePrivacyCover() {
    window.setFlags(
        WindowManager.LayoutParams.FLAG_SECURE,
        WindowManager.LayoutParams.FLAG_SECURE
    )
}

fun Activity.disablePrivacyCover() {
    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
}
