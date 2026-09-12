package com.sentinelpass

import android.app.Application
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.sentinelpass.data.VaultState

/**
 * SentinelPass Application class
 * Initializes app-wide state and lifecycle observers
 */
class SentinelPassApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // Initialize vault state
        VaultState.initialize(this)

        // Set up app background/foreground detection
        ProcessLifecycleOwner.get().lifecycle.addObserver(AppLifecycleObserver())
    }

    /**
     * Lifecycle observer for detecting app background/foreground.
     * WBS-814 background auto-lock, wired to the single timeout in
     * [VaultState.AUTO_LOCK_TIMEOUT_MS]:
     * - onStop (app left the foreground): arm the auto-lock timer. If the
     *   user stays away, [VaultState.lockVault] fires — which locks AND
     *   destroys the native handle.
     * - onStart (app returned before the timeout): DISARM the timer so the
     *   vault is not locked mid-session during active use.
     */
    class AppLifecycleObserver : DefaultLifecycleObserver {
        private var wasInBackground = false

        override fun onStart(owner: LifecycleOwner) {
            if (wasInBackground) {
                wasInBackground = false
                VaultState.current.cancelScheduledAutoLock()
            }
        }

        override fun onStop(owner: LifecycleOwner) {
            wasInBackground = true
            VaultState.current.scheduleAutoLock()
        }
    }
}
