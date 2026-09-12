package com.sentinelpass

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.compose.runtime.LaunchedEffect
import com.sentinelpass.ui.disablePrivacyCover
import com.sentinelpass.ui.enablePrivacyCover
import com.sentinelpass.ui.screens.LockScreen
import com.sentinelpass.ui.screens.SetupScreen
import com.sentinelpass.ui.screens.MainScreen
import com.sentinelpass.ui.theme.SentinelPassTheme
import com.sentinelpass.data.VaultState

/**
 * Main Activity for SentinelPass
 * Handles navigation between lock/setup/main screens
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SentinelPassTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    SentinelPassApp()
                }
            }
        }
    }

    /**
     * WBS-814 privacy cover: while the activity is not resumed its window
     * surface is captured for the recents/app-switch thumbnail — FLAG_SECURE
     * blanks that snapshot. Cleared again on resume.
     */
    override fun onPause() {
        super.onPause()
        enablePrivacyCover()
    }

    override fun onResume() {
        super.onResume()
        disablePrivacyCover()
    }
}

@Composable
fun SentinelPassApp(
    vaultState: VaultState = VaultState.current,
    navController: NavHostController = rememberNavController()
) {
    val uiState by vaultState.uiState.collectAsState()

    // WBS-814: when the vault locks (manual, background auto-lock from
    // ProcessLifecycleOwner, or slot disable), return the UI to the lock
    // screen. NavHost only evaluates startDestination once, so without this
    // the auto-locked app would sit on the (now dead) main screen.
    LaunchedEffect(uiState.hasVault, uiState.isUnlocked) {
        if (uiState.hasVault && !uiState.isUnlocked) {
            navController.navigate("lock") {
                popUpTo(0) { inclusive = true }
            }
        }
    }

    NavHost(
        navController = navController,
        startDestination = when {
            !uiState.hasVault -> "setup"
            !uiState.isUnlocked -> "lock"
            else -> "main"
        }
    ) {
        composable("setup") {
            SetupScreen(
                vaultState = vaultState,
                onNavigateToLock = {
                    navController.navigate("lock") {
                        popUpTo("setup") { inclusive = true }
                    }
                }
            )
        }

        composable("lock") {
            LockScreen(
                onUnlockSuccess = {
                    navController.navigate("main") {
                        popUpTo("lock") { inclusive = true }
                    }
                }
            )
        }

        composable("main") {
            MainScreen(
                onLock = {
                    vaultState.lockVault()
                    navController.navigate("lock") {
                        popUpTo("main") { inclusive = true }
                    }
                }
            )
        }
    }
}
