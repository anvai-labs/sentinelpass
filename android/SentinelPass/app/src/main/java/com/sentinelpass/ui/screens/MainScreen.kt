package com.sentinelpass.ui.screens

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.NavController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.sentinelpass.data.VaultState
import com.sentinelpass.ui.screens.entries.EntriesListScreen
import com.sentinelpass.ui.screens.entries.AddEntryScreen
import com.sentinelpass.ui.screens.entries.EntryDetailScreen
import com.sentinelpass.ui.screens.totp.TotpListScreen
import com.sentinelpass.ui.screens.generator.GeneratorScreen
import com.sentinelpass.ui.screens.settings.SettingsScreen

/**
 * Main Screen - Tab navigation for unlocked vault
 */
@Composable
fun MainScreen(
    vaultState: VaultState = VaultState.current,
    onLock: () -> Unit
) {
    val navController = rememberNavController()
    var selectedTab by remember { mutableStateOf(0) }

    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = {
                        selectedTab = 0
                        navController.navigate("entries") {
                            popUpTo("entries") { inclusive = true }
                        }
                    },
                    icon = { Icon(Icons.Default.Key, contentDescription = null) },
                    label = { Text("Passwords") }
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = {
                        selectedTab = 1
                        navController.navigate("totp") {
                            popUpTo("totp") { inclusive = true }
                        }
                    },
                    icon = { Icon(Icons.Default.AccessTime, contentDescription = null) },
                    label = { Text("TOTP") }
                )
                NavigationBarItem(
                    selected = selectedTab == 2,
                    onClick = {
                        selectedTab = 2
                        navController.navigate("generator") {
                            popUpTo("generator") { inclusive = true }
                        }
                    },
                    icon = { Icon(Icons.Default.Casino, contentDescription = null) },
                    label = { Text("Generate") }
                )
                NavigationBarItem(
                    selected = selectedTab == 3,
                    onClick = {
                        selectedTab = 3
                        navController.navigate("settings") {
                            popUpTo("settings") { inclusive = true }
                        }
                    },
                    icon = { Icon(Icons.Default.Settings, contentDescription = null) },
                    label = { Text("Settings") }
                )
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = "entries",
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            composable("entries") {
                EntriesListScreen(
                    vaultState = vaultState,
                    onEntryClick = { entryId ->
                        navController.navigate("entry/$entryId")
                    },
                    onAddEntry = {
                        navController.navigate("add_entry")
                    },
                    modifier = Modifier
                )
            }

            composable("entry/{entryId}") { backStackEntry ->
                val entryId = backStackEntry.arguments?.getString("entryId") ?: return@composable
                EntryDetailScreen(
                    entryId = entryId,
                    vaultState = vaultState,
                    onBack = {
                        navController.popBackStack()
                    },
                    onEdit = {
                        navController.navigate("edit_entry/$entryId")
                    },
                    modifier = Modifier
                )
            }

            composable("add_entry") {
                AddEntryScreen(
                    vaultState = vaultState,
                    onBack = {
                        navController.popBackStack()
                    },
                    modifier = Modifier
                )
            }

            composable("edit_entry/{entryId}") { backStackEntry ->
                val entryId = backStackEntry.arguments?.getString("entryId") ?: return@composable
                // Edit entry screen (similar to AddEntryScreen)
                // For now, navigate back
                LaunchedEffect(Unit) {
                    navController.popBackStack()
                }
            }

            composable("totp") {
                TotpListScreen(
                    vaultState = vaultState,
                    modifier = Modifier
                )
            }

            composable("generator") {
                GeneratorScreen(
                    vaultState = vaultState,
                    modifier = Modifier
                )
            }

            composable("settings") {
                SettingsScreen(
                    vaultState = vaultState,
                    onLock = onLock,
                    modifier = Modifier
                )
            }
        }
    }
}
