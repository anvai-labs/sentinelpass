package com.sentinelpass.ui.screens

import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Face
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.sentinelpass.data.VaultState
import kotlinx.coroutines.launch

/**
 * Lock Screen - Master password and biometric unlock
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LockScreen(
    vaultState: VaultState = VaultState.current,
    onUnlockSuccess: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val uiState by vaultState.uiState.collectAsState()

    var masterPassword by remember { mutableStateOf("") }
    var showBiometricPrompt by remember { mutableStateOf(false) }
    var hasBiometricKey by remember { mutableStateOf(false) }
    var biometricAvailable by remember { mutableStateOf(false) }

    // Check biometric availability
    LaunchedEffect(Unit) {
        hasBiometricKey = vaultState.hasBiometricKey()
        biometricAvailable = canAuthenticateBiometric(context)
        if (hasBiometricKey && biometricAvailable) {
            showBiometricPrompt = true
        }
    }

    // Show biometric prompt when flag is set
    if (showBiometricPrompt) {
        BiometricPrompt(
            onSuccess = {
                (context as? androidx.fragment.app.FragmentActivity)?.let {
                    vaultState.unlockWithBiometric(it)
                }
                showBiometricPrompt = false
            },
            onError = {
                showBiometricPrompt = false
            },
            onCancel = {
                showBiometricPrompt = false
            }
        )
    }

    // Navigate to main screen on unlock
    LaunchedEffect(uiState.isUnlocked) {
        if (uiState.isUnlocked) {
            onUnlockSuccess()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("SentinelPass") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    titleContentColor = MaterialTheme.colorScheme.onPrimary
                )
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(24.dp),
                modifier = Modifier.padding(32.dp)
            ) {
                // Logo
                Icon(
                    imageVector = Icons.Default.Face,
                    contentDescription = null,
                    modifier = Modifier.size(120.dp),
                    tint = MaterialTheme.colorScheme.primary
                )

                Text(
                    text = "Unlock Your Vault",
                    style = MaterialTheme.typography.headlineMedium
                )

                // Biometric Button
                if (biometricAvailable && hasBiometricKey) {
                    Button(
                        onClick = { showBiometricPrompt = true },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(
                            imageVector = Icons.Default.Fingerprint,
                            contentDescription = null,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Unlock with Biometric")
                    }
                }

                // Password Field
                OutlinedTextField(
                    value = masterPassword,
                    onValueChange = { masterPassword = it },
                    label = { Text("Master Password") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !uiState.isLoading
                )

                // Unlock Button
                Button(
                    onClick = {
                        vaultState.unlockVault(masterPassword)
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = masterPassword.isNotEmpty() && !uiState.isLoading
                ) {
                    if (uiState.isLoading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = MaterialTheme.colorScheme.onPrimary
                        )
                    } else {
                        Text("Unlock")
                    }
                }

                // Error Message
                if (uiState.error != null) {
                    Text(
                        text = uiState.error ?: "",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
    }
}

@Composable
fun BiometricPrompt(
    onSuccess: () -> Unit,
    onError: () -> Unit,
    onCancel: () -> Unit
) {
    val context = LocalContext.current
    val activity = context as? FragmentActivity

    val executor = remember { androidx.core.content.ContextCompat.getMainExecutor(context) }
    val biometricPrompt = remember(activity) {
        activity?.let {
            BiometricPrompt(
                it,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        onSuccess()
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        onError()
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        onError()
                    }
                }
            )
        }
    }

    val promptInfo = remember {
        BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Unlock")
            .setSubtitle("Authenticate to access your password vault")
            .setAllowedAuthenticators(
                androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .build()
    }

    LaunchedEffect(Unit) {
        biometricPrompt?.authenticate(promptInfo)
    }

    // Handle cancel when prompt is dismissed
    DisposableEffect(Unit) {
        onDispose {
            onCancel()
        }
    }
}

fun canAuthenticateBiometric(context: android.content.Context): Boolean {
    val biometricManager = androidx.biometric.BiometricManager.from(context)
    return biometricManager.canAuthenticate(
        androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
        androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
    ) == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
}
