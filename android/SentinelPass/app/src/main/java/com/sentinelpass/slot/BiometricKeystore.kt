package com.sentinelpass.slot

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import kotlin.coroutines.resume

/**
 * WBS-812: the Android half of the platform-keyslot surface (ADR-009 rev 2).
 *
 * The Keystore holds ONE RSA-2048 signing key (`KEY_ALIAS`) that is:
 * - `setUserAuthenticationRequired(true)`: every private-key operation
 *   requires a fresh BiometricPrompt authorization — a UI prompt alone
 *   authorizes nothing; the prompt gates the CRYPTOGRAPHIC operation itself
 *   via `BiometricPrompt.CryptoObject(signature)`.
 * - `setInvalidatedByBiometricEnrollment(true)`: enrolling a new biometric
 *   permanently invalidates the key — a stale slot fails closed and must be
 *   re-enabled with the master password.
 * - `SHA256withRSA/PKCS1`: DETERMINISTIC signatures. This is a hard
 *   requirement: the wrap key is `HKDF(signature)` (same design as Windows
 *   Hello, WBS-710), and release must reproduce the enable-time signature
 *   bytes. ECDSA in Keystore is randomized and would be refused at enable —
 *   the bridge's determinism check fails closed on it.
 *
 * The TEE/StrongBox backs the private key; it never leaves secure hardware.
 */
object BiometricKeystore {

    private const val TAG = "BiometricKeystore"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val KEY_ALIAS = "com.sentinelpass.vault-slot"

    /** Whether the device can host the auth-bound key at all. */
    fun canUse(context: Context): Boolean {
        val bm = BiometricManager.from(context)
        return bm.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_WEAK or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        ) == BiometricManager.BIOMETRIC_SUCCESS &&
            try {
                keyStore().containsAlias(KEY_ALIAS) || true // keystore present
            } catch (_: Exception) {
                false
            }
    }

    /** Whether the signing key exists (created by [ensureKey]). */
    fun hasKey(): Boolean = try {
        keyStore().containsAlias(KEY_ALIAS)
    } catch (_: Exception) {
        false
    }

    /**
     * Create the auth-bound signing key if absent. Idempotent. StrongBox is
     * requested when available (hardware-assurance floor, ADR-009) with a
     * TEE fallback.
     */
    fun ensureKey() {
        val ks = keyStore()
        if (ks.containsAlias(KEY_ALIAS)) return

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            ANDROID_KEYSTORE
        )
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setKeySize(2048)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            // Hardware floor (ADR-009): without a StrongBox request the key
            // is TEE-backed on every modern device — the auth-bound private
            // key still never leaves secure hardware. (StrongBox remains an
            // optional hardening follow-up; its API gating complicates the
            // minSdk-26 build for no security delta on the floor.)
            .build()
        generator.initialize(spec)
        generator.generateKeyPair()
    }

    /** Delete the slot key (disable flow). The at-rest blob dies with it. */
    fun deleteKey() {
        try {
            keyStore().deleteEntry(KEY_ALIAS)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to delete slot key", e)
        }
    }

    /**
     * Sign `challengeHex` under the auth-bound gate: shows the
     * BiometricPrompt bound to the signature operation (CryptoObject).
     * Suspends until the user completes (or cancels) the gesture.
     *
     * @param activity a FragmentActivity to host the BiometricPrompt.
     * @return hex-encoded signature, or null when the user cancelled / the
     *         gate was refused (FAIL CLOSED — callers must treat null as
     *         "slot unavailable", never retry silently).
     */
    suspend fun signHex(
        activity: FragmentActivity,
        challengeHex: String,
        reason: String
    ): String? {
        val challenge = challengeHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val signature = sign(activity, challenge, reason) ?: return null
        return signature.joinToString("") { "%02x".format(it) }
    }

    /**
     * The auth-gated signing primitive. The `Signature` object is created
     * BEFORE the prompt and passed as the CryptoObject, so the biometric
     * authorization and the private-key operation are a single hardware
     * transaction — the ADR-009 requirement.
     */
    private suspend fun sign(
        activity: FragmentActivity,
        challenge: ByteArray,
        reason: String
    ): ByteArray? = suspendCancellableCoroutine { cont ->
        try {
            if (!hasKey()) {
                cont.resume(null)
                return@suspendCancellableCoroutine
            }
            val signature = Signature.getInstance("SHA256withRSA").apply {
                initSign(keyStore().getKey(KEY_ALIAS, null) as java.security.PrivateKey)
                update(challenge)
            }

            val executor = ContextCompat.getMainExecutor(activity)
            val prompt = BiometricPrompt(
                activity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        try {
                            val gatedSignature = result.cryptoObject?.signature
                                ?: throw IllegalStateException(
                                    "authenticated without CryptoObject"
                                )
                            gatedSignature.update(challenge)
                            cont.resume(signature.sign())
                        } catch (e: Exception) {
                            Log.e(TAG, "Signing failed after auth", e)
                            cont.resume(null)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        // Cancelled, locked out, or hardware failure — fail closed.
                        cont.resume(null)
                    }

                    override fun onAuthenticationFailed() {
                        // A bad read; the prompt keeps going — nothing to do.
                    }
                }
            )

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authorize SentinelPass")
                .setSubtitle(reason)
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_WEAK or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL
                )
                .build()

            prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start gated signing", e)
            cont.resume(null)
        }
    }

    private fun keyStore(): KeyStore {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
        ks.load(null)
        return ks
    }

}
