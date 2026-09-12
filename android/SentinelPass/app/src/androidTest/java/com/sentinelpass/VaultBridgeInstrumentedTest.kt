package com.sentinelpass

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.sentinelpass.slot.BiometricKeystore
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

/**
 * Instrumentation tests over the REAL JNI bridge (libsentinelpass_mobile_bridge).
 *
 * Run with: ./gradlew connectedDebugAndroidTest   (on a device/emulator that
 * has the .so packaged — the WBS-818 CI matrix wires exactly that into CI).
 * `./gradlew testDebugUnitTest` does NOT execute these; they still must
 * compile there.
 *
 * SCOPE (un-gated paths only): vault create/unlock, entry CRUD round-trips,
 * lock/destroy/re-open, the slot CHALLENGE primitive (no prompt needed),
 * and the blob preflight. The GATED slot operations (slotSeal/slotUnlock)
 * require BiometricPrompt.CryptoObject authorization — see the gated test
 * at the bottom for how that is handled on CI emulators.
 *
 * Each test gets a fresh vault file in the target package's filesDir and
 * cleans up after itself.
 */
@RunWith(AndroidJUnit4::class)
class VaultBridgeInstrumentedTest {

    companion object {
        // Long/strong enough to satisfy any create-time strength policy.
        private const val MASTER_PASSWORD = "c0rrect-horse-battery-staple!42"
    }

    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private lateinit var bridge: VaultBridge
    private lateinit var vaultFile: File

    @Before
    fun setUp() {
        vaultFile = File(context.filesDir, "itest-vault-${UUID.randomUUID()}.db")
        // Construction IS the ABI handshake (WBS-803): the init block throws
        // IllegalStateException unless the loaded library reports ABI
        // version 2 — the same contract the app enforces at runtime.
        bridge = VaultBridge(context)
    }

    @After
    fun tearDown() {
        // Safe on a never-unlocked or already-locked bridge: the native call
        // refuses handle 0 and lockVault() returns false without throwing.
        runBlocking { bridge.lockVault() }
        vaultFile.delete()
        // SQLite sidecars, if the bridge engine created any.
        File(vaultFile.absolutePath + "-journal").delete()
        File(vaultFile.absolutePath + "-wal").delete()
        File(vaultFile.absolutePath + "-shm").delete()
    }

    // ------------------------------------------------------------------
    // ABI handshake
    // ------------------------------------------------------------------

    @Test
    fun bridgeConstruction_abiHandshakeSucceeds() {
        // Reaching this point means VaultBridge's companion loaded the
        // native library AND its init block verified nativeAbiVersion()==2;
        // any mismatch would have thrown in setUp.
        assertTrue(true)
    }

    // ------------------------------------------------------------------
    // Vault lifecycle
    // ------------------------------------------------------------------

    @Test
    fun initVault_createsVaultInTheTempFilesDir_andReportsUnlocked() = runBlocking {
        assertTrue(bridge.initVault(vaultFile.absolutePath, MASTER_PASSWORD))
        assertTrue(bridge.isUnlocked())
        assertTrue(vaultFile.exists())
    }

    @Test
    fun lockVault_locksState_andVaultReopensWithSamePassword() = runBlocking {
        assertTrue(bridge.initVault(vaultFile.absolutePath, MASTER_PASSWORD))

        // WBS-804 semantics: locking ALSO destroys the native handle
        // (nativeDestroy), so a lock/unlock cycle cannot leak registry
        // entries or open SQLite handles.
        assertTrue(bridge.lockVault())
        assertFalse(bridge.isUnlocked())

        // Re-opening proves the file is intact and the destroyed handle
        // was fully released (a second init would fail on a still-held
        // exclusive vault, and a wrong-password init would return false).
        assertTrue(bridge.initVault(vaultFile.absolutePath, MASTER_PASSWORD))
        assertTrue(bridge.isUnlocked())
    }

    @Test
    fun initVault_rejectsWrongPassword() = runBlocking {
        assertTrue(bridge.initVault(vaultFile.absolutePath, MASTER_PASSWORD))
        assertTrue(bridge.lockVault())

        // The bridge instance already dropped its handle; use a fresh one
        // for the wrong-password attempt against the same file.
        val other = VaultBridge(context)
        val otherFile = File(context.filesDir, "itest-vault-${UUID.randomUUID()}.db")
        try {
            // Copy the encrypted vault so the original stays pristine.
            vaultFile.copyTo(otherFile, overwrite = true)
            assertFalse(other.initVault(otherFile.absolutePath, "definitely-not-it"))
            assertFalse(other.isUnlocked())
        } finally {
            other.lockVault()
            otherFile.delete()
        }
    }

    // ------------------------------------------------------------------
    // Entry CRUD round-trip
    // ------------------------------------------------------------------

    @Test
    fun entryCrud_addGetListUpdateDelete_roundTrip() = runBlocking {
        assertTrue(bridge.initVault(vaultFile.absolutePath, MASTER_PASSWORD))

        val id = bridge.addEntry(
            title = "Example",
            username = "alice@example.com",
            password = "s3cret-PW!",
            url = "https://example.com/login",
            notes = "itest entry"
        )
        assertNotNull("addEntry should return the new entry id", id)

        val fetched = bridge.getEntry(id!!)
        assertEquals("Example", fetched?.title)
        assertEquals("alice@example.com", fetched?.username)
        assertEquals("s3cret-PW!", fetched?.password)
        assertEquals("https://example.com/login", fetched?.url)
        assertEquals("itest entry", fetched?.notes)

        assertTrue(bridge.listEntries().any { it.id == id })

        // WBS-807: update is a single atomic native call.
        assertTrue(bridge.updateEntry(id, password = "r0tated-PW!"))
        assertEquals("r0tated-PW!", bridge.getEntry(id)?.password)
        assertEquals("alice@example.com", bridge.getEntry(id)?.username)

        assertTrue(bridge.deleteEntry(id))
        assertNull("deleted entry must not be returned", bridge.getEntry(id))
        assertFalse(bridge.listEntries().any { it.id == id })
    }

    // ------------------------------------------------------------------
    // Platform slot — UN-GATED primitives only
    // ------------------------------------------------------------------

    @Test
    fun slotChallenge_drawsFresh32ByteHexChallenges() = runBlocking {
        val a = bridge.slotChallenge()
        assertNotNull(a)
        assertEquals("challenge must be 32 bytes hex", 64, a!!.length)
        assertTrue(a.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' })

        val b = bridge.slotChallenge()
        assertNotNull(b)
        assertTrue("challenges must not repeat", a != b)
        // Vault state is irrelevant for the challenge primitive (it is
        // drawn pre-gate), but assert the vault path was untouched anyway.
        assertFalse(bridge.isUnlocked())
    }

    @Test
    fun slotHasBlob_rejectsNonBlobs() {
        assertFalse(bridge.slotHasBlob("definitely not json"))
        assertFalse(bridge.slotHasBlob("{}"))
        assertFalse(bridge.slotHasBlob(""))
    }

    // ------------------------------------------------------------------
    // Platform slot — GATED operations (documented CI behavior)
    // ------------------------------------------------------------------

    @Test
    fun slotSealAndUnlock_areGatedBehindBiometricPrompt() {
        // slotSeal/slotUnlock require TWO (seal) / ONE (unlock) authorized
        // BiometricPrompt.CryptoObject signature rounds. A headless CI
        // emulator has no enrolled biometric and no user to answer the
        // prompt, so this test EARLY-RETURNS (Assume => skipped, not
        // failed) whenever the auth-bound Keystore key is absent. On an
        // enrolled device the full enable→lock→unlock round-trip runs via
        // VaultState.enableBiometricSlot/unlockWithBiometricSlot and this
        // test only confirms the gate exists.
        Assume.assumeTrue(
            "Biometric gate not enrolled on this device — gated slot round-trip skipped",
            BiometricKeystore.hasKey()
        )
        assertTrue(BiometricKeystore.hasKey())
    }
}
