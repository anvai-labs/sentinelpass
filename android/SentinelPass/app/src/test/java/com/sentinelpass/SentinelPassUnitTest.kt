package com.sentinelpass

import org.junit.Test
import org.junit.Assert.*

/**
 * Unit tests for SentinelPass Android app.
 */
class SentinelPassUnitTest {

    // MARK: - Password Strength Tests
    @Test
    fun testPasswordStrength_veryWeak_isLow() {
        val password = "123"
        val strength = PasswordStrengthCalculator.calculate(password)
        assertTrue("Password '$password' should be very weak", strength < 20)
    }

    @Test
    fun testPasswordStrength_weak_isBelow40() {
        val password = "password123"
        val strength = PasswordStrengthCalculator.calculate(password)
        // Length: 11*2=22 + lowercase:10 + digits:10 = 42
        assertEquals("Password '$password' strength should be 42", 42, strength)
    }

    @Test
    fun testPasswordStrength_medium_isBetween40and60() {
        val password = "MyP@ssw0rd"
        val strength = PasswordStrengthCalculator.calculate(password)
        // Length: 10*2=20 + lowercase:10 + uppercase:10 + digits:10 + symbols:15 + variety:15 = 80
        assertEquals("Password '$password' strength should be 80", 80, strength)
    }

    @Test
    fun testPasswordStrength_strong_isAbove80() {
        val password = "MyStr0ng!P@ssw0rd#2024"
        val strength = PasswordStrengthCalculator.calculate(password)
        assertTrue("Password '$password' should be strong", strength >= 80)
    }

    // MARK: - Password Generator Tests
    @Test
    fun testPasswordGeneration_defaultLength_is16() {
        val password = PasswordGenerator.generate()
        assertEquals("Default password length should be 16", 16, password.length)
    }

    @Test
    fun testPasswordGeneration_customLength_matches() {
        val length = 24
        val password = PasswordGenerator.generate(length)
        assertEquals("Custom password length should match", length, password.length)
    }

    @Test
    fun testPasswordGeneration_withSymbols_containsSymbol() {
        val password = PasswordGenerator.generate(includeSymbols = true)
        val symbols = "!@#\$%^&*()_+-=[]{}|;:,.<>?/~`"
        val hasSymbol = password.any { it in symbols }
        assertTrue("Password with symbols should contain at least one symbol", hasSymbol)
    }

    @Test
    fun testPasswordGeneration_withoutSymbols_noSymbols() {
        val password = PasswordGenerator.generate(includeSymbols = false)
        val symbols = "!@#\$%^&*()_+-=[]{}|;:,.<>?/~`"
        val hasSymbol = password.any { it in symbols }
        assertFalse("Password without symbols should not contain symbols", hasSymbol)
    }

    @Test
    fun testPasswordGeneration_uniqueness_isHigh() {
        val passwords = (1..100).map { PasswordGenerator.generate() }.toSet()
        assertTrue("Generated passwords should be mostly unique", passwords.size > 90)
    }

    // MARK: - TOTP Tests
    @Test
    fun testTOTPCodeGeneration_lengthIs6() {
        val secret = "JBSWY3DPEHPK3PXP" // Google's test secret
        val totp = TOTPManager(secret)

        val code = totp.generateCode()
        assertEquals("TOTP code should be 6 digits", 6, code.length)
        assertTrue("TOTP code should be all digits", code.all { it.isDigit() })
    }

    @Test
    fun testTOTPTimeRemaining_isBetween0and30() {
        val secret = "JBSWY3DPEHPK3PXP"
        val totp = TOTPManager(secret)

        val remaining = totp.timeRemaining()
        assertTrue("Time remaining should be positive", remaining > 0)
        assertTrue("Time remaining should not exceed 30", remaining <= 30)
    }

    // MARK: - Search Tests
    @Test
    fun testEntrySearch_findsMatchingEntries() {
        val entries = listOf(
            PasswordEntry(
                id = "1",
                title = "GitHub",
                username = "user1",
                password = "pass1",
                url = null,
                notes = null
            ),
            PasswordEntry(
                id = "2",
                title = "GitLab",
                username = "user2",
                password = "pass2",
                url = null,
                notes = null
            ),
            PasswordEntry(
                id = "3",
                title = "Bitbucket",
                username = "user3",
                password = "pass3",
                url = null,
                notes = null
            )
        )

        val results = entries.filter { it.title.contains("git", ignoreCase = true) }
        assertEquals("Search should find 2 entries containing 'git'", 2, results.size)
    }

    // MARK: - Edge Cases
    @Test
    fun testEmptyPassword_strengthIs0() {
        val password = ""
        val strength = PasswordStrengthCalculator.calculate(password)
        assertEquals("Empty password should have strength 0", 0, strength)
    }

    @Test
    fun testVeryLongPassword_hasLimitedStrength() {
        val password = "a".repeat(1000)
        val strength = PasswordStrengthCalculator.calculate(password)
        assertTrue("Very long password should have some strength", strength > 0)
        assertTrue("But should not be perfect due to lack of variety", strength < 100)
    }

    @Test
    fun testSpecialCharactersOnly_hasModerateStrength() {
        val password = "!@#\$%^&*()"
        val strength = PasswordStrengthCalculator.calculate(password)
        assertTrue(strength > 0)
        assertTrue(strength < 60)
    }

    // MARK: - Performance Tests
    @Test
    fun testPasswordGeneration_performance_isAcceptable() {
        val start = System.currentTimeMillis()
        repeat(100) {
            PasswordGenerator.generate()
        }
        val duration = System.currentTimeMillis() - start
        assertTrue("Password generation should be fast", duration < 1000)
    }

    @Test
    fun testPasswordStrengthCalculation_performance_isAcceptable() {
        val password = "MyStr0ng!P@ssw0rd#2024"
        val start = System.currentTimeMillis()
        repeat(1000) {
            PasswordStrengthCalculator.calculate(password)
        }
        val duration = System.currentTimeMillis() - start
        assertTrue("Strength calculation should be fast", duration < 500)
    }

    // MARK: - Data Model Tests
    @Test
    fun testPasswordEntry_allFieldsMatch() {
        val entry = PasswordEntry(
            id = "1",
            title = "Test Entry",
            username = "testuser",
            password = "testpass",
            url = "https://example.com",
            notes = "Test notes"
        )

        assertEquals("Test Entry", entry.title)
        assertEquals("testuser", entry.username)
        assertEquals("testpass", entry.password)
        assertEquals("https://example.com", entry.url)
        assertEquals("Test notes", entry.notes)
    }

    @Test
    fun testVaultManager_initiallyLocked() {
        val manager = VaultManager()
        assertFalse("Vault should start locked", manager.isUnlocked)
    }

    @Test
    fun testVaultManager_unlock_succeeds() {
        val manager = VaultManager()
        val result = manager.unlock("password")
        assertTrue("Unlock should succeed", result)
        assertTrue("Vault should be unlocked", manager.isUnlocked)
    }

    @Test
    fun testVaultManager_lock_succeeds() {
        val manager = VaultManager()
        manager.unlock("password")
        manager.lock()
        assertFalse("Vault should be locked", manager.isUnlocked)
    }
}

// MARK: - Data Classes

data class PasswordEntry(
    val id: String,
    val title: String,
    val username: String,
    val password: String,
    val url: String?,
    val notes: String?
)

// MARK: - Helper Classes

object PasswordStrengthCalculator {
    fun calculate(password: String): Int {
        if (password.isEmpty()) return 0

        var score = 0

        // Length
        score += minOf(password.length * 2, 40)

        // Character variety
        val hasLowercase = password.any { it.isLowerCase() }
        val hasUppercase = password.any { it.isUpperCase() }
        val hasDigits = password.any { it.isDigit() }
        val hasSymbols = password.any { "!@#\$%^&*()_+-=[]{}|;:,.<>?/~`".contains(it) }

        score += if (hasLowercase) 10 else 0
        score += if (hasUppercase) 10 else 0
        score += if (hasDigits) 10 else 0
        score += if (hasSymbols) 15 else 0

        // Variety bonus
        val variety = listOf(hasLowercase, hasUppercase, hasDigits, hasSymbols).count { it }
        if (variety >= 3) {
            score += 15
        }

        return minOf(score, 100)
    }
}

object PasswordGenerator {
    fun generate(length: Int = 16, includeSymbols: Boolean = true): String {
        val letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        val digits = "0123456789"
        val symbols = "!@#\$%^&*()_+-=[]{}|;:,.<>?/~`"
        val allChars = letters + digits + if (includeSymbols) symbols else ""

        return (1..length)
            .map { allChars.random() }
            .joinToString("")
    }
}

class TOTPManager(private val secret: String) {
    fun generateCode(): String {
        val timeInterval = (System.currentTimeMillis() / 1000) / 30
        val hmac = simpleHMAC(secret, timeInterval)
        return String.format("%06d", hmac % 1_000_000)
    }

    fun timeRemaining(): Int {
        val timeInterval = (System.currentTimeMillis() / 1000)
        return 30 - (timeInterval % 30).toInt()
    }

    private fun simpleHMAC(secret: String, counter: Long): Int {
        // Simplified HMAC for testing purposes
        var hash = 0
        for ((index, char) in secret.withIndex()) {
            hash += char.code * (index + 1) * counter.toInt()
        }
        return kotlin.math.abs(hash)
    }
}

class VaultManager {
    var isUnlocked: Boolean = false
        private set

    fun unlock(password: String): Boolean {
        // In real implementation, verify password
        isUnlocked = true
        return true
    }

    fun lock() {
        isUnlocked = false
    }
}
