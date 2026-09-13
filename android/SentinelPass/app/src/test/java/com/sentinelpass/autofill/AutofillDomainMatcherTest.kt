package com.sentinelpass.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests for the WBS-813 autofill origin matching heuristics.
 * [AutofillDomainMatcher] is deliberately pure Kotlin (no Android imports)
 * so these run in testDebugUnitTest.
 */
class AutofillDomainMatcherTest {

    // ------------------------------------------------------------------
    // hostOf
    // ------------------------------------------------------------------

    @Test
    fun hostOf_fullUrl_extractsHost() {
        assertEquals("accounts.google.com", AutofillDomainMatcher.hostOf("https://accounts.google.com/signin?v2"))
    }

    @Test
    fun hostOf_bareDomain_getsImplicitScheme() {
        assertEquals("github.com", AutofillDomainMatcher.hostOf("github.com"))
    }

    @Test
    fun hostOf_isLowercased() {
        assertEquals("www.example.com", AutofillDomainMatcher.hostOf("HTTPS://WWW.Example.COM"))
    }

    @Test
    fun hostOf_garbage_returnsNull() {
        assertNull(AutofillDomainMatcher.hostOf("not a url"))
        assertNull(AutofillDomainMatcher.hostOf(""))
        assertNull(AutofillDomainMatcher.hostOf("   "))
    }

    // ------------------------------------------------------------------
    // registrableDomainOf
    // ------------------------------------------------------------------

    @Test
    fun registrableDomain_twoLabels_stayTwo() {
        assertEquals("example.com", AutofillDomainMatcher.registrableDomainOf("www.example.com"))
        assertEquals("example.com", AutofillDomainMatcher.registrableDomainOf("example.com"))
    }

    @Test
    fun registrableDomain_secondLevelSuffix_keptThree() {
        assertEquals("bbc.co.uk", AutofillDomainMatcher.registrableDomainOf("www.bbc.co.uk"))
        assertEquals("uq.edu.au", AutofillDomainMatcher.registrableDomainOf("uq.edu.au"))
    }

    // ------------------------------------------------------------------
    // matchesWebDomain
    // ------------------------------------------------------------------

    @Test
    fun webDomain_exactHost_matches() {
        assertTrue(AutofillDomainMatcher.matchesWebDomain("https://github.com/login", "github.com"))
    }

    @Test
    fun webDomain_subdomain_matches() {
        assertTrue(AutofillDomainMatcher.matchesWebDomain("https://gist.github.com/x", "github.com"))
        assertTrue(AutofillDomainMatcher.matchesWebDomain("https://accounts.google.com", "google.com"))
    }

    @Test
    fun webDomain_secondLevelSuffixHost_matches() {
        assertTrue(AutofillDomainMatcher.matchesWebDomain("https://www.bbc.co.uk/news", "bbc.co.uk"))
    }

    @Test
    fun webDomain_differentRegistrable_neverMatches() {
        assertFalse(AutofillDomainMatcher.matchesWebDomain("https://notgoogle.com", "google.com"))
        assertFalse(AutofillDomainMatcher.matchesWebDomain("https://evil-github.com", "github.com"))
        // Path confusion: the TARGET domain appearing in the path must not match.
        assertFalse(AutofillDomainMatcher.matchesWebDomain("https://evilsite.com/github.com", "github.com"))
        assertFalse(AutofillDomainMatcher.matchesWebDomain("https://github.com.evil.io", "github.com"))
    }

    @Test
    fun webDomain_blankInputs_neverMatch() {
        assertFalse(AutofillDomainMatcher.matchesWebDomain(null, "github.com"))
        assertFalse(AutofillDomainMatcher.matchesWebDomain("https://github.com", null))
        assertFalse(AutofillDomainMatcher.matchesWebDomain("", "github.com"))
    }

    // ------------------------------------------------------------------
    // packageCandidateDomain / matchesAppPackage
    // ------------------------------------------------------------------

    @Test
    fun packageCandidate_threeSegmentsWithKnownTld_derivesDomain() {
        assertEquals("example.com", AutofillDomainMatcher.packageCandidateDomain("com.example.app"))
        assertEquals("mybank.net", AutofillDomainMatcher.packageCandidateDomain("net.mybank.mobile"))
    }

    @Test
    fun packageCandidate_unknownPattern_returnsNull() {
        assertNull(AutofillDomainMatcher.packageCandidateDomain("com.example"))          // too short
        assertNull(AutofillDomainMatcher.packageCandidateDomain("kotlin.example.app"))   // unknown TLD-ish
        assertNull(AutofillDomainMatcher.packageCandidateDomain("io.github.user.app"))   // shared namespace
        assertNull(AutofillDomainMatcher.packageCandidateDomain(null))
        assertNull(AutofillDomainMatcher.packageCandidateDomain(""))
    }

    @Test
    fun appPackage_matchingEntryUrl_matches() {
        assertTrue(AutofillDomainMatcher.matchesAppPackage("https://example.com/signin", "com.example.app"))
    }

    @Test
    fun appPackage_unmatchedPackage_neverMatches() {
        assertFalse(AutofillDomainMatcher.matchesAppPackage("https://example.com", "com.example"))
        assertFalse(AutofillDomainMatcher.matchesAppPackage("https://example.com", "io.github.user.app"))
    }

    @Test
    fun appPackage_wrongDomain_neverMatches() {
        // "com.other.app" derives "other.com" — must not match example.com.
        assertFalse(AutofillDomainMatcher.matchesAppPackage("https://example.com", "com.other.app"))
    }

    // ------------------------------------------------------------------
    // selectMatching
    // ------------------------------------------------------------------

    @Test
    fun selectMatching_filtersAndCaps() {
        val mk = { id: String, url: String? ->
            com.sentinelpass.Entry(
                id = id, title = id, username = "u$id",
                password = "p", url = url
            )
        }
        val entries = listOf(
            mk("a", "https://github.com/login"),
            mk("b", "https://evil-github.com"),
            mk("c", "https://gist.github.com"),
            mk("d", null),
            mk("e", "https://example.com")
        )
        val matched = AutofillDomainMatcher.selectMatching(entries, "github.com", null, max = 10)
        assertEquals(listOf("a", "c"), matched.map { it.id })

        val capped = AutofillDomainMatcher.selectMatching(
            (1..20).map { mk("e$it", "https://github.com/$it") },
            "github.com", null, max = 6
        )
        assertEquals(6, capped.size)
    }

    @Test
    fun selectMatching_noTarget_returnsEmpty() {
        val entry = com.sentinelpass.Entry(
            id = "a", title = "a", username = "u", password = "p", url = "https://example.com"
        )
        assertTrue(AutofillDomainMatcher.selectMatching(listOf(entry), null, null).isEmpty())
    }
}
