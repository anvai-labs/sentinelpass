package com.sentinelpass.autofill

import java.net.URI

/**
 * WBS-813: conservative origin matching between an autofill request target
 * (a web domain, or an Android app package) and a vault entry's stored URL.
 *
 * Heuristic limits (deliberately conservative — a missed fill costs one
 * manual lookup, a wrong fill leaks a credential to the wrong surface):
 *
 * - Web targets match only when the entry URL's host and the target domain
 *   resolve to the SAME registrable domain ("gist.github.com" matches
 *   "github.com"; "notgithub.com" and "evil-github.com" do not). The
 *   registrable-domain computation uses a small hard-coded second-level
 *   public-suffix set, NOT the full PSL — exotic multi-label suffixes
 *   (e.g. some *.pvt.k12.ma.us) over-match by one label. Acceptable because
 *   both sides of the comparison go through the same (mis)computation, so an
 *   entry saved for a.co.uk still only matches *.co.uk targets.
 * - App targets use the classic package→domain heuristic ONLY when it can be
 *   stated with some confidence (package is >= 3 labels and the first label
 *   is a known TLD): "com.example.app" yields registrable "example.com". A
 *   package that does not fit the pattern never matches directly — the fill
 *   falls back to the authenticated search-all picker instead.
 */
object AutofillDomainMatcher {

    /**
     * Tiny second-level public-suffix subset (not the full PSL — see class
     * comment). Covers the common cases where the registrable domain has
     * three labels.
     */
    private val SECOND_LEVEL_SUFFIXES = setOf(
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.jp", "or.jp", "ne.jp", "ac.jp",
        "com.br", "com.mx", "com.ar",
        "co.in", "co.nz", "co.za", "co.kr",
        "com.cn", "com.sg", "com.tr", "com.tw"
    )

    private val PACKAGE_TLDS = setOf(
        "com", "org", "net", "io", "dev", "app", "co", "edu", "gov", "sh", "me"
    )

    /** Extract the lowercase host from a URL or bare domain string. */
    fun hostOf(urlLike: String): String? {
        if (urlLike.isBlank()) return null
        val withScheme = if (!urlLike.contains("://")) "https://$urlLike" else urlLike
        return try {
            URI(withScheme).host?.lowercase()
        } catch (_: Exception) {
            // java.net.URI is strict about characters such as '_' or spaces;
            // treat unparseable origins as unmatched rather than guessing.
            null
        }
    }

    /**
     * Best-effort registrable domain: the last two labels, or the last three
     * when the last two are a known second-level suffix ("bbc.co.uk" stays
     * three labels).
     */
    fun registrableDomainOf(host: String): String {
        val h = host.removeSuffix(".").lowercase()
        val labels = h.split('.')
        if (labels.size <= 2) return h
        val lastTwo = labels.takeLast(2).joinToString(".")
        if (lastTwo in SECOND_LEVEL_SUFFIXES) return labels.takeLast(3).joinToString(".")
        return lastTwo
    }

    /**
     * Whether a vault entry's URL belongs to the same registrable domain as
     * the autofill request's web target.
     */
    fun matchesWebDomain(entryUrl: String?, targetWebDomain: String?): Boolean {
        if (entryUrl.isNullOrBlank() || targetWebDomain.isNullOrBlank()) return false
        val entryHost = hostOf(entryUrl) ?: return false
        val targetHost = hostOf(targetWebDomain) ?: return false
        if (entryHost.isEmpty() || targetHost.isEmpty()) return false
        return registrableDomainOf(entryHost) == registrableDomainOf(targetHost)
    }

    /**
     * The registrable domain a package name most plausibly corresponds to,
     * or null when the package does not fit the confident pattern
     * ("com.example.app" → "example.com"; "com.example" → null; "org.foo" →
     * null; "io.github.user.app" → "github.io"?? — NO: segments[1] is
     * "github", giving "github.io", which would match ANY io.github.*
     * package; that is exactly the over-match this heuristic must avoid, so
     * additionally require that the SECOND segment is not a common
     * free-hosting namespace).
     */
    fun packageCandidateDomain(appPackage: String?): String? {
        if (appPackage.isNullOrBlank()) return null
        val parts = appPackage.split('.')
        if (parts.size < 3) return null
        val tld = parts[0].lowercase()
        if (tld !in PACKAGE_TLDS) return null
        val org = parts[1].lowercase()
        // io.github.* / com.github.* style namespaces are shared by thousands
        // of unrelated apps — refuse to derive a domain for them.
        if (org in SHARED_NAMESPACES) return null
        return "$org.$tld"
    }

    private val SHARED_NAMESPACES = setOf(
        "github", "gitlab", "bitbucket", "google", "android"
    )

    /**
     * Whether a vault entry's URL plausibly belongs to the given app
     * package (package→domain heuristic; see class comment).
     */
    fun matchesAppPackage(entryUrl: String?, appPackage: String?): Boolean {
        if (entryUrl.isNullOrBlank() || appPackage.isNullOrBlank()) return false
        val candidate = packageCandidateDomain(appPackage) ?: return false
        val entryHost = hostOf(entryUrl) ?: return false
        if (entryHost.isEmpty()) return false
        return registrableDomainOf(entryHost) == candidate
    }

    /**
     * Select the entries that confidently match the fill target. Returns at
     * most [max] entries, preserving vault order.
     */
    fun selectMatching(
        entries: List<com.sentinelpass.Entry>,
        webDomain: String?,
        appPackage: String?,
        max: Int = MAX_DIRECT_MATCHES
    ): List<com.sentinelpass.Entry> {
        if (webDomain.isNullOrBlank() && appPackage.isNullOrBlank()) return emptyList()
        return entries.filter { entry ->
            matchesWebDomain(entry.url, webDomain) || matchesAppPackage(entry.url, appPackage)
        }.take(max)
    }

    /** Cap on datasets offered without user interaction (response size). */
    const val MAX_DIRECT_MATCHES = 6

    /**
     * Cap on entries whose full details are fetched for a direct domain
     * match. Larger vaults skip the direct path and go straight to the
     * authenticated picker (each detail fetch is a native decrypt; unbounded
     * work inside onFillRequest risks the system fill timeout).
     */
    const val MAX_DETAIL_FETCH = 100
}
