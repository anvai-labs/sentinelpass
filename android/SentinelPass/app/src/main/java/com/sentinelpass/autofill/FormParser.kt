package com.sentinelpass.autofill

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/**
 * WBS-813: parses an [AssistStructure] captured by the autofill framework
 * into the fields SentinelPass can act on.
 *
 * Heuristic limits (documented, not overclaimed):
 * - Hints and input-type variations are authoritative; resource-id / hint
 *   text keywords ("password", "email", "username", ...) are the fallback
 *   and can both miss and (rarely) over-match. They are filtered through
 *   the password check first so "Password or email" fields are never
 *   classified as username fields.
 * - Only VISIBLE fields are considered; hidden honeypot fields common on
 *   login forms are ignored.
 * - Field order is document order (DFS pre-order), which is the right proxy
 *   for "username comes before password" on the overwhelming majority of
 *   login forms.
 */
internal object FormParser {

    /** A parsed field we may fill or save. */
    internal data class NodeField(
        val autofillId: AutofillId,
        val idEntry: String?,
        val idPackage: String?,
        val hint: String?,
        val visibleText: String?
    )

    /** Result of parsing for a FILL request. */
    internal data class ParsedFillForm(
        val webDomain: String?,
        val appPackage: String?,
        val username: NodeField?,
        val password: NodeField?
    )

    /** Result of parsing for a SAVE request. */
    internal data class ParsedSaveForm(
        val webDomain: String?,
        val appPackage: String?,
        val username: String?,
        val password: String?
    )

    internal data class ParsedForm(
        val webDomain: String?,
        val appPackage: String?,
        val nodes: List<AssistStructure.ViewNode>
    )

    /** Flatten all visible nodes in document order. */
    internal fun parseStructure(structure: AssistStructure, selfPackage: String): ParsedForm? {
        val nodes = mutableListOf<AssistStructure.ViewNode>()
        fun walk(node: AssistStructure.ViewNode) {
            if (node.visibility == View.VISIBLE && node.autofillId != null) {
                nodes.add(node)
            }
            for (i in 0 until node.childCount) {
                walk(node.getChildAt(i))
            }
        }
        for (i in 0 until structure.windowNodeCount) {
            walk(structure.getWindowNodeAt(i).rootViewNode)
        }
        if (nodes.isEmpty()) return null

        // Web domain: first non-blank WebView domain in the structure.
        val webDomain = nodes.firstOrNull { !it.webDomain.isNullOrBlank() }?.webDomain

        // App package: the id package of an app-owned editable field. Framework
        // views ("android") and our own package are ignored — the latter is the
        // self-fill guard that keeps the service from trying to autofill
        // SentinelPass itself.
        val appPackage = nodes
            .filter { isEditableTextField(it) }
            .mapNotNull { it.idPackage }
            .firstOrNull { it != selfPackage && it != "android" }

        return ParsedForm(webDomain = webDomain, appPackage = appPackage, nodes = nodes)
    }

    /**
     * Parse for FILL: the first password field, and the last username-like
     * field BEFORE it (falling back to the first username-like field
     * anywhere). Surfaces without ANY password field (passkeys, SSO
     * redirects, plain email forms) are skipped entirely — a username-only
     * fill would put a SentinelPass chip on half the web.
     *
     * Returns null when the request is not worth acting on (no actionable
     * fields, or it is SentinelPass's own surface — see [isSelfOwned]).
     */
    internal fun parseFillTarget(structure: AssistStructure, selfPackage: String): ParsedFillForm? {
        val parsed = parseStructure(structure, selfPackage) ?: return null

        val passwordIdx = parsed.nodes.indexOfFirst { isPasswordNode(it) }
        val password = if (passwordIdx >= 0) parsed.nodes[passwordIdx].toNodeField() else null
        if (password == null) return null

        val username = parsed.nodes.withIndex()
            .filter { !isPasswordNode(it.value) && isUsernameNode(it.value) }
            .let { candidates ->
                // Last candidate before the password field, else the first anywhere.
                (candidates.lastOrNull { it.index < passwordIdx } ?: candidates.firstOrNull())
                    ?.value?.toNodeField()
            }

        if (isSelfOwned(parsed, selfPackage, listOfNotNull(username, password))) return null
        return ParsedFillForm(parsed.webDomain, parsed.appPackage, username, password)
    }

    /**
     * Parse for SAVE: the username value and the first NON-EMPTY password
     * value captured by the framework. Password fields that were never
     * submitted come through with a null autofill value; requiring a value
     * prevents save prompts for forms the user abandoned.
     */
    internal fun parseSaveForm(structure: AssistStructure, selfPackage: String): ParsedSaveForm? {
        val parsed = parseStructure(structure, selfPackage) ?: return null

        val passwordNode = parsed.nodes
            .filter { isPasswordNode(it) }
            .firstOrNull { !it.autofillValue?.textValue.isNullOrBlank() } ?: return null

        val pwIndex = parsed.nodes.indexOf(passwordNode)
        val usernameNode = parsed.nodes
            .filter { !isPasswordNode(it) && isUsernameNode(it) }
            .let { candidates ->
                candidates.lastOrNull { parsed.nodes.indexOf(it) < pwIndex }
                    ?: candidates.firstOrNull()
            }

        val username = usernameNode?.autofillValue?.textValue?.toString()
            ?.takeIf { it.isNotBlank() }
        val password = passwordNode.autofillValue?.textValue?.toString()

        val captured = listOfNotNull(usernameNode, passwordNode).map { it.toNodeField() }
        if (isSelfOwned(parsed, selfPackage, captured)) return null

        return ParsedSaveForm(
            webDomain = parsed.webDomain,
            appPackage = parsed.appPackage,
            username = username,
            password = password
        )
    }

    /**
     * Self-fill guard. [parseStructure] deliberately excludes our own
     * package when deriving [ParsedForm.appPackage], so "is this ours"
     * must be asked per-field instead: on a non-web surface whose captured
     * fields are owned by SentinelPass itself, refuse to act. Without this
     * the service would offer to autofill/save from its own unlock and
     * save overlays.
     */
    private fun isSelfOwned(
        parsed: ParsedForm,
        selfPackage: String,
        fields: List<NodeField>
    ): Boolean {
        if (!parsed.webDomain.isNullOrBlank()) return false
        return fields.any { it.idPackage == selfPackage }
    }

    // ------------------------------------------------------------------
    // Field classification
    // ------------------------------------------------------------------

    private fun AssistStructure.ViewNode.toNodeField(): NodeField = NodeField(
        autofillId = autofillId!!,
        idEntry = idEntry,
        idPackage = idPackage,
        hint = hint,
        visibleText = text?.toString()
    )

    internal fun isEditableTextField(node: AssistStructure.ViewNode): Boolean {
        val cls = node.inputType and InputType.TYPE_MASK_CLASS
        if (node.className?.endsWith("EditText") == true) return true
        return cls == InputType.TYPE_CLASS_TEXT || cls == InputType.TYPE_CLASS_NUMBER
    }

    private fun isPasswordNode(node: AssistStructure.ViewNode): Boolean {
        if (node.autofillHints?.contains(View.AUTOFILL_HINT_PASSWORD) == true) return true
        val type = node.inputType
        val cls = type and InputType.TYPE_MASK_CLASS
        val variation = type and InputType.TYPE_MASK_VARIATION
        if (cls == InputType.TYPE_CLASS_TEXT && variation in intArrayOf(
                InputType.TYPE_TEXT_VARIATION_PASSWORD,
                InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
                InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
            )
        ) return true
        if (cls == InputType.TYPE_CLASS_NUMBER &&
            variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
        ) return true
        // Fallback: EditText whose resource-id entry or hint mentions a
        // password keyword.
        if (node.className?.endsWith("EditText") == true) {
            val hay = listOfNotNull(node.idEntry, node.hint).joinToString(" ").lowercase()
            if (hay.contains("password") || hay.contains("passwd") || hay.contains("pwd")) return true
        }
        return false
    }

    private fun isUsernameNode(node: AssistStructure.ViewNode): Boolean {
        val hints = node.autofillHints
        if (hints != null && hints.any {
                it == View.AUTOFILL_HINT_USERNAME || it == View.AUTOFILL_HINT_EMAIL_ADDRESS
            }
        ) return true
        val type = node.inputType
        val cls = type and InputType.TYPE_MASK_CLASS
        val variation = type and InputType.TYPE_MASK_VARIATION
        if (cls == InputType.TYPE_CLASS_TEXT && (
                variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
                    variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
                )
        ) return true
        val hay = listOfNotNull(node.idEntry, node.hint, node.text?.toString())
            .joinToString(" ")
            .lowercase()
        return USERNAME_KEYWORDS.any { hay.contains(it) }
    }

    // Deliberately excludes bare "user" — too many false positives
    // ("username or password", "user agreement", ...).
    private val USERNAME_KEYWORDS = listOf(
        "email", "username", "user_name", "login", "log_in", "account", "phone", "mobile"
    )
}
