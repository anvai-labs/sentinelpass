/**
 * Credential-choice policy (WBS-715, TD-CLIENT-06).
 *
 * Multiple matching credentials MUST surface an explicit chooser — never a
 * silent first-match. This module holds the pure decision; the content
 * script renders the chooser overlay and requests the chosen account's
 * secret only after the user picks.
 *
 * Pure module (no DOM, no `chrome.*`) so the policy is unit-testable.
 */
/**
 * Decide the autofill flow for the listed candidates.
 *
 * - Zero candidates → `none` (the caller shows "no credentials").
 * - Exactly one → `fill` immediately.
 * - Multiple → `choose` with the candidate list, UNLESS the user already
 *   picked a username (the chooser's callback re-enters here with
 *   `requestedUsername`, which wins and must match a candidate).
 */
export function decideCredentialChoice(candidates, requestedUsername) {
    if (candidates.length === 0) {
        return { action: 'none' };
    }
    if (requestedUsername) {
        const wanted = requestedUsername.trim().toLowerCase();
        const match = candidates.find((candidate) => candidate.username.trim().toLowerCase() === wanted);
        if (match) {
            return { action: 'fill', username: match.username };
        }
        // A requested username that is not among the candidates never falls
        // back to first-match — the chooser is shown instead.
    }
    if (candidates.length === 1) {
        return { action: 'fill', username: candidates[0].username };
    }
    return {
        action: 'choose',
        candidates: candidates.map((candidate) => ({
            username: candidate.username,
            title: candidate.title,
        })),
    };
}
