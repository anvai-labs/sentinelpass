/**
 * SentinelPass Desktop UI — shared application state.
 *
 * This module owns all mutable state that is accessed by more than one
 * module.  Because ES modules use **live bindings**, importers can read
 * exported `let` variables and see updates, but they **cannot reassign**
 * them.  Cross-module mutation therefore goes through the setter functions
 * exported here.
 */
// ---------------------------------------------------------------------------
// Tauri API bindings (late-bound via initTauriAPI)
// ---------------------------------------------------------------------------
/** Tauri `invoke` bridge — call Rust commands. */
export let invoke;
/** Tauri `confirm` dialog helper. */
export let confirm;
/**
 * Detect the Tauri runtime and bind its core API helpers.
 *
 * Must be called before any `invoke` or `confirm` operations. Clipboard
 * secrets go through the `copy_secret_to_clipboard` command instead of the
 * clipboard plugin (WBS-709), so no clipboard bindings exist here.
 *
 * @returns `true` if the Tauri API is available, `false` otherwise.
 */
export function initTauriAPI() {
    if (window.__TAURI__) {
        invoke = window.__TAURI__.core.invoke;
        confirm = window.__TAURI__.dialog.confirm;
        return true;
    }
    return false;
}
// ---------------------------------------------------------------------------
// Mutable application state + setters
// ---------------------------------------------------------------------------
/** The currently-selected vault entry, or `null`. */
export let currentEntry = null;
/** Set the currently-selected vault entry. */
export function setCurrentEntry(v) {
    currentEntry = v;
}
/** All loaded vault entries. */
export let entries = [];
/** Replace the full entry list. */
export function setEntries(v) {
    entries = v;
}
/** Normalised TOTP metadata for the current entry, or `null`. */
export let currentTotpMetadata = null;
/** Set the current TOTP metadata. */
export function setCurrentTotpMetadata(v) {
    currentTotpMetadata = v;
}
/** The active sidebar filter (`"all"` or `"favorites"`). */
export let currentFilter = 'all';
/** Set the active sidebar filter. */
export function setCurrentFilter(v) {
    currentFilter = v;
}
/** Guard flag preventing concurrent entry refreshes. */
export let entriesRefreshInFlight = false;
/** Set the entries-refresh-in-flight guard. */
export function setEntriesRefreshInFlight(v) {
    entriesRefreshInFlight = v;
}
// ---------------------------------------------------------------------------
// DOM element cache (safe at module-load — script is at end of body)
// ---------------------------------------------------------------------------
/** The main vault screen container. */
export const vaultScreen = document.getElementById('vault-screen');
/** The sidebar entry list container. */
export const entryList = document.getElementById('entry-list');
/** The sidebar search input. */
export const searchInput = document.getElementById('search-input');
/** The "no entry selected" placeholder. */
export const noSelection = document.getElementById('no-selection');
/** The entry detail pane. */
export const entryDetail = document.getElementById('entry-detail');
