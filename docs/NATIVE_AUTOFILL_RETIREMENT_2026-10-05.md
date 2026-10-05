# Native autofill prototype retirement

The Windows build used to warn about a handwritten `GetWindowTextW` FFI declaration
with a Rust slice in place of a Win32 buffer pointer. Review also found incorrectly
laid-out keyboard input structures, Unicode/modifier loss, credential characters
in error messages, and clipboard memory without the required allocation/ownership
and terminating NUL. These are concrete defects, not a general Windows safety
assessment. No exploit or credential disclosure was demonstrated.

## Decision

Retire credential search/delivery in the unshipped native-autofill prototype on
Windows, macOS and Linux. A repository-wide call-site search found no shipped
UI, CLI, daemon or native-host caller of `AutoFillManager` or the platform-specific
delivery functions. The browser extension uses separate daemon-authorized IPC;
its implementation and explicit desktop Copy actions are unchanged.

Merely correcting native bindings would preserve unsafe authority assumptions:
window titles are attacker-controlled, matching previously admitted every entry
with a nonempty username, entry IDs and a borrowed `VaultManager` bypass daemon
authorization, and foreground keyboard injection lacks field/focus binding and
can submit a form. Clipboard delivery also lacked bounded retention and ownership
handling. macOS/Linux have the same direct-vault design, so their equivalent
paths are retired in the same change rather than leaving a platform fallback.

Public signatures/types remain for source compatibility; calls now return
`PasswordManagerError::NotImplemented` before vault or desktop access. This is an
intentional behavior change for any external embedder using the prototype. There
is no environment-variable bypass. Unsafe clipboard, input simulation, title-domain
heuristics and hotkey-registration implementations are removed, not left dormant.
The Windows read-only diagnostic context uses generated `windows` bindings, a
512-code-unit title buffer, and always reports `domain: None`. Titles are untrusted
display metadata. macOS/Linux prototype context acquisition is disabled too.
The `x11` feature flag remains accepted for compatibility, but the now-unused
Xlib/XTest dependency is removed; enabling the flag cannot reactivate delivery.

## Reintroduction requirements

Native application autofill is a future feature, not claimed fixed or supported by
this retirement. Reintroduction requires daemon-mediated field-scoped retrieval,
an explicit user gesture, verified application identity, binding to a specific
destination/field with focus-change denial, no implicit form submission, and an
audited/zeroizing secret lifecycle. Clipboard use must be explicit and separately
qualified for ownership, timeout clearing that preserves newer user clipboard
content, and OS clipboard-history/cloud-sync behavior. Do not use titles or process
names as authority. Use generated platform bindings or an evaluated library;
qualification must include non-ASCII input, focus races and denied destinations.

## Validation scope

Regression tests use an uninitialized in-memory vault with no key/schema/logger:
an accidental vault read would return a different error than the required disabled
result. Windows title tests create invisible test-owned windows with empty,
spoofed-domain, Unicode and oversized titles; they do not set foreground focus,
send keystrokes, access the clipboard, or use production credentials. Null handles
are rejected. These tests run in ordinary Windows CI, not behind an ignored test.
Record native run and CI results in the PR; passing these checks does not qualify
native autofill as a shipped feature.

Also correct the stale revocation comment from the PR #252 review: publication can
already have occurred when durability confirmation fails. Runtime behavior is
unchanged by that comment correction.

Primary API contracts:
[GetWindowTextW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowtextw),
[SetClipboardData](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setclipboarddata),
[SendInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput).
