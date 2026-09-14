# Dependency Exception Lifecycle (WBS-909 / TD-REL-04 / SR-SUPPLY-003)

Status: **Adopted 2026-09-11**. Owner: **core-maintainer**.

This document is the human-readable half of the dependency-exception
lifecycle. The machine-readable half is `.cargo/audit.toml`, which holds the
`ignore` list `cargo audit` actually applies. The two are kept in sync by
review discipline: every config ignore MUST have a register row here, and
every register row marked `config-ignore` MUST appear in the config file.

## Policy

1. **What gets excepted.** Only advisories that would FAIL `cargo audit`
   (unfixed vulnerability-class findings) may appear in the
   `.cargo/audit.toml` `ignore` list. Warning-class findings — unmaintained,
   unsound, yanked — do not fail the audit by default and are deliberately
   NOT suppressed: they stay visible in every audit run so accumulating
   dependency risk is seen, not hidden. They are registered here with the
   same governance metadata.
2. **Every exception has an owner.** The owner is the core-maintainer role
   (not an individual) unless a row names a specific subsystem owner.
3. **Every exception has an expiry.** The default term is one quarter.
   Expiry is a REVIEW deadline, not an automatic fix date: at review the
   exception is re-approved (with an updated assessment), remediated, or
   removed.
4. **Removal criteria (any one suffices):**
   - the advisory stops firing against `Cargo.lock` (upstream fix, feature
     change, or dependency removal) — dead exceptions are drift;
   - the exposure assessment is invalidated (a code path starts using the
     affected crate in the vulnerable way) — this is an escalation, and the
     finding moves to the release blocker register;
   - the expiry passes without an explicit re-approval at review;
   - the upstream advisory is withdrawn or superseded.
5. **Addition criteria.** A new exception requires a PR that (a) adds the
   config entry with metadata comments, (b) adds/updates the register row
   with owner + exposure assessment + expiry, and (c) states why the
   dependency cannot be upgraded or removed in the same change.
6. **Escalation.** Any advisory of severity HIGH/CRITICAL that fires on a
   release tag is a release blocker, not a register row: it must be fixed
   or explicitly re-assessed before the release/publish runs (the tag-time
   security audit jobs make this visible — release.yml, WBS-901 — and the
   escalation is recorded in `docs/RELEASE_BLOCKER_REGISTER.md`).

## Quarterly review

- **Next review: 2026-12-31.**
- The review re-runs a raw `cargo audit` (config set aside) and reconciles:
  new findings get rows; rows whose advisories stopped firing are removed;
  every expiry is re-approved or dropped.
- Review evidence (raw finding list + decisions) is appended to the
  session log in `TECHNICAL_DEBT.md`.

## Register — 2026-09-11 baseline

Raw audit run (config set aside) against the current lockfile: **1
vulnerability** (would fail) and **18 warning-class findings** (reported
only). Rows below cover each distinct advisory.

### Config-ignored (fail the audit if unignored)

| RUSTSEC | Crate (ver) | Class | Severity | Owner | Expiry | Exposure assessment | Review note / removal |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RUSTSEC-2023-0071 | rsa 0.9.10 | vulnerability | 5.9 medium | core-maintainer | 2026-12-31 | NOT REACHABLE: linked via ssh-key 0.6.7 and a direct sentinelpass-core dependency that no code uses (verified: no `use rsa` in the workspace); SSH RSA keygen shells out to `ssh-keygen`; no in-process RSA decrypt oracle exists in a local-first app with no network RSA surface. Marvin requires timing observation of RSA decryption — outside the threat model. | Remove when ssh-key ships a fixed rsa chain or the advisory is withdrawn. The unused direct `rsa` dep in sentinelpass-core is a removal candidate; ssh-key keeps the crate in the tree regardless. |

### Registered warnings (visible in audit output; do not fail)

| RUSTSEC | Crate (ver) | Class | Owner | Expiry | Exposure assessment | Review note / removal |
| --- | --- | --- | --- | --- | --- | --- |
| RUSTSEC-2025-0141 | bincode 1.3.3 | unmaintained | core-maintainer | 2026-12-31 | Direct core dep; legacy durable-format decode (`from_bincode_bytes`). Local, post-authentication parse of our own vault data — no untrusted-input surface. | Migration away is envelope-v2 scope (ADR-005); remove row when the last bincode codec is retired. |
| RUSTSEC-2021-0145 | atty 0.2.14 | unsound | core-maintainer | 2026-12-31 | Build tooling only: clap 3 → cbindgen → mobile-bridge FFI header generation. Not shipped in runtime binaries. | Remove when cbindgen/clap3 chain updates. |
| RUSTSEC-2024-0375 | atty 0.2.14 | unmaintained | core-maintainer | 2026-12-31 | Same path as RUSTSEC-2021-0145 (build tooling only). | Same removal condition as above. |
| RUSTSEC-2024-0370 | proc-macro-error 1.0.4 | unmaintained | core-maintainer | 2026-12-31 | Tauri/gtk3-macros proc-macro chain. Compile-time only. | Remove on the next Tauri minor that drops it. |
| RUSTSEC-2024-0388 | derivative 2.2.0 | unmaintained | core-maintainer | 2026-12-31 | zbus → secret-service → keyring (Linux OS keystore). Deref-macro codegen; no runtime secret handling. | Remove on keyring/zbus upgrade. |
| RUSTSEC-2025-0057 | fxhash 0.2.1 | unmaintained | core-maintainer | 2026-12-31 | selectors → kuchikiki → wry, and tauri-utils → kuchikiki (Tauri webview HTML processing). | Remove on wry/tauri upgrade. |
| RUSTSEC-2024-0384 | instant 0.1.13 | unmaintained | core-maintainer | 2026-12-31 | fastrand → futures-lite → async-io stack (zbus/async-process). Timing-shim crate. | Remove on the async-stack upgrade. |
| RUSTSEC-2025-0075 | unic-char-range 0.9.0 | unmaintained | core-maintainer | 2026-12-31 | Unicode tables via urlpattern → tauri-utils (Tauri URL matching). Static data. | Remove on tauri upgrade. |
| RUSTSEC-2025-0081 | unic-char-property 0.9.0 | unmaintained | core-maintainer | 2026-12-31 | Same urlpattern → tauri-utils path. | Remove on tauri upgrade. |
| RUSTSEC-2025-0080 | unic-common 0.9.0 | unmaintained | core-maintainer | 2026-12-31 | Same urlpattern → tauri-utils path. | Remove on tauri upgrade. |
| RUSTSEC-2025-0098 | unic-ucd-version 0.9.0 | unmaintained | core-maintainer | 2026-12-31 | Same urlpattern → tauri-utils path. | Remove on tauri upgrade. |
| RUSTSEC-2025-0100 | unic-ucd-ident 0.9.0 | unmaintained | core-maintainer | 2026-12-31 | Same urlpattern → tauri-utils path. | Remove on tauri upgrade. |
| RUSTSEC-2024-0429 | glib 0.18.5 | unsound | core-maintainer | 2026-12-31 | gtk-rs stack (Linux UI/webview). Iterator unsoundness requires specific `VariantStrIter` usage by gtk-rs internals, not our code. Linux-only. | Remove on gtk-rs 0.20 stack adoption by Tauri. |
| RUSTSEC-2026-0221 | event-listener 5.4.1 | unsound | core-maintainer | 2026-12-31 | async-lock/event-listener-strategy → zbus (Linux keystore D-Bus). Requires `!Send` listener tags crossing threads — not used by zbus's surface. | Remove on async-lock/zbus upgrade. |
| RUSTSEC-2026-0097 | rand 0.7.3 / 0.8.5 / 0.9.2 | unsound | core-maintainer | 2026-12-31 | Trigger is a CUSTOM GLOBAL `log` LOGGER combined with `rand::rng()`/thread-local generator — an application-configuration bug class, not a flaw in generator output. SentinelPass does not install a custom global logger that rand's ThreadRng would route through (the daemon/CLI use tracing with a fixed subscriber). rand 0.8.5 is a DIRECT workspace dependency and production code does use `thread_rng()` (`crypto/password.rs` generation, `vault/recovery.rs` recovery keys, `sync/device.rs` device-identity secrets) — ThreadRng is reseeded from the OS CSPRNG and is acceptable entropy-wise, but SECURITY-CRITICAL material should not depend on it; escalation watch: migrate key-material generation (recovery keys, device identity) to OsRng — tracked as TD-SEC-09. Flagged versions additionally arrive via phf (build-time), zbus, and quinn-proto/proptest. | Remove on quinn/proptest/zbus and phf-chain upgrades AND when the direct thread_rng usages for key material are migrated to OsRng (TD-SEC-09). |
| (no RUSTSEC id) | spin 0.9.8 | yanked | core-maintainer | 2026-12-31 | lazy_static → tao (Tauri windowing), tracing-subscriber/sharded-slab, keyring, num-bigint-dig, and a direct (jni-feature) sentinelpass-mobile-bridge dependency. Yank reflects republish policy, not a reported vulnerability. | Remove when the lazy_static consumers update their chains. |

### Removed at governance adoption (were in audit.toml, advisory no longer fires)

| RUSTSEC | Was | Reason removed |
| --- | --- | --- |
| RUSTSEC-2024-0413 | gtk-rs GTK3 bindings unmaintained ignore | No longer fires against the current lockfile (gtk-rs stack moved past the flagged versions). Removal criterion 1. |
| RUSTSEC-2026-0037 | quinn DoS (via tauri) | No longer fires: the tauri chain now pulls quinn-proto >= 0.11.14. Removal criterion 1. |

## Historical note

Before 2026-09-11 the ignore list carried nine entries with a single shared
comment and no owner/expiry metadata, and `security.yml` carried a
redundant inline `--ignore RUSTSEC-2023-0071`. The governance adoption
(2026-09-11) removed the inline flag (the config file is the single source
of audit policy), dropped the two dead entries, and stopped
config-ignoring warning-class findings so they stay visible in audit
output.
