#!/usr/bin/env bash
# WBS-905 recovery drill: forgotten-master-password recovery end to end
# (ADR-004; TECHNICAL_DEBT.md TD-SEC-03 residual "recovery drill remains";
# docs/SECURITY_STATUS_MATRIX.md row "Forgotten-password recovery").
#
# Proves, against a throwaway vault in an isolated environment:
#   1. vault init + credential round-trip;
#   2. `recovery setup` displays a 256-bit checksummed key once and requires
#      verified re-entry (SR-RECOVERY-002);
#   3. `recovery recover` restores access WITHOUT the old password;
#   4. the NEW password unlocks and decrypts the pre-recovery credential;
#   5. the OLD password FAILS (fail closed);
#   6. the used recovery slot is single-use: a second recovery with the
#      same key FAILS, and `recovery status` reports no usable recovery
#      slot afterwards.
#
# Prerequisites: a built `sentinelpass` CLI. RELEASE profile required in
# practice: the drills run a dozen-plus full Argon2id ops and a debug build
# takes minutes per KDF (a debug build works only with
# DRILL_PTY_TIMEOUT_SECONDS raised to several hundred seconds per step).
#   cargo build --release -p sentinelpass-cli
# The script does NOT build anything by default. Resolve order:
#   $SENTINELPASS_BIN_DIR/sentinelpass, then $PATH, then
#   <repo>/target/release, then <repo>/target/debug.
# Flags: --build   run `cargo build --release -p sentinelpass-cli` first.
# Env:    DRILL_REPORT_DIR (default: invocation directory),
#         SENTINELPASS_BIN_DIR, DRILL_KEEP=1 (keep the temp environment),
#         DRILL_TMP_BASE.
# Usage:  bash scripts/drills/drill-recovery.sh [--build]

# --build: build the CLI first (opt-in; CI and local default assume the
# binary already exists).
for arg in "$@"; do
  case "$arg" in
    --build)
      echo "[drill] --build: cargo build --release -p sentinelpass-cli"
      cargo build --release -p sentinelpass-cli
      ;;
    *)
      echo "usage: $0 [--build]" >&2
      exit 2
      ;;
  esac
done

# Read by lib.sh after `source` (drill report naming).
# shellcheck disable=SC2034
DRILL_LABEL="recovery"
_DRILL_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$_DRILL_LIB_DIR/lib.sh"

drill_setup
drill_header "forgotten-password recovery (ADR-004)"

# Runtime secrets — throwaway, CSPRNG, redacted in the transcript.
MP_ORIG="$(drill_gen_secret)"     # original master password
MP_NEW="$(drill_gen_secret)"      # post-recovery master password
MP_UNUSED="$(drill_gen_secret)"   # second-recovery attempt password (must never take effect)
ENTRY_SECRET="$(drill_gen_secret)"
drill_register_secret "$MP_ORIG"
drill_register_secret "$MP_NEW"
drill_register_secret "$MP_UNUSED"
drill_register_secret "$ENTRY_SECRET"

drill_log "[step] 1. init vault + credential round-trip"
drill_cli "$MP_ORIG
$MP_ORIG" init
drill_expect_ok "vault init"
drill_expect_out_contains "init reports vault created" "Vault created successfully"

drill_cli "$MP_ORIG" add --title "Drill Credential" --username "drill-user" \
  --password "$ENTRY_SECRET" --url "https://drill.example"
drill_expect_ok "add credential entry"
drill_expect_out_contains "add reports entry id" "Entry created with ID: 1"

drill_cli "$MP_ORIG" get 1
drill_expect_ok "read back entry 1 before recovery"
drill_expect_out_contains_raw "entry secret decrypts before recovery" "$ENTRY_SECRET"

drill_log "[step] 2. recovery setup (key shown once, verified re-entry)"
# The driver plays the human: it reads the displayed key from the child's
# output and types it back at the re-entry prompt (SR-RECOVERY-002).
KEY_PATTERN='    ([A-Z0-9-]{40,})'
drill_cli_respond "$KEY_PATTERN"$'\t''\1' "$MP_ORIG" recovery setup
drill_expect_ok "recovery setup"
RECOVERY_KEY="$(drill_extract_recovery_key)"
if [[ -n "$RECOVERY_KEY" ]]; then
  drill_pass "recovery key captured from setup output"
else
  drill_fail "recovery key captured from setup output" \
    "a 4-space-indented dashed key line" "no matching line in output"
  drill_finish
fi
drill_register_secret "$RECOVERY_KEY"
# The key was echoed by the pty before rpassword disabled echo — scrub the
# transcript now that it is registered.
drill_scrub_report
# 9 groups of 6 Crockford symbols = 54 chars + 8 dashes = 62 chars.
if [[ ${#RECOVERY_KEY} -eq 62 && "$(printf '%s' "$RECOVERY_KEY" | tr -d '-' | wc -c | tr -d ' ')" -eq 54 ]]; then
  drill_pass "key shape: 9 dashed groups of 6 symbols (54 symbols)"
else
  drill_fail "key shape: 9 dashed groups of 6 symbols (54 symbols)" \
    "62 chars incl. dashes" "${#RECOVERY_KEY} chars: [REDACTED]"
fi

# The CLI is stateless between invocations (the vault locks when the
# process drops it), so every drill step below is already a FRESH session —
# the "forgotten password" simulation is that no step ever uses MP_ORIG
# again except to prove it fails.

drill_log "[step] 3. recovery recover (no old password)"
drill_cli "$RECOVERY_KEY
$MP_NEW
$MP_NEW" recovery recover
drill_expect_ok "recovery recover with captured key + new password"
drill_expect_out_contains "recover reports success + slot revocation" "Access recovered"

drill_log "[step] 4. new password unlocks; credential intact"
drill_cli "$MP_NEW" get 1
drill_expect_ok "entry 1 readable with NEW master password"
drill_expect_out_contains_raw "credential decrypts identically after recovery" "$ENTRY_SECRET"

drill_cli "$MP_NEW" recovery status
drill_expect_ok "recovery status with NEW password"
drill_expect_out_contains "post-recovery slot state: recovery slot revoked" \
  "Recovery slot: NOT configured"
drill_expect_out_contains "exactly one usable slot remains (the new password)" \
  "Usable key slots: 1"

drill_log "[step] 5. old password must FAIL (fail closed)"
drill_cli "$MP_ORIG" recovery status
drill_expect_error "old master password rejected after recovery"

drill_log "[step] 6. the used recovery slot is single-use"
drill_cli "$RECOVERY_KEY
$MP_UNUSED
$MP_UNUSED" recovery recover
drill_expect_error "second recovery with the SAME key rejected"

drill_cli "$MP_NEW" recovery status
drill_expect_ok "vault still openable with the NEW password after refused reuse"
drill_expect_out_contains "no usable recovery slot after refused reuse" \
  "Recovery slot: NOT configured"

drill_log "[step] 7. containment cross-check: custom paths are never daemon-served"
drill_cli_nocompat "$MP_NEW" list
drill_expect_error "custom --vault without the flagged compat path is refused (ADR-007)"

drill_finish
