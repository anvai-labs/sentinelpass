#!/usr/bin/env bash
# WBS-905 compromise-rotation drill: master-password rotation as compromise
# response (ADR-002; ADR-004 rev 4 epoch advance; SECURITY_STATUS_MATRIX
# row "Key hierarchy and password rotation").
#
# Proves, against a throwaway vault in an isolated environment:
#   1. vault init + credential entry;
#   2. `passwd` rotation (old -> new password) re-wraps the DEK (entries
#      are not re-encrypted) and ADVANCES the key epoch;
#   3. the NEW password unlocks and the data decrypts intact;
#   4. the OLD password FAILS (fail closed — a stolen old password is dead
#      against the rotated vault);
#   5. the password slot surface reports exactly one usable slot (the new
#      password) after rotation.
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
# Env:    DRILL_REPORT_DIR, SENTINELPASS_BIN_DIR, DRILL_KEEP=1, DRILL_TMP_BASE.
# Usage:  bash scripts/drills/drill-compromise-rotation.sh [--build]

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
DRILL_LABEL="compromise-rotation"
_DRILL_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$_DRILL_LIB_DIR/lib.sh"

drill_setup
drill_header "compromise rotation via passwd (ADR-002/ADR-004 rev 4)"

MP_OLD="$(drill_gen_secret)"
MP_NEW="$(drill_gen_secret)"
ENTRY_SECRET="$(drill_gen_secret)"
drill_register_secret "$MP_OLD" "$MP_NEW" "$ENTRY_SECRET"

drill_log "[step] 1. init vault + one credential"
drill_cli "$MP_OLD
$MP_OLD" init
drill_expect_ok "vault init"

drill_cli "$MP_OLD" add --title "Rotation Drill" --username "drill-user" \
  --password "$ENTRY_SECRET"
drill_expect_ok "add credential entry"

drill_log "[step] 2. record the pre-rotation key epoch"
drill_cli "" status
drill_expect_ok "password-free vault status"
EPOCH_BEFORE="$(drill_extract_epoch)"
if [[ -n "$EPOCH_BEFORE" ]]; then
  drill_pass "pre-rotation key epoch surfaced: $EPOCH_BEFORE"
else
  drill_fail "pre-rotation key epoch surfaced" "'key epoch:' line in status output" "none found"
  drill_finish
fi

drill_log "[step] 3. rotate the master password (compromise response)"
drill_cli "$MP_OLD
$MP_NEW
$MP_NEW" passwd
drill_expect_ok "passwd rotation old -> new"
drill_expect_out_contains "rotation reports the epoch advance" "Master password rotated (key epoch"

drill_log "[step] 4. post-rotation state"
drill_cli "" status
drill_expect_ok "password-free vault status after rotation"
EPOCH_AFTER="$(drill_extract_epoch)"
if [[ -n "$EPOCH_AFTER" && "$EPOCH_AFTER" -gt "$EPOCH_BEFORE" ]]; then
  drill_pass "key epoch advanced: $EPOCH_BEFORE -> $EPOCH_AFTER"
else
  drill_fail "key epoch advanced" \
    "epoch > $EPOCH_BEFORE" "epoch=$(printf '%s' "${EPOCH_AFTER:-<none>}")"
fi

# TODO(WBS-905 follow-up): assert that the OLD epoch's SLOTS are revoked
# once the CLI exposes a richer status surface (per-slot type/epoch/usable
# listing). Today the CLI surfaces only `recovery status`'s aggregate
# usable-slot count and `status`'s plaintext key epoch; per-slot revocation
# at the old epoch is enforced in core (`vault/slot_ops.rs`, stale-epoch
# UPDATE guard + registry MAC) and covered by unit tests there.

drill_cli "$MP_NEW" recovery status
drill_expect_ok "recovery status with NEW password after rotation"
drill_expect_out_contains "exactly one usable slot (the new password wrap)" \
  "Usable key slots: 1"

drill_log "[step] 5. new password unlocks; data intact (no re-encryption needed)"
drill_cli "$MP_NEW" get 1
drill_expect_ok "entry 1 readable with NEW master password"
drill_expect_out_contains_raw "credential decrypts identically after rotation" "$ENTRY_SECRET"

drill_log "[step] 6. old password must FAIL (fail closed)"
drill_cli "$MP_OLD" recovery status
drill_expect_error "old master password rejected after rotation"

drill_cli "$MP_OLD" get 1
drill_expect_error "old master password cannot read entries"

drill_log "[step] 7. containment cross-check: custom paths are never daemon-served"
drill_cli_nocompat "$MP_NEW" list
drill_expect_error "custom --vault without the flagged compat path is refused (ADR-007)"

drill_finish
