#!/usr/bin/env bash
# WBS-905 installed-artifact restore drill: authenticated portable backup
# and verified restore end to end (ADR-008; TECHNICAL_DEBT.md TD-ROB-12
# residual "routine recovery drill remains for 1.0"; SECURITY_STATUS_MATRIX
# row "Authenticated portable backup and restore").
#
# Proves, against a throwaway vault in an isolated environment:
#   1. vault init + 3 credential entries (each decrypts);
#   2. `backup create` produces a .spbackup bundle; `backup verify --deep`
#      validates format, bounds, digest, manifest MAC, and full decrypt;
#   3. post-backup mutations (add + delete + edit) change the live vault;
#   4. `backup restore` (with the required --allow-replace acknowledgment)
#      brings back EXACTLY the 3 original entries; every entry decrypts to
#      its ORIGINAL secret and the mutations are absent;
#   5. restore is fail closed: without --allow-replace it refuses to
#      replace an existing vault.
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
# Usage:  bash scripts/drills/drill-backup-restore.sh [--build]

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
DRILL_LABEL="backup-restore"
_DRILL_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$_DRILL_LIB_DIR/lib.sh"

drill_setup
drill_header "authenticated backup + verified restore (ADR-008)"

MP="$(drill_gen_secret)"
SECRET_A="$(drill_gen_secret)"
SECRET_B="$(drill_gen_secret)"
SECRET_C="$(drill_gen_secret)"
SECRET_ADDED="$(drill_gen_secret)"
SECRET_EDITED="$(drill_gen_secret)"
drill_register_secret "$MP" "$SECRET_A" "$SECRET_B" "$SECRET_C" \
  "$SECRET_ADDED" "$SECRET_EDITED"

drill_log "[step] 1. init vault + 3 original entries"
drill_cli "$MP
$MP" init
drill_expect_ok "vault init"

drill_cli "$MP" add --title "Original One" --username "user-a" --password "$SECRET_A"
drill_expect_ok "add entry 1 (Original One)"
drill_cli "$MP" add --title "Original Two" --username "user-b" --password "$SECRET_B"
drill_expect_ok "add entry 2 (Original Two)"
drill_cli "$MP" add --title "Original Three" --username "user-c" --password "$SECRET_C"
drill_expect_ok "add entry 3 (Original Three)"

drill_log "[step] 2. backup create + deep verify"
BUNDLE="$DRILL_HOME/drill.spbackup"
drill_cli "$MP" backup create "$BUNDLE"
drill_expect_ok "backup create"
drill_expect_out_contains "create reports backup id" "backup_id:"
if [[ -f "$BUNDLE" ]]; then
  drill_pass "bundle file exists: \$DRILL_HOME/drill.spbackup"
else
  drill_fail "bundle file exists" "\$DRILL_HOME/drill.spbackup" "missing"
fi

drill_cli "$MP" backup verify --deep "$BUNDLE"
drill_expect_ok "backup verify --deep (format/bounds/digest/MAC + full decrypt)"
drill_expect_out_matches "deep verify counts 3 entries" '^  entries: +3 \('
drill_expect_out_matches "deep validation passed" '^  deep validation: +identity, slots, schema, full decrypt'

drill_log "[step] 3. mutate the live vault AFTER the backup"
drill_cli "$MP" add --title "PostBackup Fourth" --username "user-d" --password "$SECRET_ADDED"
drill_expect_ok "mutation: add a 4th entry"
drill_cli "$MP" delete 1 --force
drill_expect_ok "mutation: delete entry 1"
drill_cli "$MP" edit --id 2 --password "$SECRET_EDITED"
drill_expect_ok "mutation: edit entry 2's secret"

drill_cli "$MP" list
drill_expect_out_contains "live vault now has 3 entries (4 added - 1 deleted)" "Total: 3 entries"

drill_log "[step] 4. restore is fail closed without the acknowledgment flag"
drill_cli "$MP" backup restore "$BUNDLE"
drill_expect_error "restore WITHOUT --allow-replace refused (fail closed)"

drill_log "[step] 5. verified restore"
drill_cli "$MP" backup restore "$BUNDLE" --allow-replace
drill_expect_ok "backup restore --allow-replace"
drill_expect_out_contains "restore verified and complete" "Restore verified and complete"
drill_expect_out_matches "restore summary counts 3 entries" '^  entries: +3$'

drill_log "[step] 6. restored vault = exactly the 3 original entries"
drill_cli "$MP" list --show-passwords
drill_expect_ok "list --show-passwords with master password after restore"
drill_expect_out_contains "restored vault has 3 entries" "Total: 3 entries"
drill_expect_out_contains "entry 1 present again after restore" "Original One"
drill_expect_out_contains "entry 2 present again after restore" "Original Two"
drill_expect_out_contains "entry 3 present again after restore" "Original Three"
drill_expect_out_contains_raw "entry 1 decrypts to its ORIGINAL secret" "Password: $SECRET_A"
drill_expect_out_contains_raw "entry 2 decrypts to its ORIGINAL secret (edit undone)" "Password: $SECRET_B"
drill_expect_out_contains_raw "entry 3 decrypts to its ORIGINAL secret" "Password: $SECRET_C"
drill_expect_out_not_contains "post-backup ADD is absent" "PostBackup Fourth"
drill_expect_out_not_contains_raw "post-backup EDIT value is absent" "$SECRET_EDITED"

drill_cli "$MP" get 1
drill_expect_ok "get 1 after restore"
drill_expect_out_contains_raw "entry 1 get() decrypts to original secret" "Password: $SECRET_A"
drill_cli "$MP" get 2
drill_expect_ok "get 2 after restore"
drill_expect_out_contains_raw "entry 2 get() decrypts to original secret" "Password: $SECRET_B"
drill_cli "$MP" get 3
drill_expect_ok "get 3 after restore"
drill_expect_out_contains_raw "entry 3 get() decrypts to original secret" "Password: $SECRET_C"
drill_cli "$MP" get 4
drill_expect_error "post-backup 4th entry is gone after restore"

drill_finish
