#!/usr/bin/env bash
# Shared library for the WBS-905 drills (ADR-003 rev 3 blocking 1.0 drill
# gates; TD-REL-05). Sources: docs/SECURITY_STATUS_MATRIX.md rows
# "Forgotten-password recovery" and "Authenticated portable backup and
# restore"; TECHNICAL_DEBT.md TD-SEC-03 / TD-ROB-12 residual notes.
#
# What this library guarantees:
#   ISOLATION  - every drill runs inside a fresh `mktemp -d` environment:
#                HOME and the FULL XDG family (XDG_CONFIG_HOME,
#                XDG_DATA_HOME, XDG_CACHE_HOME, XDG_STATE_HOME,
#                XDG_RUNTIME_DIR) are overridden into it, and the vault is
#                an explicit custom `--vault` path inside it. The `dirs`
#                crate derives every default path from these variables on
#                Linux/macOS (same isolation model as
#                browser-extension/e2e/tests/helpers/daemon-harness.ts),
#                so the drills cannot reach a real user installation by
#                construction. (Windows is NOT covered: the dirs crate
#                ignores HOME/XDG_* there — see .github/workflows/drills.yml.)
#   SECRETS    - master passwords / recovery keys are generated at runtime
#                via `openssl rand` (CSPRNG) and are never hardcoded; every
#                generated secret is registered for REDACTION before any
#                output is written to the evidence transcript.
#   FAIL-CLOSED- assertion helpers count failures and `drill_finish` exits
#                nonzero when any assertion failed.
#
# Usage (inside a drill script):
#   DRILL_LABEL="recovery"; source "$(dirname "$0")/lib.sh"
#   drill_setup
#   ... drill_cli / drill_expect_* ...
#   drill_finish

set -euo pipefail

# Directory this library lives in (for the pty driver). shellcheck disable=SC2034
_DRILL_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DRILL_LABEL="${DRILL_LABEL:-drill}"
# Evidence transcript: next to the invocation directory unless overridden.
DRILL_REPORT_DIR="${DRILL_REPORT_DIR:-$PWD}"
DRILL_TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DRILL_REPORT="$DRILL_REPORT_DIR/drill-report-$DRILL_LABEL-$DRILL_TIMESTAMP.txt"
# Keep the isolated environment on failure (or always, with DRILL_KEEP=1)
# for post-mortem; default is to remove it on success.
DRILL_KEEP="${DRILL_KEEP:-}"
# Where prebuilt binaries are found: $SENTINELPASS_BIN_DIR, else $PATH.
SENTINELPASS_BIN_DIR="${SENTINELPASS_BIN_DIR:-}"

DRILL_PASS_COUNT=0
DRILL_FAIL_COUNT=0
DRILL_SECRETS=()
DRILL_WORK=""
DRILL_SEQ=0

if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
  DRILL_C_PASS=$'\033[32m'
  DRILL_C_FAIL=$'\033[31m'
  DRILL_C_RESET=$'\033[0m'
else
  DRILL_C_PASS="" DRILL_C_FAIL="" DRILL_C_RESET=""
fi

# ---------------------------------------------------------------------------
# Logging / evidence transcript
# ---------------------------------------------------------------------------

drill_log() {
  printf '%s\n' "$1" | tee -a "$DRILL_REPORT"
}

# Redact every registered runtime secret before text reaches the transcript.
drill_redact() {
  local text="$1"
  local secret
  # "${arr[@]+...}" keeps bash 3.2 (macOS system bash) happy under set -u
  # when no secret has been registered yet.
  for secret in ${DRILL_SECRETS[@]+"${DRILL_SECRETS[@]}"}; do
    [[ -n "$secret" ]] || continue
    text="${text//"$secret"/[REDACTED]}"
  done
  printf '%s' "$text"
}

drill_header() {
  {
    echo "======================================================================="
    echo "SentinelPass drill: $1 (WBS-905)"
    echo "Started (UTC): $DRILL_TIMESTAMP"
    echo "Host: $(uname -s -r) | CLI: $(_drill_cli_description)"
    echo "Runtime secrets are generated per-run and [REDACTED] in this transcript."
    echo "======================================================================="
  } > "$DRILL_REPORT"
  drill_log "[env] isolated environment: $DRILL_HOME (removed on success unless DRILL_KEEP=1)"
}

_drill_cli_description() {
  if [[ -n "${SENTINELPASS_BIN:-}" ]]; then
    printf '%s' "$SENTINELPASS_BIN"
  else
    printf 'sentinelpass (resolved at drill_setup)'
  fi
}

# ---------------------------------------------------------------------------
# Setup / teardown
# ---------------------------------------------------------------------------

# Resolve the CLI binary and create the isolated environment.
drill_setup() {
  # CLI resolution: explicit dir first, then the REPO's own builds, then
  # PATH last. Drills verify THIS tree's behavior — an installed app found
  # on PATH can be several releases behind (proven 2026-09-13: an
  # installed 0.10.0 predates the ADR-007 custom-path refusal, which
  # silently flipped the containment assertion to a false failure).
  # Release preferred: a debug-profile Argon2id takes minutes per KDF.
  local repo_root
  repo_root="$(cd "$_DRILL_LIB_DIR/../.." && pwd)"
  SENTINELPASS_BIN=""
  if [[ -n "$SENTINELPASS_BIN_DIR" ]]; then
    SENTINELPASS_BIN="$SENTINELPASS_BIN_DIR/sentinelpass"
  elif [[ -x "$repo_root/target/release/sentinelpass" ]]; then
    SENTINELPASS_BIN="$repo_root/target/release/sentinelpass"
  elif [[ -x "$repo_root/target/debug/sentinelpass" ]]; then
    SENTINELPASS_BIN="$repo_root/target/debug/sentinelpass"
  else
    SENTINELPASS_BIN="$(command -v sentinelpass || true)"
  fi
  if [[ -z "$SENTINELPASS_BIN" || ! -x "$SENTINELPASS_BIN" ]]; then
    echo "FATAL: sentinelpass CLI not found." >&2
    echo "Build it first (RELEASE profile: debug Argon2id is minutes-slow):" >&2
    echo "  cargo build --release -p sentinelpass-cli" >&2
    echo "then either put target/release on PATH or set SENTINELPASS_BIN_DIR=target/release," >&2
    echo "or re-run the drill with --build (see the script header)." >&2
    exit 2
  fi

  local tmp_base="${DRILL_TMP_BASE:-${TMPDIR:-/tmp}}"
  DRILL_HOME="$(mktemp -d "$tmp_base/sp-drill-${DRILL_LABEL}-XXXXXX")"

  # Paranoia guard: refuse to run anywhere that is not a per-run temp dir.
  case "$DRILL_HOME" in
    /tmp/*|/private/tmp/*|/var/folders/*|"$tmp_base"/*) ;;
    *)
      echo "FATAL: refusing non-temp isolation dir: $DRILL_HOME" >&2
      exit 2
      ;;
  esac

  # FULL XDG family (matches daemon-harness.ts isolatedEnv): on Linux the
  # dirs crate PREFERS XDG_* over HOME, so each variable must be overridden.
  export HOME="$DRILL_HOME"
  export XDG_CONFIG_HOME="$DRILL_HOME/.config"
  export XDG_DATA_HOME="$DRILL_HOME/.local/share"
  export XDG_CACHE_HOME="$DRILL_HOME/.cache"
  export XDG_STATE_HOME="$DRILL_HOME/.local/state"
  export XDG_RUNTIME_DIR="$DRILL_HOME/runtime"
  mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" \
           "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"

  # Custom vault path: never the default vault, therefore never
  # daemon-served (ADR-007); the connect() backend needs the flagged
  # direct-vault compat window (WBS-502/503) for vault-op commands.
  DRILL_VAULT="$DRILL_HOME/vault.db"
  export SENTINELPASS_ALLOW_DIRECT_VAULT=1

  DRILL_WORK="$DRILL_HOME/.drill-out"
  mkdir -p "$DRILL_WORK"

  # Uncaught-abort backstop: the EXIT trap guarantees the transcript is
  # scrubbed and the temp environment removed even when the drill dies
  # between secret capture and an explicit drill_finish (signal, OOM,
  # disk-full, a set -e trip on an unguarded command). Idempotent with the
  # explicit early-abort/end-of-script calls — first invocation wins.
  trap drill_finish EXIT
}

drill_cleanup() {
  if [[ -n "$DRILL_KEEP" || "$DRILL_FAIL_COUNT" -gt 0 ]]; then
    drill_log "[env] isolated environment KEPT for inspection: $DRILL_HOME"
  else
    rm -rf "$DRILL_HOME"
  fi
}

# Generate a throwaway secret (hex: safe to pass as argv/stdin, CSPRNG).
drill_gen_secret() {
  openssl rand -hex 16
}

# Register value(s) for redaction in the transcript.
drill_register_secret() {
  local v
  for v in "$@"; do
    DRILL_SECRETS+=("$v")
  done
}

# ---------------------------------------------------------------------------
# CLI invocation (pty driver)
# ---------------------------------------------------------------------------

# Run the CLI under a pty with the given stdin (rpassword prompts need a
# real terminal). Sets DRILL_RC and DRILL_OUT (path to captured output).
# NEVER logs the stdin (it carries the passwords).
# Every stdin payload MUST terminate with a newline — rpassword reads to
# the line terminator, and a missing final newline makes the LAST prompt
# block forever (same convention as the E2E harness's SENTINELPASS_CLI_STDIN).
drill_cli() {
  local stdin_data="$1"; shift
  if [[ -n "$stdin_data" && "$stdin_data" != *$'\n' ]]; then
    stdin_data+=$'\n'
  fi
  DRILL_SEQ=$((DRILL_SEQ + 1))
  DRILL_OUT="$DRILL_WORK/out.$DRILL_SEQ"
  DRILL_RC=0
  SENTINELPASS_CLI_STDIN="$stdin_data" \
    python3 "$(_drill_lib_dir)/cli_pty.py" \
    "$SENTINELPASS_BIN" --vault "$DRILL_VAULT" "$@" \
    > "$DRILL_OUT" 2>&1 || DRILL_RC=$?
  {
    printf '$ sentinelpass --vault <isolated> %s\n' "$(drill_redact "$*")"
    drill_redact "$(cat "$DRILL_OUT")" | sed 's/^/    /'
    printf '    [exit: %s]\n' "$DRILL_RC"
  } >> "$DRILL_REPORT" 2>&1
}

# Same, but for the deliberate containment check: run with the flagged
# direct-vault compat path DISABLED (proves custom paths fail closed
# without it).
drill_cli_nocompat() {
  local stdin_data="$1"; shift
  if [[ -n "$stdin_data" && "$stdin_data" != *$'\n' ]]; then
    stdin_data+=$'\n'
  fi
  DRILL_SEQ=$((DRILL_SEQ + 1))
  DRILL_OUT="$DRILL_WORK/out.$DRILL_SEQ"
  DRILL_RC=0
  env -u SENTINELPASS_ALLOW_DIRECT_VAULT \
    SENTINELPASS_CLI_STDIN="$stdin_data" \
    python3 "$(_drill_lib_dir)/cli_pty.py" \
    "$SENTINELPASS_BIN" --vault "$DRILL_VAULT" "$@" \
    > "$DRILL_OUT" 2>&1 || DRILL_RC=$?
  {
    printf '$ (no compat env) sentinelpass --vault <isolated> %s\n' "$(drill_redact "$*")"
    drill_redact "$(cat "$DRILL_OUT")" | sed 's/^/    /'
    printf '    [exit: %s]\n' "$DRILL_RC"
  } >> "$DRILL_REPORT" 2>&1
}

# Like drill_cli, but additionally teaches the pty driver to respond ONCE
# to a pattern in the child's output: RESPOND_SPEC is "<regex>\t<template>"
# ("\1" = first capture group). Used for `recovery setup`'s verified
# re-entry: the driver reads the displayed key and "types it back" exactly
# like a human, exercising SR-RECOVERY-002 rather than bypassing it.
drill_cli_respond() {
  local respond_spec="$1"; shift
  local stdin_data="$1"; shift
  if [[ -n "$stdin_data" && "$stdin_data" != *$'\n' ]]; then
    stdin_data+=$'\n'
  fi
  DRILL_SEQ=$((DRILL_SEQ + 1))
  DRILL_OUT="$DRILL_WORK/out.$DRILL_SEQ"
  DRILL_RC=0
  SENTINELPASS_CLI_STDIN="$stdin_data" \
    DRILL_PTY_RESPOND="$respond_spec" \
    python3 "$(_drill_lib_dir)/cli_pty.py" \
    "$SENTINELPASS_BIN" --vault "$DRILL_VAULT" "$@" \
    > "$DRILL_OUT" 2>&1 || DRILL_RC=$?
  {
    printf '$ sentinelpass --vault <isolated> %s (auto re-entry of displayed key)\n' "$(drill_redact "$*")"
    drill_redact "$(cat "$DRILL_OUT")" | sed 's/^/    /'
    printf '    [exit: %s]\n' "$DRILL_RC"
  } >> "$DRILL_REPORT" 2>&1
}

_drill_lib_dir() {
  printf '%s' "${_DRILL_LIB_DIR:?lib.sh must be sourced, not executed}"
}

# ---------------------------------------------------------------------------
# Assertions — every one prints what it expected vs what it got
# ---------------------------------------------------------------------------

drill_pass() {
  DRILL_PASS_COUNT=$((DRILL_PASS_COUNT + 1))
  drill_log "${DRILL_C_PASS}PASS${DRILL_C_RESET}: $1"
}

drill_fail() {
  DRILL_FAIL_COUNT=$((DRILL_FAIL_COUNT + 1))
  drill_log "${DRILL_C_FAIL}FAIL${DRILL_C_RESET}: $1"
  drill_log "  expected: $2"
  drill_log "  got:      $3"
}

drill_expect_rc() {
  local want="$1" label="$2" matched=0
  if [[ "$want" == "nonzero" ]]; then
    [[ "$DRILL_RC" -ne 0 ]] && matched=1
  else
    [[ "$DRILL_RC" == "$want" ]] && matched=1
  fi
  if [[ "$matched" -eq 1 ]]; then
    drill_pass "$label (exit=$want)"
  else
    drill_fail "$label" "exit=$want" "exit=$DRILL_RC"
  fi
}

drill_expect_ok()    { drill_expect_rc 0 "$1"; }
drill_expect_error() { drill_expect_rc nonzero "$1"; }

drill_expect_out_contains() {
  local label="$1" needle="$2" redacted
  redacted="$(drill_redact "$(cat "$DRILL_OUT")")"
  if printf '%s' "$redacted" | grep -qF -- "$needle"; then
    drill_pass "$label"
  else
    drill_fail "$label" "output contains: $needle" \
      "output: $(printf '%s' "$redacted" | head -c 600 | tr '\n' ' ')"
  fi
}

# Variants that match against the RAW output (before redaction) — required
# when the needle IS a registered secret (e.g. "the entry's password value
# appears in get output"). The transcript is still redacted on failure.
drill_expect_out_contains_raw() {
  local label="$1" needle="$2"
  if grep -qF -- "$needle" "$DRILL_OUT"; then
    drill_pass "$label"
  else
    drill_fail "$label" "output contains: [REDACTED needle]" \
      "output: $(drill_redact "$(head -c 600 "$DRILL_OUT")" | tr '\n' ' ')"
  fi
}

drill_expect_out_not_contains_raw() {
  local label="$1" needle="$2"
  if grep -qF -- "$needle" "$DRILL_OUT"; then
    drill_fail "$label" "output does NOT contain: [REDACTED needle]" \
      "output contains it: $(drill_redact "$(head -c 600 "$DRILL_OUT")" | tr '\n' ' ')"
  else
    drill_pass "$label"
  fi
}

drill_expect_out_not_contains() {
  local label="$1" needle="$2" redacted
  redacted="$(drill_redact "$(cat "$DRILL_OUT")")"
  if printf '%s' "$redacted" | grep -qF -- "$needle"; then
    drill_fail "$label" "output does NOT contain: $needle" \
      "output contains it: $(printf '%s' "$redacted" | head -c 600 | tr '\n' ' ')"
  else
    drill_pass "$label"
  fi
}

# Regex variant (ERE) for whitespace-insensitive matching of formatted
# report lines, e.g. '^  entries: +3$'. CR is stripped first (the pty
# converts the CLI's LF output to CRLF).
drill_expect_out_matches() {
  local label="$1" pattern="$2" redacted
  redacted="$(drill_redact "$(cat "$DRILL_OUT")" | tr -d '\r')"
  if printf '%s\n' "$redacted" | grep -qE -- "$pattern"; then
    drill_pass "$label"
  else
    drill_fail "$label" "output matches: $pattern" \
      "output: $(printf '%s' "$redacted" | head -c 600 | tr '\n' ' ')"
  fi
}

# Extract the recovery key from `recovery setup` output: displayed once as
# 9 groups of 6 Crockford symbols joined by dashes, on its own line with a
# 4-space indent.
drill_extract_recovery_key() {
  tr -d '\r' < "$DRILL_OUT" | sed -n 's/^    \([A-Z0-9-]\{40,\}\)$/\1/p' | head -1
}

# Re-apply redaction over the WHOLE transcript. Called after a secret that
# was only learned mid-drill (e.g. the recovery key displayed by
# `recovery setup`) is registered — the pty echoes typed input before
# rpassword disables echo, so secrets can appear in captured output.
# Idempotent.
drill_scrub_report() {
  local scrubbed
  scrubbed="$(drill_redact "$(cat "$DRILL_REPORT")")"
  printf '%s\n' "$scrubbed" > "$DRILL_REPORT"
}

# Extract `key epoch:      N` from `sentinelpass status`.
drill_extract_epoch() {
  tr -d '\r' < "$DRILL_OUT" | sed -n 's/^[[:space:]]*key epoch:[[:space:]]*\([0-9]\{1,\}\)$/\1/p' | head -1
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

drill_finish() {
  # Idempotent: reachable both explicitly (early-abort + end-of-script)
  # and via the EXIT trap installed by drill_setup — whichever fires
  # first scrubs, reports, and cleans up; the second is a no-op.
  if [[ -n "${_DRILL_FINISHED:-}" ]]; then
    return 0
  fi
  _DRILL_FINISHED=1
  local status="OK"
  if [[ "$DRILL_FAIL_COUNT" -gt 0 ]]; then
    status="FAILED"
  fi
  # Final paranoia pass: every secret is registered by now.
  drill_scrub_report
  drill_log "-----------------------------------------------------------------------"
  drill_log "Drill result: $status — $DRILL_PASS_COUNT passed, $DRILL_FAIL_COUNT failed"
  drill_log "Evidence transcript: $DRILL_REPORT"
  drill_cleanup
  if [[ "$DRILL_FAIL_COUNT" -gt 0 ]]; then
    exit 1
  fi
  exit 0
}
