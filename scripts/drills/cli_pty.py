"""Run a command under a pseudo-tty with piped input (WBS-905 drill helper).

The CLI's password prompts use rpassword, which requires a real terminal
(termios ioctls). This driver forks the command on a pty, writes the input
from SENTINELPASS_CLI_STDIN, echoes output to stdout, and exits with the
child's status.

Adapted from browser-extension/e2e/tests/helpers/cli_pty.py (WBS-719);
the only change is the timeout override (DRILL_PTY_TIMEOUT_SECONDS,
default 300) because KDF operations dominate the runtime even against
RELEASE-profile binaries — the profile lib.sh and drills.yml mandate
(a debug-profile Argon2id takes minutes per derivation).

Usage: SENTINELPASS_CLI_STDIN='pw
pw' python3 cli_pty.py <command> [args...]
"""

import os
import pty
import re
import select
import sys
import time

TIMEOUT_SECONDS = float(os.environ.get("DRILL_PTY_TIMEOUT_SECONDS", "300"))

# DRILL_PTY_RESPOND='<regex>\t<template>': when the child's output matches
# <regex> (group 1 = captured text), write <template> with "\1" replaced by
# the captured text, followed by a newline — ONCE. This lets a drill mimic
# the human "read the displayed recovery key and type it back" step of
# `recovery setup` (SR-RECOVERY-002 verified re-entry).
RESPOND_SPEC = os.environ.get("DRILL_PTY_RESPOND", "")


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print("usage: cli_pty.py <command> [args...]", file=sys.stderr)
        return 2

    data = os.environ.get("SENTINELPASS_CLI_STDIN", "").encode()

    respond = None
    if RESPOND_SPEC:
        pattern, template = RESPOND_SPEC.split("\t", 1)
        respond = (re.compile(pattern.encode()), template)

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
        os._exit(127)

    if data:
        # The terminal line discipline buffers this until the child reads it.
        try:
            os.write(fd, data)
        except OSError:
            pass

    output = bytearray()
    responded = False
    status = None
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            ready, _, _ = select.select([fd], [], [], 0.5)
        except OSError:
            break
        if ready:
            try:
                chunk = os.read(fd, 8192)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
            if respond and not responded:
                m = respond[0].search(bytes(output))
                if m:
                    payload = respond[1].replace("\\1", m.group(1).decode("ascii", "replace"))
                    try:
                        os.write(fd, payload.encode() + b"\n")
                        responded = True
                    except OSError:
                        pass
            continue
        done, code = os.waitpid(pid, os.WNOHANG)
        if done == pid:
            status = code
            break
    if status is None:
        # Deadline exceeded: kill so the blocking reap below returns (a hung
        # child must not hang the driver past its timeout).
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        done, status = os.waitpid(pid, 0)

    # Drain whatever remains buffered on the master side.
    while True:
        try:
            chunk = os.read(fd, 8192)
        except OSError:
            break
        if not chunk:
            break
        output.extend(chunk)
    try:
        os.close(fd)
    except OSError:
        pass

    sys.stdout.write(output.decode("utf-8", "replace"))
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    sys.exit(main())
