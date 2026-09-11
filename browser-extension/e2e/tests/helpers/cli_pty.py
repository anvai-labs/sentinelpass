"""Run a command under a pseudo-tty with piped input (E2E harness helper).

The CLI's password prompts use rpassword, which requires a real terminal
(termios ioctls). This driver forks the command on a pty, writes the input
from SENTINELPASS_CLI_STDIN, echoes output to stdout, and exits with the
child's status.

Usage: SENTINELPASS_CLI_STDIN='pw
pw' python3 cli_pty.py <command> [args...]
"""

import os
import pty
import select
import sys
import time

TIMEOUT_SECONDS = 30.0


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print("usage: cli_pty.py <command> [args...]", file=sys.stderr)
        return 2

    data = os.environ.get("SENTINELPASS_CLI_STDIN", "").encode()

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
            continue
        done, code = os.waitpid(pid, os.WNOHANG)
        if done == pid:
            status = code
            break
    if status is None:
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
