"""Scratch: probe the native host end-to-end (host -> daemon -> vault).

Usage: SENTINELPASS_CLI_STDIN unused; args: <host-bin> <json-message>
Env: HOME/XDG_RUNTIME_DIR must point at the harness install.
Reads the daemon token/capability from those paths. Prints the response.
"""

import json
import os
import struct
import subprocess
import sys

host_bin = sys.argv[1]
message = sys.argv[2].encode()

payload = struct.pack("<I", len(message)) + message
env = dict(os.environ)
proc = subprocess.run([host_bin], input=payload, capture_output=True, env=env, timeout=30)
out = proc.stdout
err = proc.stderr
if len(out) >= 4:
    (length,) = struct.unpack("<I", out[:4])
    body = out[4 : 4 + length]
    print("RESPONSE:", body.decode("utf-8", "replace")[:400])
else:
    print("NO RESPONSE; stderr:", err.decode("utf-8", "replace")[:400])
