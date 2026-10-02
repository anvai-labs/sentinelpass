# Service Credentials (systemd) — Runbook

Restart-safe secret delivery for Linux servers: provision selected vault
secrets into **systemd encrypted credentials** so units restart with no
SentinelPass daemon, vault, or master password available. Design and threat
model: [ADR-011](decisions/adr/ADR-011-service-credentials-systemd.md).
Tracking: [#191](https://github.com/anvai-labs/sentinelpass/issues/191).

```
vault (locked outside provisioning) → daemon broker → GetExternalSecret
        (scoped grant + client token, audited)
                ↓  plaintext via stdin pipe only (never argv/env/disk)
        systemd-creds encrypt --with-key=host|tpm2 --name=<id>
                ↓  ciphertext (base64), verified by decrypt+compare FIRST
        /etc/credstore.encrypted/<id>   (0600, atomic rename)
                ↓  at unit start, by PID 1 — no SentinelPass involved
        LoadCredentialEncrypted=<id> → $CREDENTIALS_DIRECTORY/<id>
```

## Requirements

- Linux host, systemd ≥ 254 (bare-name `LoadCredentialEncrypted=` lookup);
  `--with-key=` needs ≥ 250.
- Root (or equivalent) for `/etc/credstore.encrypted/` — the host key
  `/var/lib/systemd/credential.secret` is root-only 0600.
- A local `sentinelpass-daemon` with a vault containing the secret
  (its own server-side vault; stays locked outside provisioning), plus a
  scoped grant and client token:
  ```bash
  sentinelpass secret allow <client> --domain <domain> --field password
  ```

## Install (and rotate)

**Prerequisite — same-UID rule.** The CLI resolves the daemon socket, IPC
token, grant allowlist, and the manifest from the **invoking user's**
directories, and the daemon refuses foreign peer UIDs by design (WBS-507
peer-credential check). On host-key hosts, encryption additionally requires
root (the host key `/var/lib/systemd/credential.secret` is root-only) and
`/etc/credstore.encrypted` is root-owned. Therefore, on a host-key host the
daemon — and its vault — run as **root** (the *server provisioning
profile*), and every `service-credential`, `secret allow`, and `secret
token mint` command for this flow runs under the same `sudo`. On TPM2 hosts,
any OS user that can reach the TPM and write the credstore directory works.
Decoupling broker resolution (vault user) from publication (root) is
designed follow-up work (ADR-011 "Later"). On TPM2 hosts a non-root
provisioner additionally needs `--credstore-dir` pointing at a directory
**it owns** (the store validation refuses foreign-owned directories), and
the unit must then use the explicit-path form
`LoadCredentialEncrypted=<name>:<dir>/<name>` — the bare-name lookup only
searches the standard directories.

Unlock the daemon's vault for the provisioning window
(`sudo sentinelpass unlock`; headless hosts have no biometric path), then:

```bash
sudo sentinelpass service-credential install \
  --client-id myautomation --domain sandhi:provider:apikey \
  --cred-name myautomation.provider.apikey \
  --protection host-key
# client token: --token or $SENTINELPASS_CLIENT_TOKEN
```

Re-lock when done (`sudo sentinelpass lock`) — nothing later needs the
vault. All provisioning state (manifest, grants, tokens) lives under the
same root profile, so inspection commands are sudo'd too:

```bash
sudo sentinelpass service-credential list
```

What it does: resolves the secret through the audited broker, encrypts it
(`--with-key=host` or `--with-key=tpm2` — the mode is **required**), decrypts
the result back and compares in constant time, then atomically renames the
verified ciphertext into `/etc/credstore.encrypted/<cred-name>`. Options:

| Option | Meaning |
| --- | --- |
| `--protection host-key\|tpm2` | **Required.** `null`/`auto` semantics are refused. |
| `--field username\|password\|title` | Vault field (default `password`). |
| `--not-after <date>` | Passes `--not-after=` to systemd-creds: the credential stops decrypting after the date (a rotation forcing function). |
| `--credstore-dir <path>` | Override target directory (default `/etc/credstore.encrypted`). |
| `--systemd-creds <path>` | Override the tool path (default `systemd-creds`). |
| `--no-verify` | Skip the decrypt-and-compare pre-publish check (not recommended). |

**Rotation is the same command re-run.** Verification happens before the
atomic rename, so a failed rotation never damages the installed credential.

## Wire the unit

```ini
# /etc/systemd/system/myautomation.service
[Service]
LoadCredentialEncrypted=myautomation.provider.apikey
# ... or with an explicit path on systemd < 254:
# LoadCredentialEncrypted=myautomation.provider.apikey:/etc/credstore.encrypted/myautomation.provider.apikey
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart myautomation
```

The unit reads the decrypted secret from
`$CREDENTIALS_DIRECTORY/myautomation.provider.apikey`. PID 1 performs the
decryption at unit start; SentinelPass is not involved at start, and the
decrypted credential is only readable by the unit's `User=`. **Use a
dedicated UNIX user per service** — that user boundary is the per-program
authorization (see ADR-011 § "Program identity").

Credential names must be filename-safe ASCII (`A–Z a–z 0–9 . _ -`).

## Verify / list

```bash
# Decrypt the installed credential and compare against the vault (constant-time).
# Exit 0 = match, non-zero = mismatch/absent. Prints MATCH/MISMATCH only — never the secret.
sudo sentinelpass service-credential verify \
  --client-id myautomation --domain sandhi:provider:apikey \
  --cred-name myautomation.provider.apikey

sentinelpass service-credential list          # manifest rows (no secret material)
```

Run `verify` before relying on a rotated credential and after any host-key
event.

## Remove / revoke

```bash
sudo sentinelpass service-credential remove --cred-name myautomation.provider.apikey
sudo systemctl restart myautomation    # unit must cope with the credential being gone
```

Removal deletes the ciphertext file and the manifest row. **Removing the
credential is not a revocation of the secret itself**: the plaintext lived in
the unit's memory and in PID 1 during its lifetime, and deletion is not
guaranteed to erase physical SSD pages or snapshots. To revoke a possibly
exposed secret: rotate it **at its provider**, then provision the new value.
Also remove/rotate the grant if the tooling no longer needs it:
`sentinelpass secret revoke --client-id <client> --domain <domain> --field password`.

## Failure recovery

| Failure | State after | Recovery |
| --- | --- | --- |
| Daemon locked/unreachable | Nothing written | Unlock/start daemon, re-run `install` |
| `systemd-creds encrypt` fails | Temp file removed; installed credential untouched | Check root, host key presence, systemd version |
| Verify mismatch (decrypt ≠ secret) | Temp file removed; installed credential untouched | Re-run; persistent mismatch = file a bug, do not `--no-verify` |
| Crash mid-run | Temp file may remain (never published) | Re-run `install`; stale `.<name>.*.tmp` files in the credstore can be deleted |
| Manifest save failed after publish | Credential installed but unrecorded (`list` misses it) | Re-run `install` (idempotent) or `remove` — the error names the published path |
| Host key lost/regenerated | All encrypted credentials undecryptable; units fail to start | Re-run `install` for every manifest row (`list` shows them); restart units |
| Unit fails to start | Check `systemctl status` / `journalctl -u <unit>` — a missing/undecryptable credential is a start failure with an explicit message | Fix credential (`install`/`verify`), restart |

The manifest lives at `<config>/service-credentials.json` (0600) and never
contains secret material or secret hashes.

## Upgrading a Linux host from <= 0.14.0

The shared private-file custody hardening (ADR-012) tightens the broker's
allowlist storage: files with group/world permission bits are now REFUSED
instead of warned about. Allowlists written by SentinelPass **0.14.0 and
earlier** on Linux could be born group/world-readable (a birth-mode bug
that hardening fixes), so after upgrading, `service-credential` /
`secret` operations can fail closed with an allowlist permissions error
until repaired once:

```bash
chmod 600 "<config>/external-secret-access.json"   # typically /root/.config/PasswordManager/
```

The daemon denies external-secret access (including service-credential
provisioning) until the repair — fail-closed by design.

## Limitations (read before trusting host-key mode)

- **A complete disk snapshot defeats host-key encryption.** The encryption
  key (`/var/lib/systemd/credential.secret`) is on the same disk as the
  ciphertext; anyone who can image the full disk can decrypt offline. On the
  current OVH VPS there is no usable TPM, so `--protection host-key` is the
  available mode — treat disk-snapshot access as equivalent to plaintext
  access. `--protection tpm2` (TPM-equipped hosts) binds decryption to the
  chip and is the recommended mode wherever available.
- Root on the server can decrypt everything (it can also just read the
  running service's memory).
- systemd credentials are size-limited: the installer caps provisioning at
  512 KiB per credential, and systemd enforces an overall ~1 MiB credential
  budget per service — several large credentials on one unit can exceed it.
- User-scope (`--user`) credentials and TPM2 PCR policies are not yet
  supported (ADR-011 "Later").

## Security invariants

- Plaintext reaches `systemd-creds` **only** via a stdin pipe; it is never in
  argv, environment, logs, temp files, or repository files.
- The CLI prints paths, sizes, and verdicts — never secrets or ciphertext.
- Ciphertext is verified (decrypt + constant-time compare) **before** the
  atomic rename; the previous credential survives any failed run.
- Every provisioning fetch is broker-scoped (grant + client token) and
  audited (`purpose=service-credential-install` / `-verify`).

## Testing

Unit and integration tests use a fake `systemd-creds` tool (synthetic
credentials only). Production secrets must not be touched until the flow is
qualified on the target host with synthetic values.
