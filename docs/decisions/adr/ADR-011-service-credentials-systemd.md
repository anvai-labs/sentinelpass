# ADR-011: Restart-Safe Service Credentials via systemd Encrypted Credentials

| Field | Value |
|-------|-------|
| Status | Accepted (2026-09-30, after two independent review rounds — adversarial + proxy; remediation folded into the same change) |
| Date | 2026-09-30 |
| Owners | Core maintainer, security lead |
| Related | ADR-003; ADR-007 (§ secrets broker); [#191](https://github.com/anvai-labs/sentinelpass/issues/191) |
| Runbook | `docs/SERVICE_CREDENTIALS.md` |

## Summary

Provision selected vault secrets into Linux **systemd encrypted credentials**
(`systemd-creds encrypt`, consumed by `LoadCredentialEncrypted=`) so services on
a server restart with **no** SentinelPass daemon, vault, or master password
available. Provisioning reuses the WBS-506 least-privilege broker: a scoped
`ExternalSecretGrant` plus per-client token resolves the secret through
`GetExternalSecret`, exactly like `sentinelpass secret get`/`exec`.

## Context

Server-side services (the OVH VPS automation) need credentials at boot and at
arbitrary restarts. The desktop-style flow — daemon with an unlocked vault —
cannot satisfy that: requiring an unlocked vault at every start would store the
master password on the server or leave a vault permanently unlocked. The target
host runs systemd 259 and has no usable TPM, so TPM2-bound credentials are not
available there today (the mechanism is still supported for hosts that have
one). Operationally the constraint set is:

- No plaintext secret at rest on the server, in unit files, or in arguments.
- No vault unlock, vault file, or master password needed at service start.
- An explicit, machine-checkable protection mode — never a silently chosen one.
- Failed provisioning must never damage a working installed credential.
- Rotation and revocation must have a documented, auditable runbook.

## Decision

Add a `sentinelpass service-credential` CLI surface backed by a core module
that: resolves a secret through the scoped daemon broker; encrypts it by
invoking `systemd-creds encrypt --with-key=<mode> --name=<id>` with the
plaintext supplied **only via stdin pipe** (never argv, never an environment
variable, never a temp file); verifies the result by decrypting it and
comparing in constant time **before** publishing; publishes by atomic rename
into the encrypted credential store (default `/etc/credstore.encrypted/<id>`,
mode 0600, owner-only directory); and records metadata (never secret material)
in a local manifest.

1. **Explicit protection mode is mandatory.** `--protection host-key|tpm2`
   maps to `--with-key=host|tpm2`. The tool refuses `null`, `auto`, and
   `auto-initrd` semantics: `auto` can silently select weaker or no
   confidentiality, and `null` is plaintext with extra steps.
2. **Verify-then-publish.** The ciphertext is decrypted back and compared to
   the resolved secret (constant time) before the rename. A credential that
   does not round-trip is never installed; a failed run leaves the previous
   credential untouched.
3. **Atomic replacement.** The ciphertext is written to a same-directory
   temporary file (0600, fsynced), verified there, then renamed over the
   target and the directory fsynced. Crash or failure mid-run leaves either
   the old credential or no credential — never a torn or unverified one.
   The temp name is **unique per attempt** (random suffix, created
   `O_EXCL | O_NOFOLLOW`): concurrent installs of the same credential each
   verify exactly the bytes they publish — the deterministic-name variant
   was demonstrated (adversarial review) to let one run rename another's
   unverified ciphertext over a working credential.
4. **Manifest, not secrets.** `<config>/service-credentials.json` (0600)
   records client id, domain, field, credential name, protection mode,
   directory, size, and timestamp — enough to drive `list`, `verify`,
   `remove`, and rotation runbooks without storing hashes of secret values
   (a fingerprint of a low-entropy secret is itself a leak).
5. **System scope only (MVP).** Encrypted credentials land in
   `/etc/credstore.encrypted/` for system units. User-scope credentials
   (`systemd-creds --user`, systemd ≥ 256) are deferred: they add uid +
   machine-id binding semantics that need their own qualification.
6. **Server-side resolution.** Provisioning runs on the target host against a
   local daemon (its vault can stay locked outside provisioning windows).
   Encrypting for a *remote* host's key would require copying the target's
   `/var/lib/systemd/credential.secret` to the vault machine — rejected.

### Program identity and authorization granularity

This ADR deliberately does **not** add argv/cwd/uid "command fingerprint"
authorization to the broker:

- argv and cwd are attacker-controlled (`exec -a`, `chdir`); authorizing on
  them repeats the self-asserted-origin mistake ADR-007 removed ("origin is
  provenance, never authorization").
- Any program fingerprint fails against a same-user attacker, who can simply
  execute the bound program with the bound arguments and read its output —
  the program is the authority, so binding to it adds no boundary.

The kernel-enforceable granularity for per-program delivery is the systemd
unit boundary itself: PID 1 decrypts the credential into the unit's
`$CREDENTIALS_DIRECTORY`, readable only by the unit's `User=` — pair each
service with a dedicated UNIX user and delivery is per-program by
construction. As follow-up hardening (separate change), an opt-in,
Linux-only grant binding to the peer's `/proc/<pid>/exe` digest — obtained
from the already-kernel-verified `SO_PEERCRED` pid at accept time — is
feasible; its honest threat model is damage limitation for token theft
across a user boundary, not same-user defense, and cwd/argv would ride in
the audit log as provenance only.

## Options Considered

- **`EnvironmentFile=` with plaintext** — plaintext at rest; rejected outright.
- **Plain `LoadCredential=` store** — plaintext at rest; rejected.
- **`systemd-creds --with-key=host`** — ciphertext at rest, PID 1 decrypts at
  unit start, zero extra moving parts on systemd ≥ 250; chosen (the target's
  259 satisfies it; bare-name credential lookup needs ≥ 254).
- **TPM2-bound credentials** — strongest at-rest binding (key never
  disk-readable), but no TPM on the target; supported via `--protection tpm2`
  for hosts that have one. PCR policy binding is future work.
- **`--key=<custom key file>`** — equivalent confidentiality to the host key
  but forfeits automatic PID 1 decryption (units would need a manual decrypt
  step) and invents a second key to manage; rejected.
- **Runtime fetch per start** (`ExecStartPre` + broker) — requires an
  unlocked vault at every start; violates the core requirement; rejected.
- **Vault sync to the server + boot-time unlock** — puts master-password
  material on the server and depends on experimental sync; rejected.

## Threat Model

Reduces: plaintext at rest on the server; secret exposure to processes
outside the target unit (PID 1 delivers only into the unit's credential
directory, restricted to the unit's user); unscoped provisioning (grant +
client token + audit, unchanged broker semantics); torn or unverified
installs (verify-then-rename).

Does not defeat: **root** on the server (reads `/var/lib/systemd/
credential.secret` and the ciphertext, decrypts offline); **full-disk
snapshot exfiltration** — the snapshot includes the host key, so encrypted
credentials are only as protected as the snapshot itself (documented
limitation of host-key mode with no TPM; TPM2 mode raises the bar);
compromise of the provisioning account while the vault is unlocked
(plaintext transits daemon memory); loss of the host key (all encrypted
credentials become unreadable — recover by re-provisioning, which is cheap
by design); physical SSD remanence after removal (provider-side rotation is
the real revocation); and the known residual that the provisioning CLI
prints nothing secret but the *installed service* necessarily receives the
plaintext at runtime.

## MVP vs. Later

- **MVP:** `service-credential install|verify|list|remove`; host-key and
  TPM2 protection modes; `--not-after` pass-through; verify-before-publish;
  atomic replacement (unique `O_EXCL` temp — concurrency-safe); capped tool
  output with `SENTINELPASS_*` environment scrubbing and plaintext redaction
  in tool-error excerpts; credstore ownership/writability validation;
  manifest; runbook with rotation/revocation and failure recovery;
  synthetic-credential tests (fake `systemd-creds` tool) including
  concurrency, environment-scrub and redaction regressions. Operates the
  *server provisioning profile*: on host-key hosts the daemon, vault, and
  CLI share one UID (root), stated in the runbook.
- **Later:** opt-in exe-digest grant binding + peer provenance in audit
  (Linux, follow-up change); decoupling broker resolution (vault user) from
  credstore publication (root) so a non-root daemon can serve provisioning
  without a peer-policy change; `--user` scope (systemd ≥ 256); TPM2 PCR
  policies; `SetCredentialEncrypted=` embedded-in-unit variant for
  template-ish deploys.

## Migration and Rollout

Purely additive surface; no existing behavior changes. Qualification path:
synthetic credentials in `/etc/credstore.encrypted/` on a test unit on the
VPS (coordinated with the owning session), then provider-side rotation of
real secrets before pointing production units at provisioned credentials.

## Consequences

Servers gain restart-safe secret delivery without vault availability, at the
cost of one new CLI surface and a manifest to keep honest. Host-key mode
must be documented as snapshot-equivalent-to-plaintext; operators who need
stronger at-rest binding must use TPM2 hosts or accept the limitation.
Rotation becomes an explicit operational act (re-provision + unit restart),
which is exactly the auditability the broker wants.
