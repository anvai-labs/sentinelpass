# Security Policy

## Supported Versions

| Version line | Status |
| --- | --- |
| `0.1.x` | Supported (active release testing) |
| `<0.1` | Unsupported |

## Reporting a Vulnerability

Do not open public issues for exploitable vulnerabilities.

1. Email maintainers at `vijay@anvaiops.com` with subject `SentinelPass Security Report`.
2. Include: affected component, impact, reproduction steps, and suggested mitigation (if known).
3. If needed, include encrypted attachments/logs only.

## Response Targets

| Stage | Target |
| --- | --- |
| Initial acknowledgement | within 72 hours |
| Triage update | within 7 days |
| Fix plan / mitigation | as soon as validated |

## Scope

Security reports are especially valuable for:
- cryptography and key handling (`sentinelpass-core/src/crypto/`)
- vault lock/unlock and daemon IPC (`sentinelpass-core/src/daemon/`)
- browser extension/native host boundaries (`browser-extension/`, `sentinelpass-host/`)
- install/update trust chain and manifest registration

For deeper design context, see `SECURITY_ARCHITECTURE.md`.

