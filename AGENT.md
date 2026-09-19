# Agent Guide

Primary instructions for working in this repository live in [CLAUDE.md](CLAUDE.md) — read it first. This file holds the quick-reference facts agents most often need verbatim; keep it short.

## Release Channels and What They Include

Three channels ship from the same `v*` tag with deliberately different component sets:

| Component | Homebrew formula (`anvai-labs/tap/sentinelpass`) | DMG (`.app` bundle) | Installer archive (`sentinelpass-installer-*`) |
| --- | --- | --- | --- |
| CLI (`sentinelpass`) | ✓ macOS + Linux | ✗ | ✓ |
| Desktop UI (`sentinelpass-ui`) | ✓ | ✓ (the `.app`) | ✓ |
| Native host (`sentinelpass-host`) | ✓ | ✓ (sidecar inside the `.app`) | ✓ |
| Daemon (`sentinelpass-daemon`) | ✓ Linux only — omitted on macOS on purpose | ✓ (sidecar inside the `.app`) | ✓ |
| Browser extensions | ✗ | ✗ | ✓ |
| LaunchAgent / auto-start + native-host manifests | ✗ (binaries only) | manifests auto-register on UI launch | ✓ (full setup) |

## Hard facts (verified; do not restate from stale docs)

- The DMG bundle's sidecar resources contain ONLY `sentinelpass-daemon` + `sentinelpass-host` — never the CLI. Full binary upgrades use the installer archive (`sentinelpass-installer-<VERSION>-<PLATFORM>.tar.gz`), not the DMG.
- One daemon per vault: the maintenance lock (WBS-501/503) is exclusive. The brew formula omits the macOS daemon so it never races the app-managed LaunchAgent daemon.
- The extension that brew users get is NOT from brew — the formula ships no extensions. Extensions come from the installer archive or the separate `chrome-v*` release train, and they version independently of app releases.
- Whichever `sentinelpass-ui` launched last re-registers the native-host manifests; keep installed channels version-aligned.
- Homebrew formula bumps live in the separate `anvai-labs/homebrew-tap` repo (dispatch: Actions → Update SentinelPass Formula). Its CI checks formulas against LIVE upstream registries — an upstream release (e.g. a new PyPI sdist for `victor`) can redden all tap PRs until that formula's own bump PR merges. Verify with `brew audit`, a real `brew install`/`upgrade`, and `brew test` before landing a bump; formula SHAs must be computed from downloaded bytes, never copied.
