# Browser Integration Tests

Two suites live here (WBS-719):

## 1. Daemon E2E — `tests/daemon-autofill.spec.ts` (REAL daemon + host)

Drives the actual trust boundary — Chromium extension -> native messaging
host -> daemon -> vault — against an ISOLATED installation (temp `HOME` /
`XDG_RUNTIME_DIR`; nothing touches the developer's real vault):

- HTTPS autofill fills the single matching credential into the bound field
- HTTP autofill is default-denied (WBS-711) until an explicit per-site
  grant is made through the popup (WBS-712 daemon-side permission store)
- Multiple matches surface the explicit chooser and fill the picked
  account (WBS-715)
- Submitting a login captures, prompts on the next page, and saves through
  the daemon (verified via the CLI against the same vault)
- A locked vault delivers nothing

### Prerequisites

```bash
cargo build -p sentinelpass-daemon -p sentinelpass-host -p sentinelpass-cli
cd browser-extension/e2e
npm install
npx playwright install chromium
```

### Run

```bash
npm run test:e2e                # headless (new headless supports extensions)
npm run test:e2e:headed         # visible browser for debugging
CHROME_EXECUTABLE=/usr/bin/chromium npm run test:e2e   # local Chromium
```

Notes:
- The unpacked extension keeps its stable ID from the manifest `key`, so
  the native-host manifest's `allowed_origins` can pin it.
- Firefox is NOT covered here: Playwright cannot load extensions in stock
  Firefox (documented gap in the security status matrix). The daemon-side
  and shared-source behavior Firefox consumes is covered by the Rust
  suites and the byte-parity pipeline gate.

## 2. Save-prompt UI tests — `tests/save-prompt.spec.ts`

Historical suite; assertions relied on content-script injection that
Playwright could not perform reliably (all cases skipped). The daemon E2E
suite above covers the same flows against the real backend.

Setup for local runs: Node.js 20+, Chromium installed by Playwright.
