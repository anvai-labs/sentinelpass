# Install and launch with Homebrew

For a macOS desktop installation, follow the [DMG installation guide](MACOS_INSTALL.md), including download verification and the current signing limitation. The app bundle includes the daemon and native messaging host needed for browser integration.

The Homebrew formula installs terminal executables. It does not install `SentinelPass.app`, a Dock shortcut, or a login service. The current prebuilt formula supports **Apple Silicon macOS** and **x86_64 Linux**; it does not provide Intel macOS or ARM Linux archives.

## Install

```bash
brew tap anvai-labs/tap https://github.com/anvai-labs/homebrew-tap
brew update
brew install anvai-labs/tap/sentinelpass
sentinelpass --version
sentinelpass --help
```

Continue with [launch](#launch). On macOS, first read the [current formula limitations](#current-formula-limitations).

## Upgrade an existing installation

Quit the SentinelPass UI normally, then run:

```bash
brew update
brew upgrade anvai-labs/tap/sentinelpass
sentinelpass --version
```

Reopen the UI and unlock the vault, then open the extension popup. If it shows **Unlocked**, no browser restart is needed. If it does not connect, reload the extension and reopen its popup; fully quit and reopen the browser if the error persists. An independently managed daemon must also be restarted using whichever service manager originally started it; upgrading files does not replace an already running process.

`brew update` refreshes the tap's formula definitions; `brew upgrade` installs a newer version when available. `brew reinstall` is for reinstalling the version Homebrew resolves, for example to repair missing package files. It is not a prerequisite for upgrading. In the reported `0.10.0` → `0.11.0` session, the tap refreshed during `brew upgrade`, after `brew reinstall` had already installed `0.10.0` again. See the [Homebrew command reference](https://docs.brew.sh/Manpage).

If Homebrew reports an older version than expected:

```bash
brew update
brew info anvai-labs/tap/sentinelpass
type -a sentinelpass sentinelpass-ui sentinelpass-daemon
"$(brew --prefix sentinelpass)/bin/sentinelpass" --version
```

Compare `brew info` with [published releases](https://github.com/anvai-labs/sentinelpass/releases). The tap update is a separate workflow and may lag a release. If the explicit Homebrew binary reports the expected version but `sentinelpass --version` does not, an earlier source/script installation is taking precedence on `PATH`.

## Launch

For the formula installation:

```bash
sentinelpass-ui
```

This runs the desktop window as a foreground process. The terminal prompt returns when the app exits; a quiet terminal alone does not establish that startup failed. Check the Dock and other desktop spaces for the window. Pressing `Ctrl-C` interrupts the application; use the window's normal quit action when finished.

For the DMG installation, launch **SentinelPass** from Applications, or use:

```bash
open -a SentinelPass
```

That command requires the installed app bundle; the formula alone does not provide it. Create a vault on first use or unlock the existing vault. Keep the UI open for browser autofill: it normally owns the daemon it starts and stops that daemon on exit. If a compatible daemon is already running, the UI connects to it.

The UI also registers `sentinelpass-host` for Chrome, Chromium, and Firefox. Install the [browser extension](../README.md#browser-extension), then check its popup for **Unlocked**. The browser launches the host and communicates with it over native messaging. Running `sentinelpass-host` in Terminal only starts a process waiting for framed browser messages; its startup log is not an interactive prompt or a daemon health check.

## Current formula limitations

**Verified against the `0.11.0` tap formula on September 14, 2026:**

| Component | Apple Silicon macOS | x86_64 Linux |
| --- | --- | --- |
| `sentinelpass` CLI | Installed | Installed |
| `sentinelpass-ui` | Installed as a bare executable | Installed as a bare executable |
| `sentinelpass-host` | Installed | Installed |
| `sentinelpass-daemon` | **Omitted by the formula** | Installed |
| Homebrew `service do` definition | **Absent** | **Absent** |

The [tap formula](https://github.com/anvai-labs/homebrew-tap/blob/main/Formula/sentinelpass.rb) installs the daemon only on Linux even though the upstream macOS portable archive contains it. A clean macOS formula installation therefore cannot start its own daemon for browser autofill. An older daemon elsewhere on `PATH` can mask this omission. A successful `brew install` or `brew reinstall` does not validate the complete browser workflow.

The macOS DMG supplies all desktop components while this packaging gap remains; read its [signing status](MACOS_INSTALL.md#current-signing-status) before installing. Quit the formula UI before opening the app bundle, then check the extension connection after the app registers its host. The default vault directory is `~/Library/Application Support/PasswordManager`, outside Homebrew's Cellar; do not delete it to troubleshoot installation. The app uses the existing default vault when run as the same user with the same configuration. A legacy vault may need the [owner-only permission repair](MACOS_INSTALL.md#legacy-vault-permissions) before it can unlock.

The source/script installer's macOS LaunchAgent work is tracked separately in [PR #144](https://github.com/anvai-labs/sentinelpass/pull/144). Installing a formula does not run `installation/install.sh`; that PR alone does not add a Homebrew service or fix the formula's missing daemon.

## Background services

Homebrew's syntax puts the action before the **formula name**:

```text
brew services start <formula>
brew services restart <formula>
brew services stop <formula>
```

For SentinelPass, the formula name is `anvai-labs/tap/sentinelpass`, not `sentinelpass-daemon`. However, **the current formula has no service definition**, so even the correctly ordered `brew services start anvai-labs/tap/sentinelpass` is not a supported startup path yet. The [Homebrew service documentation](https://docs.brew.sh/Formula-Cookbook#service-files) explains the formula's required service declaration.

Use the desktop app to manage its daemon. Do not add a second service manager if a script-installed LaunchAgent or another daemon is already managing the same vault. A future Homebrew service needs to start the daemon with `--start-locked` so it does not request a password from a noninteractive login service; users must still unlock through the app.

## Troubleshooting

| What you see | Meaning and next step |
| --- | --- |
| `unknown subcommand: sentinelpass` or `sentinelpass-daemon` | `brew services` expects the action first. See [background services](#background-services), including the current lack of a service definition. |
| A newer Command Line Tools release is available / Tier 2 notice | These are Homebrew environment warnings. In the reported session, the subsequent Cellar summary and `Upgraded` line confirm installation completed. Use Software Update in System Settings to update the tools; consult [Homebrew support tiers](https://docs.brew.sh/Support-Tiers#tier-2) if warnings persist. Deleting Command Line Tools is not required to resolve these SentinelPass command errors. |
| `already installed` | Homebrew has no newer version in its current formula metadata. Check [upgrade steps](#upgrade-an-existing-installation). |
| `sentinelpass-ui` stays quiet and holds the terminal | Expected for a foreground GUI process if the window opens. If no window appears, use the checks below; silence alone cannot diagnose a hang. |
| `open -a SentinelPass` cannot find the app | The formula installs executables, not an app bundle. Install the DMG, or run `sentinelpass-ui`. |
| The UI cannot start/connect to the daemon | Check whether the daemon exists in the formula's `bin` directory. For the macOS `0.11.0` omission, use the DMG. |
| `sentinelpass-host` prints a startup line and waits | It is waiting for browser-native messages. Exit the manual process and launch the UI, then use the extension. |
| Native messaging host not found after an upgrade | Reopen the UI to refresh host registration, reload the extension, and check its popup. Restart the browser if the error persists. The old Cellar version may have been removed by Homebrew cleanup. |

If no UI window appears, collect non-secret installation details:

```bash
brew info anvai-labs/tap/sentinelpass
brew list anvai-labs/tap/sentinelpass
type -a sentinelpass sentinelpass-ui sentinelpass-daemon
"$(brew --prefix sentinelpass)/bin/sentinelpass" --version
ls -l "$(brew --prefix sentinelpass)/bin"
sw_vers # macOS only
uname -m
```

Run the exact formula UI to rule out another binary on `PATH`:

```bash
"$(brew --prefix sentinelpass)/bin/sentinelpass-ui"
```

Record whether a window appears, any terminal error, and whether the process exits by itself or only when interrupted. Release builds do not emit the opt-in `SENTINELPASS_DEBUG_UNLOCK` debug log, so an absent `ui_unlock_debug.log` is not evidence of failure. Include the installation details and observations in a [bug report](https://github.com/anvai-labs/sentinelpass/issues/new?template=bug_report.md); do not attach vault files, IPC tokens, passwords, or decrypted entries.

## Packaging follow-up

The tap is maintained in [anvai-labs/homebrew-tap](https://github.com/anvai-labs/homebrew-tap); [issue #145](https://github.com/anvai-labs/sentinelpass/issues/145) tracks these gaps. Completing the Homebrew experience requires changes there: install the daemon on macOS, print launch instructions as formula caveats, and add/test an optional service with an upgrade-stable daemon path. Verify a clean installation, upgrade, locked startup, UI unlock, browser connection, and interaction with existing LaunchAgents before recommending `brew services` to users. An app-bundle cask would also provide the expected Applications/Dock launch experience.

This guide documents existing behavior; it does not change binaries, install a service, or require a new SentinelPass release.
