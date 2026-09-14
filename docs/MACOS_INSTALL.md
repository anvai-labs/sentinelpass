# Install and upgrade the macOS app

The DMG installs **SentinelPass.app**, including the desktop UI, daemon, and browser native messaging host. Homebrew's formula installs a separate set of terminal executables; `brew upgrade` does **not** upgrade an existing app in Applications.

The published `0.11.0` DMG is for **Apple Silicon (`arm64`)**. Check **Apple menu → About This Mac** for an Apple chip, or run `uname -m`. An `x86_64` Intel Mac needs an appropriate build; the generic `-macos.dmg` filename does not mean universal architecture.

## Current signing status

**Verified September 14, 2026:** the official `0.11.0` DMG matches its published checksum and contains all three executables, but its app fails strict signature verification and Gatekeeper assessment:

```text
code has no resources but signature indicates they must be present
```

The executable has an ad-hoc signature, no Developer ID team, and no sealed bundle resources. This is tracked in [issue #148](https://github.com/anvai-labs/sentinelpass/issues/148). A matching checksum verifies agreement with the release's checksum file; it does not establish Developer ID signing, notarization, or independent provenance.

A GitHub-CLI-downloaded copy launched through macOS during verification. Command-line downloads may lack browser quarantine metadata, so that launch does not establish that a browser-downloaded copy will pass Gatekeeper. A signed and notarized release is needed for a normal, verified first-launch experience.

If macOS blocks the app, retain the error and consult [Apple's guidance](https://support.apple.com/en-us/102445). Apple describes a per-app **Privacy & Security → Open Anyway** option for software you have independently decided to trust; it may not be available for a damaged signature or on a managed Mac. Do not disable Gatekeeper, remove quarantine attributes, or locally re-sign the download to conceal a verification failure. If verification fails, prefer a corrected release; report the exact failure rather than treating it as a missing password or daemon problem.

## Download and verify

1. Open [official SentinelPass releases](https://github.com/anvai-labs/sentinelpass/releases) and select a stable version.
2. Download that release's `sentinelpass-<VERSION>-macos.dmg` and `sha256sums.txt` into the same new folder. `SentinelPass_0.11.0_aarch64.dmg` is an alternative name for the same `0.11.0` DMG; download only one and check the checksum entry for the exact filename you chose.
3. In Terminal, change to that folder. For the `0.11.0` generic filename, run:

```bash
awk '$2 == "./sentinelpass-0.11.0-macos.dmg" || $2 == "sentinelpass-0.11.0-macos.dmg" { print }' sha256sums.txt | shasum -a 256 --check
hdiutil verify sentinelpass-0.11.0-macos.dmg
```

The first command must report `sentinelpass-0.11.0-macos.dmg: OK`; the second must report a valid image checksum. Stop if either fails or the checksum entry is missing. Select only the DMG entry instead of checking the whole manifest, which also lists platform assets you have not downloaded. For another release, use its filename and its own checksum file.

Optional terminal download using GitHub CLI, into a new directory:

```bash
gh release download v0.11.0 --repo anvai-labs/sentinelpass \
  --pattern sentinelpass-0.11.0-macos.dmg \
  --pattern sha256sums.txt --dir ./SentinelPass-0.11.0
cd ./SentinelPass-0.11.0
```

Then run the verification commands above. These examples are pinned to the inspected release; check the release page for newer versions. When using `curl` instead, use `--fail --location` so HTTP errors fail and GitHub's download redirects are followed.

## Install or replace the app

1. Quit the current SentinelPass UI normally, including one launched from Terminal. If you manage a separate daemon service, use its original service manager to stop it before upgrading. Do not start competing daemons.
2. Before upgrading an existing vault, make a backup using the [supported encrypted backup workflow](decisions/adr/ADR-008-authenticated-backup-and-verified-restore.md). The CLI's `sentinelpass backup create <OUTPUT>` requires offline access with the daemon stopped and prompts locally for the master password. Preserve any existing app bundle separately if you need an application rollback copy. That copy is **not** a vault backup; an older app may not support a vault migrated by a newer version.
3. Open the verified DMG in Finder. Drag **SentinelPass** onto its **Applications** shortcut. If replacing an older copy, choose **Replace**, not **Keep Both**. If Applications requires administrator authorization you do not have, use a writable `~/Applications` folder and launch that exact copy consistently.
4. Eject the **SentinelPass** disk image. Launch the installed app from Applications, not from the mounted DMG:

```bash
open /Applications/SentinelPass.app
```

5. Unlock the existing vault using its master password. Create a new vault only for a first installation. A running-but-locked daemon is expected until you unlock; the password-strength meter is not an unlock confirmation.
6. Install the [browser extension](../README.md#browser-extension) if needed, then open its popup to check the connection. If it shows **Unlocked**, a browser restart is unnecessary. Keep the UI open while using autofill. The UI starts the bundled daemon with `--start-locked`; no `brew services` command or manual native-host launch is needed.

The default vault stays at `~/Library/Application Support/PasswordManager/vault.db`. Installing/replacing the app does not require deleting that directory, changing your password, or reinstalling Homebrew.

## Verify the installed copy

Check the app's version separately from the Homebrew CLI:

```bash
/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
  /Applications/SentinelPass.app/Contents/Info.plist
```

For `0.11.0`, the expected helper paths are:

```text
/Applications/SentinelPass.app/Contents/MacOS/sentinelpass-ui
/Applications/SentinelPass.app/Contents/Resources/src-tauri/resources/bin/sentinelpass-daemon
/Applications/SentinelPass.app/Contents/Resources/src-tauri/resources/bin/sentinelpass-host
```

If an older app opens, use the explicit `open /Applications/SentinelPass.app` command and remove/re-add its Dock shortcut. `sentinelpass --version` describes the CLI on `PATH`, not the app bundle. A Homebrew CLI and a DMG desktop app can coexist, but launching the formula's UI later can change browser host registration back to its own installation. Use one desktop installation consistently.

## Legacy vault permissions

An older vault may have mode `0644` (readable by other users). Current SentinelPass refuses to open it under `SR-DATA-003`, even when the master password is correct. The error explicitly says `has permissive mode ...; refusing to open`. This is an on-disk permission failure, not evidence of an incorrect password.

For your own default vault, inspect ownership and permissions without reading its contents:

```bash
ls -ld "$HOME/Library/Application Support/PasswordManager"
ls -l "$HOME/Library/Application Support/PasswordManager/vault.db"
```

If the files belong to your account and the error matches, repair just the vault and any existing SQLite sidecars. This block refuses symlinks and files owned by another account and does not read database contents:

```bash
(
  set -eu
  vault="$HOME/Library/Application Support/PasswordManager/vault.db"
  for file in "$vault" "$vault-wal" "$vault-shm" "$vault-journal"; do
    if [ -L "$file" ]; then
      echo "Refusing symlink: $file" >&2
      exit 1
    fi
    if [ ! -e "$file" ]; then
      if [ "$file" = "$vault" ]; then
        echo "Vault not found: $file" >&2
        exit 1
      fi
      continue
    fi
    if [ ! -f "$file" ] || [ ! -O "$file" ]; then
      echo "Expected a regular file owned by your account: $file" >&2
      exit 1
    fi
    chmod 600 "$file"
  done
)
```

Retry **Unlock** afterward. `0600` gives your account read/write access and removes group/other permissions; it does not alter the database contents. Do not delete `-wal`/`-shm` files, use recursive `chmod`, or use `sudo`/`chown` to make an unfamiliar vault accessible. For a custom vault path, use the exact path in the error. A different unlock error needs its own diagnosis.

## Chrome extension from the release archive

The `0.11.0` release has no standalone Chrome ZIP asset. Its `sentinelpass-installer-0.11.0-macos.tar.gz` includes `browser-extension/chrome/`, with the compiled JavaScript and manifest needed by Chrome. Download that installer archive from the same official release, verify its own entry in `sha256sums.txt`, and extract it. You do not need to run the script installer when the DMG app is already installed.

Copy the extracted `browser-extension/chrome/` folder to a stable location such as `~/Library/Application Support/SentinelPass/chrome-extension`. Keep the folder there: Chrome loads unpacked extensions from that path, so a temporary mount or Downloads cleanup can break the installation.

1. Visit `chrome://extensions/` in the Chrome profile you use.
2. Turn on **Developer mode**, click **Load unpacked**, and select the stable folder containing `manifest.json`. If Library is hidden, press **Command + Shift + G** in the folder picker, paste `~/Library/Application Support/SentinelPass/chrome-extension` without quotes, press Return, then click **Select**. In Terminal commands, quote paths containing spaces, for example `open "$HOME/Library/Application Support/SentinelPass/chrome-extension"`.
3. Confirm the extension ID is `nophfgfiiohedlodfeepjoioljbhggdd`, matching the app's native-host allowlist. Do not broaden that allowlist to work around a mismatched ID.
4. Pin SentinelPass in the toolbar and open its popup while the installed desktop app is running and unlocked. **Unlocked** confirms that the status request reached the native host and daemon; no Chrome restart is needed in that case. Refresh already-open login tabs before testing autofill. Grant only the site access you intend to use and verify autofill on a site you choose.

If the popup does not connect, first check the desktop app is running and unlocked, then click **Reload** on the extension's card and reopen the popup. If connection problems persist after host registration or an upgrade, quit Chrome completely with **Command + Q** and reopen it. A locked vault still needs local unlock; restarting Chrome does not unlock it. Chrome [starts a native host for each `sendNativeMessage` request](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-protocol), so a full browser restart is a troubleshooting step, not proof of a working connection.

Chrome's supported unpacked-install workflow requires the browser's own confirmation; copying the files alone does not activate the extension. Managed Chrome profiles may prohibit Developer mode or unpacked extensions. See [Chrome's loading instructions](https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world#load-unpacked).

The extension in the `0.11.0` archive still declares manifest version `0.6.3`; that label alone cannot establish which release supplied its files. Verify the archive provenance and use its complete extension folder. Unpacked extensions do not automatically update from GitHub releases: replace the stable folder with a verified later release and click **Reload** in Chrome.

This release's extension logger can automatically enable debug mode when Chrome identifies an unpacked install as development. Debug output can contain site/credential metadata. Review the logging limitations below before using it; installation as unpacked is not equivalent to a production logging configuration.

## Logging and diagnostic privacy

The release UI compiles out `SENTINELPASS_DEBUG_UNLOCK` instrumentation and does not create `ui_unlock_debug.log`. Its managed daemon uses INFO tracing, but the UI redirects its standard output/error to null. A separately launched service can redirect those streams elsewhere, so inspect that service's configuration independently.

Security audit logging remains enabled in `~/Library/Application Support/PasswordManager/audit/audit.log`. These are plaintext event records; current keyed records use opaque identifiers and a keyed integrity chain. Records from older versions remain in the file and are not retroactively sanitized. The `sealed` marker is not encryption, and checking that marker alone does not verify the cryptographic chain. Keep the directory private (`0700`) and the file owner-only (`0600`); do not attach raw logs to support requests.

The native host logs requested domains at INFO to stderr. Daemon log call sites also include domains, and extension debug mode can record URLs and other identifying metadata. Consequently, the absence of passwords in an audit-file scan does **not** prove that every diagnostic channel is free of sensitive information. Use redacted, minimal diagnostics and report logging gaps rather than enabling verbose logging against real credentials. [Issue #149](https://github.com/anvai-labs/sentinelpass/issues/149) tracks these defaults and owner-only audit file creation/rotation; tightening an existing file alone does not fix future file creation.

## Installation verification record

On September 14, 2026, an Apple Silicon Mac had Homebrew `0.11.0` alongside an older Applications bundle reporting `0.5.4`. The verified official `0.11.0` DMG replaced that app while preserving a separate copy of the old bundle. Installed files matched the mounted DMG; the image was ejected and the app launched from Applications. Its daemon ran with `--start-locked`, and Chrome, Chromium, and Firefox manifests pointed to the existing host inside the app bundle using absolute paths.

The user confirmed the unlock window appeared. Unlock initially refused the legacy vault's `0644` mode; ownership was verified, the file was tightened to `0600`, and no SQLite sidecars were present. The user then confirmed successful unlock. An audit-file scan found no secret-named fields, credential-assignment patterns, or plaintext domain values; this was a heuristic inspection, not proof of absence across all log channels. The existing audit log was also tightened from `0644` to `0600` inside its already-private directory.

The Chrome extension was extracted from the checksum-verified installer archive into a stable user folder, with its manifest key verified against the expected extension ID. The user confirmed loading it, and Chrome's stored registration matched the stable folder. A direct, framed native-host status request returned success and an unlocked vault. The user then confirmed **Unlocked** in Chrome's extension popup without a browser restart, establishing the Chrome-to-host-to-daemon status path. Automated UI inspection remained blocked by disabled browser automation/accessibility permissions, and credential autofill/save were not exercised. An empty matching-credentials list is separate from connection status. The release's signature assessment failed as described above.
