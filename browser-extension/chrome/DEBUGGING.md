# SentinelPass Browser Extension - Debugging Guide

## How to View Extension Logs

### Chrome DevTools Console

1. **Open Chrome DevTools:**
   - Press `F12` or `Ctrl+Shift+I` (Windows) / `Cmd+Option+I` (Mac)
   - Or right-click anywhere on the page and select "Inspect"

2. **View Console Logs:**
   - Click on the "Console" tab
   - All SentinelPass logs are prefixed with `[SentinelPass]`

3. **Filter Logs:**
   - In the console filter box, type: `SentinelPass`
   - This will show only SentinelPass-related logs

### Background Service Worker Logs

To view logs from the background script (which handles native messaging):

1. **Open Extensions Page:**
   - Navigate to `chrome://extensions/`
   - Or click the three-dot menu → More tools → Extensions

2. **Find SentinelPass Extension:**
   - Locate "SentinelPass" in your extensions list

3. **Open Service Worker:**
   - Click on "Service worker" link (blue text)
   - A new DevTools window will open for the background service worker

4. **View Console:**
   - Click on the "Console" tab
   - Look for `[SentinelPass Background]` prefixed logs

## Debugging Save Password Feature

### Step 1: Verify Content Script Loaded

1. Navigate to a login page (e.g., github.com/login)
2. Open DevTools Console (F12)
3. Look for:
   ```
   [SentinelPass] Content script loaded
   [SentinelPass] Current URL: https://github.com/login
   [SentinelPass] Hostname: github.com
   ```

### Step 2: Check Password Field Detection

On a page with a password field, you should see:
```
[SentinelPass] Password fields detected: 1
[SentinelPass] Processing password field 0
[SentinelPass] Injecting autofill button for field 0
```

### Step 3: Test Save Prompt

To test the save prompt:

1. **Navigate to a registration page** (e.g., sign up for a new service)
2. **Fill out the form:**
   - Enter username/email
   - Enter password
   - If there's a "confirm password" field, fill it too
3. **Submit the form**
4. **Watch the console for:**
   ```
   [SentinelPass] Form submission detected!
   [SentinelPass] Form action: ...
   [SentinelPass] Password field has value length: 12
   [SentinelPass] Username field found: true Username value: your@email.com
   [SentinelPass] Is new password form: true
   [SentinelPass] Scheduling save prompt in 500ms...
   [SentinelPass] showSavePrompt called!
   [SentinelPass] Creating save prompt element...
   [SentinelPass] Save prompt appended to DOM
   ```

### Step 4: Verify Background Communication

When you click "Save" on the prompt:

1. Open Background Service Worker console (see instructions above)
2. Look for:
   ```
   [SentinelPass Background] Handling save_credential
   [SentinelPass Background] Username: your@email.com
   [SentinelPass Background] Domain: example.com
   [SentinelPass Background] Sending native message to host: com.passwordmanager.host
   [SentinelPass Background] Message type: save_credential
   ```

## Common Issues and Solutions

### Issue 1: No logs appearing

**Possible causes:**
- Extension not loaded
- Content script not injected
- Page not refreshed after extension update

**Solution:**
1. Go to `chrome://extensions/`
2. Verify SentinelPass is enabled
3. Click the refresh icon on the extension card
4. Refresh the page you're testing

### Issue 2: "Password fields detected: 0"

**Possible causes:**
- No password field on page
- Page still loading

**Solution:**
1. Navigate to a login page
2. Wait for page to fully load
3. Check console again

### Issue 3: "Is new password form: false"

The save prompt only appears for new accounts, not existing logins.

**To test:**
1. Navigate to a sign-up/registration page
2. Look for forms with:
   - "Sign up", "Register", "Create account"
   - Password confirmation field

### Issue 4: Native messaging errors

**Error message:** "Native host has exited"

**Possible causes:**
- Daemon not running
- Native messaging host not registered
- Incorrect extension ID in manifest

**Solution:**
1. Verify daemon is running:
   ```powershell
   Get-Process sentinelpass-daemon
   ```

2. Check native messaging manifest:
   ```powershell
   Get-Content "C:\Program Files\PasswordManager\com.passwordmanager.host.json"
   ```

3. Verify extension ID matches:
   - Go to `chrome://extensions/`
   - Find SentinelPass extension ID (32 characters)
   - Update the manifest:
     ```powershell
     .\register-chrome.ps1 YOUR_EXTENSION_ID
     ```

## Manual Testing Checklist

- [ ] Content script loads on page
- [ ] Password fields are detected
- [ ] Autofill button appears when clicking password field
- [ ] Clicking autofill button shows notification
- [ ] Form submission is tracked (check console)
- [ ] New password form is detected
- [ ] Save prompt appears after registration
- [ ] Clicking "Save" on prompt sends message to background
- [ ] Background script sends message to native host
- [ ] Credentials are saved to vault

## Enabling Verbose Logging

All debug logging is now enabled by default. No additional configuration needed.

## Testing on Specific Sites

### Good Test Sites for Registration:

1. **GitHub** - `https://github.com/signup`
2. **Reddit** - `https://www.reddit.com/register/`
3. **Dummy sign-up forms** - Search for "test registration form"

### Testing Password Reset:

1. Use a site's "forgot password" feature
2. When creating a new password, the save prompt should appear
3. Look for "create password" or "new password" indicators

## Extension Secret Lifetime Inventory (WBS-716)

What the extension keeps, where, and for how long — the concrete answer to
"where can a password live?" for the browser surface:

| Location | Content | Lifetime | Cleared by |
|---|---|---|---|
| Background: `chrome.storage.session` `pendingCredential` | Captured submission (username + password) | 30 s (`expiresAt` stamp) | 2FA-page resume consumption, expiry alarm sweep (1 min), vault lock, browser exit |
| Background: `chrome.storage.session` `pendingSaveCredential:<id>` | Pending save payload for one notification | 10 min (`expiresAt` stamp) | Save/never/dismiss handling, expiry alarm sweep, vault lock, browser exit |
| Background: `chrome.storage.session` `pendingUnlockRetry` | Locked-vault save retry payload | 2 min (`expiresAt` stamp) | Retry/expiry handling, expiry alarm sweep, vault lock, browser exit |
| Content script: `lastAutofillContext` (memory) | Autofilled username + password for submit-source detection | 10 min timeout | Timeout, page navigation (`pagehide`), `scrub_secrets` broadcast on vault lock |
| Popup: `allCredentials` (memory) | Usernames/titles for the CURRENT site only — no passwords | Popup lifetime | Popup closes |
| `chrome.storage.local` `neverSaveDomains`, site prefs | Domains only — never secrets | Until removed | User action |

Hard rules enforced by this model:

- **Content scripts never hold session secrets.** Captured submissions are
  handed to the background (`capture_pending_login`); resuming a pending
  login is a question (`resume_pending_login`) whose answer is yes/no — the
  payload never round-trips to a page context. `chrome.storage.session`
  stays a trusted-context surface.
- **Every secret entry is stamped `expiresAt`** and swept by a
  `chrome.alarms` tick (service workers are ephemeral; timers are not
  trusted). An entry that LOSES its stamp is swept as expired (fail-closed).
- **A vault lock purges everything** pending and broadcasts `scrub_secrets`
  to all tabs; `chrome.storage.session` itself dies with the browser session.

## Reporting Issues

When reporting issues, please include:

1. **Console logs from content script** (F12 → Console)
2. **Background service worker logs** (chrome://extensions/ → Service worker)
3. **Screenshot of the page**
4. **URL you were testing on**
5. **Steps to reproduce**
