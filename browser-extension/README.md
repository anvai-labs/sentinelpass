# SentinelPass Browser Extensions

Secure, local-first password manager browser extensions for Chrome and Firefox.

## Quick Links

- **[Store Submission Guide](./STORE_SUBMISSION_GUIDE.md)** — Step-by-step submission instructions
- **[Security Checklist](./SUBMISSION_CHECKLIST.md)** — Security hardening verification
- **[Project README](../README.md)** — Main project documentation

## Current Version

**v0.6.3** — Security Hardening Release (March 31, 2026)

### What's New in v0.6.3

This release addresses all security vulnerabilities identified in the Chrome Web Store review and prepares Firefox for AMO submission.

**Security Fixes:**
- ✅ Removed password exposure in DOM (credentialStore Map instead of data attributes)
- ✅ Eliminated innerHTML usage (safe DOM APIs only)
- ✅ Removed unused clipboardRead permission
- ✅ Added message sender validation
- ✅ Implemented rate limiting (30 msg/5sec per tab)
- ✅ Reduced clipboard auto-clear to 10 seconds
- ✅ Protected debug mode (setDebugMode no longer exported)
- ✅ Migrated to session-only credential storage
- ✅ Added autofill context clearing after use
- ✅ Enforced strict Content Security Policy

**Firefox Improvements:**
- ✅ Migrated from Manifest V2 to V3
- ✅ All Chrome security fixes applied
- ✅ Added XSS protection (HTML escaping)
- ✅ Removed inline event handlers
- ✅ Updated extension ID to production domain

## Architecture

### Chrome Extension (Manifest V3)
```
browser-extension/chrome/
├── manifest.json          # MV3 configuration
├── background.ts          # Service worker
├── content.ts             # Autofill & save prompts
├── popup.ts               # Popup UI
├── logger.ts              # Secure logging
├── save-heuristics.ts     # Save detection
├── popup.html             # Popup markup
└── styles.css             # UI styles
```

### Firefox Extension (Manifest V3)
```
browser-extension/firefox/
├── manifest.json          # MV3 configuration
├── background.ts          # Background service worker
├── content.ts             # Autofill & save prompts
├── popup.ts               # Popup UI
├── logger.ts              # Secure logging
├── save-heuristics.ts     # Save detection
├── popup.html             # Popup markup
└── styles.css             # UI styles
```

### Native Messaging Architecture

The extensions communicate with the local SentinelPass desktop app via native messaging:

```
Browser Extension
    ↓ Native Messaging (JSON over stdin/stdout)
sentinelpass-host
    ↓ IPC (Unix socket / named pipe + AES-256-GCM)
sentinelpass-daemon
    ↓ Vault operations
Encrypted SQLite Database
```

## Building

### Prerequisites
- Node.js 20+
- npm 10+
- TypeScript 5+

### Build Commands

```bash
# Install dependencies
npm install

# Build TypeScript to JavaScript
npm run web:build

# Run tests
npm run test:ts

# Type check
npm run web:typecheck

# Package extensions
./browser-extension/package-chrome.sh 0.6.3
./browser-extension/package-firefox.sh 0.6.3
```

### Build Artifacts

Compiled JavaScript files are output to the respective extension directories:
- `browser-extension/chrome/*.js` (from `*.ts`)
- `browser-extension/firefox/*.js` (from `*.ts`)

Packaged extensions are created in:
- `browser-extension/dist/sentinelpass-chrome-<version>.zip`
- `browser-extension/dist/sentinelpass-firefox-<version>.zip`

## Testing

### TypeScript Tests
```bash
npm run test:ts              # Run all tests
npm run test:ts:watch        # Watch mode
```

### E2E Tests (Playwright)
```bash
cd browser-extension/e2e
npm install
npm run test:e2e             # Run E2E tests
npm run test:e2e:headed      # Run with visible browser
```

### Manual Testing

1. **Load Extension Unpacked:**
   - Chrome: `chrome://extensions/` → "Developer mode" → "Load unpacked"
   - Firefox: `about:debugging#/runtime/this-firefox` → "Load Temporary Add-on"

2. **Verify Functionality:**
   - Navigate to a login page
   - Click the extension popup
   - Verify credentials display
   - Test autofill button
   - Test save prompt after registration

## Development

### Adding New Features

1. Update TypeScript source files in `browser-extension/chrome/` or `browser-extension/firefox/`
2. Run `npm run web:build` to compile
3. Test changes by loading unpacked extension
4. Commit both `.ts` and compiled `.js` files

### Security Considerations

**NEVER:**
- Store passwords in DOM attributes
- Use innerHTML with user data
- Skip sender validation on messages
- Expose sensitive data in console logs

**ALWAYS:**
- Use safe DOM APIs (createElement, textContent, appendChild)
- Validate sender.id on all message handlers
- Sanitize URLs and hostnames in logs
- Use session storage for temporary data
- Follow Content Security Policy

### Logging

The extensions use secure logging that redacts sensitive information in production:

```typescript
import { debugLog, infoLog, warnLog, errorLog } from './logger';

// Only logs in debug mode (development install or storage flag)
debugLog('Debug info', data);

// Always logs but redacts sensitive data
infoLog('User action', sanitizeUrl(url));
warnLog('Warning message');
errorLog('Error occurred', error);
```

## Permissions

### Chrome Extension
- `storage` — Extension settings
- `activeTab` — Autofill on current tab
- `notifications` — Vault status alerts
- `nativeMessaging` — Communication with desktop app

### Firefox Extension
- `storage` — Extension settings
- `activeTab` — Autofill on current tab
- `notifications` — Vault status alerts
- `nativeMessaging` — Communication with desktop app

## Distribution

### Chrome Web Store

1. Package extension: `./browser-extension/package-chrome.sh <version>`
2. Upload to: https://chrome.google.com/webstore/devconsole
3. Follow: [Store Submission Guide](./STORE_SUBMISSION_GUIDE.md)

### Firefox Add-ons (AMO)

1. Package extension: `./browser-extension/package-firefox.sh <version>`
2. Upload to: https://addons.mozilla.org/en-US/developers/
3. Follow: [Store Submission Guide](./STORE_SUBMISSION_GUIDE.md)

## Troubleshooting

### Extension Not Connecting to Desktop App

1. Verify desktop app is running: `sentinelpass-daemon`
2. Check native messaging host is registered:
   - **Chrome**: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` (macOS)
   - **Firefox**: `~/.config/mozilla/native-messaging-hosts/` (Linux)
   - **Windows**: Registry `HKCU\Software\{Mozilla,Google}...`
3. Re-register by launching the desktop SentinelPass app

### Credentials Not Appearing

1. Check vault is unlocked via popup
2. Verify domain matches stored credential
3. Check browser console for `[SentinelPass]` logs
4. Ensure desktop app is running

### Save Prompt Not Showing

1. Check `content.ts` is loaded: `chrome://extensions/` → "Service worker" / "Content script"
2. Verify password field detection: Look for `[SentinelPass]` console logs
3. Check form submission is detected

## Resources

- **Main Project**: https://github.com/anvai-labs/sentinelpass
- **Issue Tracker**: https://github.com/anvai-labs/sentinelpass/issues
- **Security**: Report via GitHub Security Advisories

## License

MIT License — See project root for details.

---

**Version**: 0.6.3  
**Last Updated**: March 31, 2026  
**Status**: Ready for Store Submission ✅
