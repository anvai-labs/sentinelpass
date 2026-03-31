# Browser Extension Submission Checklist v0.6.3

## Security Hardening Completed ✅

This release addresses all security vulnerabilities identified in the Chrome Web Store rejection and prepares Firefox for AMO submission.

### Chrome Extension (Manifest V3)
- ✅ **Removed passwords from DOM** — Credentials stored in memory Map, not in `data-*` attributes
- ✅ **Eliminated innerHTML** — All UI built with safe DOM APIs (createElement, textContent, appendChild)
- ✅ **Removed clipboardRead permission** — Unused dangerous permission removed
- ✅ **Sender validation** — All message listeners validate `sender.id` matches extension ID
- ✅ **Rate limiting** — 30 messages per 5-second window per tab
- ✅ **Reduced clipboard timeout** — Auto-clear after 10 seconds (down from 30)
- ✅ **Debug mode protection** — `setDebugMode` no longer exported
- ✅ **Session-only storage** — Credentials no longer persist to disk via chrome.storage.local
- ✅ **Autofill context clearing** — Sensitive data cleared after use
- ✅ **CSP enforced** — `script-src 'self'; object-src 'none'`

### Firefox Extension (Manifest V3)
- ✅ **Migrated to Manifest V3** — No longer MV2 (AMO requirement)
- ✅ **All Chrome security fixes applied** — Same hardened codebase
- ✅ **XSS protection** — All user input escaped via `escapeHtml()` helper
- ✅ **Removed inline event handlers** — No `onclick` attributes
- ✅ **CSP enforced** — `script-src 'self'; object-src 'none'`
- ✅ **Updated extension ID** — `sentinelpass@sentinelpass.org` (production-ready)
- ✅ **Permissions minimized** — Only `storage`, `activeTab`, `notifications`, `nativeMessaging`

## Test Coverage ✅
- 26 tests passing
- 96.02% statements coverage
- 88.46% branches coverage
- 94.11% functions coverage
- 96.02% lines coverage

## Packages Ready for Upload

### Chrome Web Store
```
Location: browser-extension/dist/sentinelpass-chrome-0.6.3.zip
Size: 37KB
Manifest: Manifest V3
Extension ID: nophfgfiiohedlodfeepjoioljbhggdd
```

### Firefox Add-ons (AMO)
```
Location: browser-extension/dist/sentinelpass-firefox-0.6.3.zip
Size: 37KB
Manifest: Manifest V3
Extension ID: sentinelpass@sentinelpass.org
```

## Store Submission Steps

### Chrome Web Store
1. Go to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
2. Select "SentinelPass" extension
3. Upload `browser-extension/dist/sentinelpass-chrome-0.6.3.zip`
4. Fill in store listing:
   - **Name**: SentinelPass
   - **Description**: Secure, local-first password manager with autofill support
   - **Version**: 0.6.3
   - **Privacy**: Emphasize local-only storage, no telemetry
5. Submit for review
6. **Review notes** (optional but recommended):
   ```
   v0.6.3 Security Hardening Release
   
   This release addresses all previously identified security vulnerabilities:
   - Removed credential exposure in DOM (data attributes)
   - Eliminated all innerHTML usage with user data
   - Removed unused clipboardRead permission
   - Added message sender validation
   - Implemented rate limiting
   - Enforced strict Content Security Policy
   - Migrated Firefox extension to Manifest V3
   
   All changes follow Chrome Web Store security best practices.
   ```

### Firefox Add-ons (AMO)
1. Go to [Firefox Add-ons Developer Dashboard](https://addons.mozilla.org/en-US/developers/)
2. Click "Submit a New Add-on"
3. Upload `browser-extension/dist/sentinelpass-firefox-0.6.3.zip`
4. Fill in store listing:
   - **Name**: SentinelPass
   - **Description**: Secure, local-first password manager with autofill support
   - **Version**: 0.6.3
5. Submit for review
6. **Review notes** (optional but recommended):
   ```
   v0.6.3 — Initial Release + Security Hardening
   
   This is the first AMO submission of SentinelPass.
   
   Security highlights:
   - Manifest V3 compliant
   - No inline scripts or event handlers
   - Strict Content Security Policy
   - All user input escaped
   - Message sender validation
   - Rate limiting implemented
   - Credentials stored in memory only (session storage)
   - No telemetry or remote connections except native messaging
   
   The extension uses native messaging to communicate with a local
   daemon (sentinelpass-daemon) that runs on the user's machine.
   All credentials are stored locally in an encrypted SQLite database.
   ```

## Verification Before Submission

Run these commands to verify the packages:

```bash
# Verify no TypeScript files leaked
unzip -l browser-extension/dist/sentinelpass-chrome-0.6.3.zip | grep '\.ts$'
# Should return empty

# Verify no node_modules leaked
unzip -l browser-extension/dist/sentinelpass-chrome-0.6.3.zip | grep 'node_modules'
# Should return empty

# Verify manifest version
unzip -p browser-extension/dist/sentinelpass-chrome-0.6.3.zip manifest.json | jq '.manifest_version'
# Should return 3

# Verify no dangerous permissions
unzip -p browser-extension/dist/sentinelpass-chrome-0.6.3.zip manifest.json | jq '.permissions'
# Should show: ["storage", "activeTab", "notifications", "nativeMessaging"]
```

## What Changed Since v0.6.2

See PR #49 for full details: https://github.com/your-org/sentinelpass/pull/49

### Critical Security Fixes
- DOM security: Credentials no longer exposed via data attributes
- XSS prevention: All user-generated content now uses safe DOM APIs
- Permission hygiene: Removed unused clipboardRead permission
- Message isolation: Sender validation prevents cross-extension messages
- DoS protection: Rate limiting on background message handler

### Firefox Migration
- Upgraded from Manifest V2 to V3
- Updated browser_action → action
- Added content_security_policy
- Converted to TypeScript for type safety
- Aligned security hardening with Chrome extension

## Known Limitations

1. **Native messaging host** must be installed separately (included with desktop app)
2. **Biometric unlock** requires Windows Hello or macOS Touch ID
3. **Linux** does not support biometric unlock
4. **Multi-device sync** is optional and requires a relay server

## Support

For issues or questions:
- GitHub Issues: https://github.com/your-org/sentinelpass/issues
- Documentation: See project README.md
- Security: Report vulnerabilities via private GitHub Security advisory

---

**Date**: March 31, 2026  
**Version**: 0.6.3  
**Status**: Ready for Store Submission ✅
