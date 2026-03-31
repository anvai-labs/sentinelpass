# SentinelPass Extension Store Submission Guide v0.6.3

## Quick Start

1. **Chrome Web Store**: https://chrome.google.com/webstore/devconsole
2. **Firefox Add-ons**: https://addons.mozilla.org/en-US/developers/

Upload the packages from `browser-extension/dist/`:
- `sentinelpass-chrome-0.6.3.zip` (37KB)
- `sentinelpass-firefox-0.6.3.zip` (37KB)

---

## Chrome Web Store Submission

### Step 1: Access Developer Dashboard
1. Go to https://chrome.google.com/webstore/devconsole
2. Sign in with your developer account
3. Select "SentinelPass" extension or create new item

### Step 2: Upload Package
1. Click "Upload Updated Package"
2. Select `browser-extension/dist/sentinelpass-chrome-0.6.3.zip`
3. Wait for Chrome to validate the package

### Step 3: Fill Store Listing

**Basic Information:**
- **Name**: SentinelPass
- **Description**: Secure, local-first password manager with autofill support
- **Detailed Description**: 
  ```
  SentinelPass is a secure, local-first password manager that stores all your credentials locally on your device using military-grade encryption (Argon2id + AES-256-GCM).
  
  Key features:
  • Local-only storage — no cloud sync required
  • Military-grade encryption (Argon2id KDF + AES-256-GCM)
  • Autofill support for password fields
  • Biometric unlock (Windows Hello, macOS Touch ID)
  • Zero-knowledge architecture
  • Open source
  
  This extension requires the SentinelPass desktop app to be installed on your computer.
  ```

**Category:** `Tools > Productivity`

**Language:** English

### Step 4: Privacy & Permissions
Chrome will auto-detect permissions from the manifest. Confirm:
- ✅ `storage` — For extension settings
- ✅ `activeTab` — For autofill on current tab
- ✅ `notifications` — For vault status alerts
- ✅ `nativeMessaging` — For communication with desktop app

**Privacy Practices:**
- **Data Usage**: Local-only, no telemetry
- **User Data**: All data stored locally in encrypted database
- **Third-party**: No third-party data sharing

### Step 5: Screenshots
Add at least 3 screenshots (1280x800 or 640x400):
1. Main popup showing credentials
2. Save prompt after registration
3. Settings/biometric unlock screen

### Step 6: Review Notes (Optional)
```
v0.6.3 Security Hardening Release

This release addresses all previously identified security vulnerabilities:
- Removed credential exposure in DOM (no data attributes)
- Eliminated all innerHTML usage with user data
- Removed unused permissions (clipboardRead)
- Added message sender validation
- Implemented rate limiting (30 msg/5sec per tab)
- Enforced strict Content Security Policy
- Credentials stored in memory only (session storage)
- Reduced clipboard auto-clear to 10 seconds

All changes follow Chrome Web Store security best practices.
```

### Step 7: Submit
1. Click "Submit for Review"
2. Review typically takes 3-7 business days

---

## Firefox Add-ons (AMO) Submission

### Step 1: Access Developer Hub
1. Go to https://addons.mozilla.org/en-US/developers/
2. Sign in with your Mozilla account
3. Click "Submit a New Add-on"

### Step 2: Upload Package
1. Click "Upload" or drag-and-drop
2. Select `browser-extension/dist/sentinelpass-firefox-0.6.3.zip`
3. Wait for AMO to validate

### Step 3: Fill Listing Details

**Basic Information:**
- **Name**: SentinelPass
- **Summary**: Secure, local-first password manager with autofill support
- **Description**:
  ```
  SentinelPass is a secure, local-first password manager that stores all your credentials locally on your device using military-grade encryption (Argon2id + AES-256-GCM).
  
  Key features:
  • Local-only storage — no cloud sync required
  • Military-grade encryption (Argon2id KDF + AES-256-GCM)
  • Autofill support for password fields
  • Biometric unlock (Windows Hello, macOS Touch ID)
  • Zero-knowledge architecture
  • Open source
  
  This extension requires the SentinelPass desktop app to be installed on your computer.
  ```

**Categories:**
- Primary: `Privacy & Security`
- Secondary: `Productivity > Tools`

**Version**: 0.6.3

### Step 4: Privacy Policy
Create a privacy policy page or use:
```
SentinelPass Privacy Policy

Data Storage:
- All user credentials are stored locally on the user's device
- Credentials are encrypted using AES-256-GCM
- No data is transmitted to external servers (except via native messaging to local desktop app)

Data Collection:
- SentinelPass does not collect, transmit, or sell any user data
- No telemetry or analytics
- No tracking

Permissions:
- storage: Used for extension settings only
- activeTab: Used to detect password fields for autofill
- notifications: Used to display vault status alerts
- nativeMessaging: Used to communicate with the local SentinelPass desktop application

Third-Party Services:
- None

For more information, visit: https://github.com/vjsingh1984/sentinelpass
```

### Step 5: Support
- **Support URL**: https://github.com/vjsingh1984/sentinelpass/issues
- **Homepage**: https://github.com/vjsingh1984/sentinelpass

### Step 6: Review Notes (Important!)
```
v0.6.3 — Initial AMO Release + Security Hardening

Security highlights:
- Manifest V3 compliant
- No inline scripts or event handlers
- Strict Content Security Policy: script-src 'self'; object-src 'none'
- All user input escaped via HTML entity encoding
- Message sender validation prevents cross-extension communication
- Rate limiting implemented (30 messages per 5-second window)
- Credentials stored in memory only (chrome.storage.session)
- No telemetry or remote connections except native messaging to local daemon

Native Messaging Architecture:
This extension uses native messaging to communicate with a local daemon (sentinelpass-daemon) that runs on the user's machine. All credentials are stored locally in an encrypted SQLite database (AES-256-GCM). The extension does not make any HTTP requests or communicate with external services.

The native messaging host is auto-registered when the user installs the SentinelPass desktop application.
```

### Step 7: Submit for Review
1. Click "Submit for Review"
2. AMO review typically takes 3-10 business days

---

## Post-Submission Checklist

### After Approval
- [ ] Test extension installation from store
- [ ] Verify autofill functionality
- [ ] Test save prompts
- [ ] Verify biometric unlock (if applicable)
- [ ] Check extension listing appears correctly
- [ ] Monitor user reviews and feedback

### Ongoing Maintenance
- Monitor security advisories in dependencies
- Keep extension version in sync with desktop app
- Update store listing for new releases
- Respond to user reviews and issues

---

## Package Contents Verification

Both packages contain exactly 11 files:
- `manifest.json` — Manifest V3 configuration
- `background.js` — Service worker (compiled from background.ts)
- `content.js` — Content script for autofill (compiled from content.ts)
- `popup.js` — Popup UI logic (compiled from popup.ts)
- `popup.html` — Popup markup
- `styles.css` — UI styles
- `logger.js` — Logging utilities (compiled from logger.ts)
- `save-heuristics.js` — Save prompt detection (compiled from save-heuristics.ts)
- `icon16.png` — 16x16 icon
- `icon48.png` — 48x48 icon
- `icon128.png` — 128x128 icon

**No TypeScript source files, no node_modules, no build artifacts.**

---

## Support & Resources

- **GitHub**: https://github.com/vjsingh1984/sentinelpass
- **Issues**: https://github.com/vjsingh1984/sentinelpass/issues
- **Documentation**: See project README.md
- **Security**: Report vulnerabilities via GitHub Security Advisories

---

**Date**: March 31, 2026  
**Version**: 0.6.3  
**Status**: Ready for Store Submission ✅
