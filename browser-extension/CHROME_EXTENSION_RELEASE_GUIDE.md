# Chrome Extension Automated Publishing - Quick Start Guide

## What's Been Set Up

A GitHub Actions workflow has been created that allows you to publish the Chrome extension directly to the Chrome Web Store from your GitHub repository.

**Workflow File**: `.github/workflows/chrome-extension-release.yml`

## Two Ways to Publish

### 1. Tag-Based Release (Recommended)

```bash
# Create and push a version tag
git tag chrome-v0.1.0
git push origin chrome-v0.1.0
```

The workflow will:
- Extract version from tag (`0.1.0`)
- Update `manifest.json` with the version
- Build and package the extension
- Upload to Chrome Web Store (TEST MODE - trusted testers only)

### 2. Manual Workflow Dispatch

1. Go to **Actions** tab in GitHub
2. Select **"Chrome Extension Release"** workflow
3. Click **"Run workflow"**
4. Enter:
   - **Version**: e.g., `0.1.0`
   - **Publish Target**:
     - `test` - Upload to trusted testers only
     - `production` - Publish to public store

## Before You Can Use It

You need to configure Chrome Web Store API credentials:

### Step 1: Get Chrome Web Store API Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project or select existing
3. Enable **"Chrome Web Store API"**
4. Create OAuth 2.0 credentials:
   - **Application type**: Web application
   - **Authorized redirect URI**: `https://oauth2.googleapis.com/token`
5. Save **Client ID** and **Client Secret**

### Step 2: Generate Refresh Token

Replace `YOUR_CLIENT_ID` in this URL and open in browser:

```
https://accounts.google.com/o/oauth2/auth?response_type=code&scope=https://www.googleapis.com/auth/chromewebstore&client_id=YOUR_CLIENT_ID&redirect_uri=urn:ietf:wg:oauth:2.0:oob
```

1. Authorize when prompted
2. Copy the authorization code
3. Exchange for refresh token:

```bash
curl -d "client_id=YOUR_CLIENT_ID" \
     -d "client_secret=YOUR_CLIENT_SECRET" \
     -d "code=AUTH_CODE" \
     -d "grant_type=authorization_code" \
     -d "redirect_uri=urn:ietf:wg:oauth:2.0:oob" \
     https://oauth2.googleapis.com/token
```

4. Save the **refresh_token** from the response

### Step 3: Get Extension IDs

1. Go to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
2. Find your extension
3. Copy **Item ID** (Extension ID)
4. Copy **App ID** from URL or extension details

### Step 4: Add GitHub Secrets

Go to: **Repository Settings** > **Secrets and variables** > **Actions**

Add these secrets:

| Secret Name | Description |
|------------|-------------|
| `CHROME_EXTENSION_ID` | Extension ID (e.g., `nophfgfiiohedlodfeepjoioljbhggdd`) |
| `CHROME_WEBSTORE_CLIENT_ID` | OAuth Client ID |
| `CHROME_WEBSTORE_CLIENT_SECRET` | OAuth Client Secret |
| `CHROME_WEBSTORE_REFRESH_TOKEN` | OAuth Refresh Token |
| `CHROME_WEBSTORE_APP_ID` | Chrome Web Store App ID |

## Publishing Modes

### Test Mode (Trusted Testers)
- **Trigger**: Default mode or select `test` target
- **Speed**: Faster review (minutes to hours)
- **Audience**: Only trusted testers
- **Use for**: Testing before production release

### Production Mode (Public Store)
- **Trigger**: Select `production` target
- **Speed**: Full review process (can take several days)
- **Audience**: Public Chrome Web Store
- **Use for**: Stable, tested releases

## Version Management

- Chrome extension versions: `MAJOR.MINOR.PATCH` (e.g., `0.1.0`, `0.1.1`, `1.0.0`)
- Each release must have a **higher version** than previous
- The workflow **automatically updates** `manifest.json` version

## Quick Test

Once secrets are configured, test with:

```bash
# Create a test version tag
git tag chrome-v0.1.0-test
git push origin chrome-v0.1.0-test
```

Then:
1. Check **Actions** tab for workflow status
2. Check Chrome Web Store Developer Dashboard for uploaded extension
3. Verify with trusted testers

## Current Extension Info

Your current Chrome extension details:
- **Extension ID**: `nophfgfiiohedlodfeepjoioljbhggdd`
- **Current Version**: `0.1.0`
- **Manifest Version**: 3

## Documentation

For detailed setup instructions, see: `browser-extension/CHROME_WEBSTORE_SETUP.md`

## Support

If you encounter issues:
- Check workflow logs in Actions tab
- Verify all secrets are correctly set
- Ensure extension exists in your Chrome Web Store account
- Check Chrome Web Store Developer Dashboard for review status

## Next Steps

1. ✅ Chrome extension workflow created
2. ⏳ Configure Chrome Web Store API credentials
3. ⏳ Add secrets to GitHub repository
4. ⏳ Test with a small version increment
5. ⏳ Publish first release to Chrome Web Store
