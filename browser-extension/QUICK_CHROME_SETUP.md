# Chrome Web Store API Setup - Quick Guide

## Important: Chrome Web Store API is NOT in Google Cloud Console

The Chrome Web Store API is **not listed** in the Google Cloud Console API library like other Google APIs. You don't need to "enable" it there.

## Quick Setup Steps

### Step 1: Get Extension ID

1. Go to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
2. Find your extension
3. Copy the **Item ID** (this is your Extension ID)

**Your Extension ID**: `nophfgfiiohedlodfeepjoioljbhggdd`

### Step 2: Create OAuth Client in Google Cloud Console

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or use existing)
3. Go to **APIs & Services** > **Credentials**
4. Click **Create Credentials** > **OAuth client ID**
5. Select **Web application**
6. Name: "Chrome Web Store Publish"
7. **Authorized redirect URIs**:
   - `https://oauth2.googleapis.com/token`
   - `urn:ietf:wg:oauth:2.0:oob`
8. Click **Create**

Save:
- **Client ID**
- **Client Secret**

### Step 3: Generate Refresh Token

**Method 1: OAuth 2.0 Playground (Easier)**

1. Go to [OAuth 2.0 Playground](https://developers.google.com/oauthplayground/)
2. Click the gear icon (⚙️) in top right
3. Check **Use your own OAuth credentials**
4. Enter your Client ID and Client Secret
5. Click **Close**
6. In the left panel, find and click **Chrome Web Store API** (or enter custom scope: `https://www.googleapis.com/auth/chromewebstore`)
7. Click **Authorize APIs**
8. Authorize the application
9. Click **Exchange authorization code for tokens**
10. Copy the **Refresh Token**

**Method 2: Using Browser**

1. Open this URL in your browser (replace YOUR_CLIENT_ID):
   ```
   https://accounts.google.com/o/oauth2/auth?response_type=code&scope=https://www.googleapis.com/auth/chromewebstore&client_id=YOUR_CLIENT_ID&redirect_uri=urn:ietf:wg:oauth:2.0:oob
   ```

2. Click "Allow" when prompted

3. Copy the authorization code from the page

4. Exchange it for a refresh token:
   ```bash
   curl -X POST https://oauth2.googleapis.com/token \
     -d "client_id=YOUR_CLIENT_ID" \
     -d "client_secret=YOUR_CLIENT_SECRET" \
     -d "code=AUTHORIZATION_CODE" \
     -d "redirect_uri=urn:ietf:wg:oauth:2.0:oob" \
     -d "grant_type=authorization_code"
   ```

5. Copy the **refresh_token** from the response

### Step 4: Add GitHub Secrets

Go to: **GitHub Repository** > **Settings** > **Secrets and variables** > **Actions**

Add these 5 secrets:

| Secret Name | Value | Example |
|------------|-------|---------|
| `CHROME_EXTENSION_ID` | Extension ID from Step 1 | `nophfgfiiohedlodfeepjoioljbhggdd` |
| `CHROME_WEBSTORE_CLIENT_ID` | OAuth Client ID from Step 2 | `123456789-abc...apps.googleusercontent.com` |
| `CHROME_WEBSTORE_CLIENT_SECRET` | OAuth Client Secret from Step 2 | `GOCSPX-xxxxxxxxxxxxx` |
| `CHROME_WEBSTORE_REFRESH_TOKEN` | Refresh Token from Step 3 | `1//0xxxxxxxxxxxxx` |
| `CHROME_WEBSTORE_APP_ID` | App ID (usually same as Extension ID) | `nophfgfiiohedlodfeepjoioljbhggdd` |

### Step 5: Test

```bash
# Create a test tag
git tag chrome-v0.1.0-test
git push origin chrome-v0.1.0-test
```

Then check the Actions tab in GitHub.

## Summary

**Key Point**: You don't need to "enable" Chrome Web Store API in Google Cloud Console. Just create the OAuth client credentials and generate a refresh token.

**What You Need:**
1. Extension ID (from Chrome Web Store Developer Dashboard)
2. OAuth Client ID and Secret (from Google Cloud Console)
3. Refresh Token (from OAuth 2.0 Playground or manual exchange)
4. GitHub secrets configured

**Next**: Once secrets are added, create a test release to verify everything works!
