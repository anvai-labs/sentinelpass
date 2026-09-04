# Chrome Web Store Automated Publishing Setup

This guide explains how to configure automated Chrome extension publishing from GitHub Actions to the Chrome Web Store.

## Prerequisites

1. Google Developer Account with Chrome Web Store access
2. Extension already registered in Chrome Web Store
3. GitHub repository with Actions enabled

## Step 1: Get Chrome Web Store API Credentials

### 1.1 Create Chrome Web Store API Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable "Chrome Web Store API" for your project
4. Go to "APIs & Services" > "Credentials"
5. Create OAuth 2.0 credentials:
   - Click "Create Credentials" > "OAuth client ID"
   - Application type: "Web application"
   - Name: "Chrome Web Store Publish"
   - Authorized redirect URIs: `https://oauth2.googleapis.com/token`
   - Click "Create"

### 1.2 Get Your Client ID and Secret

After creating the OAuth client, you'll receive:
- **Client ID**: Save this (you'll need it for GitHub secrets)
- **Client Secret**: Save this (you'll need it for GitHub secrets)

### 1.3 Generate Refresh Token

Use the following steps to generate a refresh token:

1. Open your browser and navigate to:
   ```
   https://accounts.google.com/o/oauth2/auth?response_type=code&scope=https://www.googleapis.com/auth/chromewebstore&client_id=YOUR_CLIENT_ID&redirect_uri=urn:ietf:wg:oauth:2.0:oob
   ```
   Replace `YOUR_CLIENT_ID` with your actual Client ID.

2. Authorize the application when prompted

3. Copy the authorization code from the response

4. Exchange the authorization code for a refresh token:
   ```bash
   curl -d "client_id=YOUR_CLIENT_ID" \
        -d "client_secret=YOUR_CLIENT_SECRET" \
        -d "code=AUTHORIZATION_CODE" \
        -d "grant_type=authorization_code" \
        -d "redirect_uri=urn:ietf:wg:oauth:2.0:oob" \
        https://oauth2.googleapis.com/token
   ```

5. Save the **refresh_token** from the response

### 1.4 Get Your Extension ID and App ID

1. Go to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
2. Find your extension in the list
3. Copy the **Item ID** (this is your Extension ID)
4. Copy the **App ID** from the URL or extension details

## Step 2: Configure GitHub Secrets

Add the following secrets to your GitHub repository (Settings > Secrets and variables > Actions):

| Secret Name | Description | Example |
|------------|-------------|---------|
| `CHROME_EXTENSION_ID` | Extension ID from Chrome Web Store | `nophfgfiiohedlodfeepjoioljbhggdd` |
| `CHROME_WEBSTORE_CLIENT_ID` | OAuth Client ID | `123456789-abcdefg.apps.googleusercontent.com` |
| `CHROME_WEBSTORE_CLIENT_SECRET` | OAuth Client Secret | `GOCSPX-xxxxxxxxxxxxx` |
| `CHROME_WEBSTORE_REFRESH_TOKEN` | OAuth Refresh Token | `1//0xxxxxxxxxxxxx` |
| `CHROME_WEBSTORE_APP_ID` | Chrome Web Store App ID | `123456789` |

## Step 3: Extension Manifest Requirements

Ensure your `manifest.json` has:

```json
{
  "manifest_version": 3,
  "version": "0.1.0",
  "name": "Your Extension Name",
  "description": "Your extension description"
}
```

## Step 4: Trigger Extension Release

### Automated Release (Tag-based)

Create and push a version tag:

```bash
git tag chrome-v0.1.0
git push origin chrome-v0.1.0
```

This will trigger the workflow with the version extracted from the tag.

### Manual Release (Workflow Dispatch)

1. Go to Actions tab in GitHub
2. Select "Chrome Extension Release" workflow
3. Click "Run workflow"
4. Enter:
   - **Version**: e.g., `0.1.0`
   - **Publish Target**: `test` (trusted testers) or `production` (public store)

## Step 5: Verify Release

1. Check the Actions tab for workflow status
2. For test releases, verify in Chrome Web Store Developer Dashboard
3. For production releases, the extension will be published to the public store

## Versioning

- Chrome extension versions follow semantic versioning: `MAJOR.MINOR.PATCH`
- Example tags: `chrome-v0.1.0`, `chrome-v0.1.1`, `chrome-v1.0.0`
- The version in `manifest.json` will be automatically updated to match the tag

## Publishing Workflow

### Test Mode (Trusted Testers)
- Uploads extension for trusted testers only
- Does not publish to public Chrome Web Store
- Faster review process
- Ideal for testing before production release

### Production Mode
- Uploads and publishes to public Chrome Web Store
- Requires full review process
- Can take several days for approval
- Use only for stable releases

## Troubleshooting

### "Invalid Credentials" Error
- Verify all secrets are correctly set in GitHub
- Check that the refresh token is valid and not expired
- Ensure the OAuth client has Chrome Web Store API enabled

### "Extension Not Found" Error
- Verify the Extension ID is correct
- Ensure the extension exists in your Chrome Web Store account
- Check that you have owner permissions for the extension

### "Upload Failed" Error
- Verify the ZIP file is properly formatted
- Check that manifest.json is valid
- Ensure all required files are included in the extension package

### "Publish Failed" Error
- For production mode, ensure extension passes all store requirements
- Check Chrome Web Store Developer Dashboard for review status
- Verify extension has a valid description, screenshots, and privacy policy

## Security Best Practices

1. Never commit secrets to the repository
2. Use GitHub Encrypted Secrets for all credentials
3. Rotate refresh tokens periodically (Google recommends every 6 months)
4. Limit OAuth client scope to only Chrome Web Store API
5. Use separate OAuth clients for test and production environments

## Additional Resources

- [Chrome Web Store API Documentation](https://developer.chrome.com/docs/webstore/api)
- [Chrome Extension Publishing Best Practices](https://developer.chrome.com/docs/webstore/publish/)
- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
