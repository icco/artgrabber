# Dropbox OAuth Setup Guide

This guide will help you set up OAuth2 authentication for your ArtGrabber bot. OAuth2 with refresh tokens is **required** for authentication.

## Why OAuth?

- **Automatic token refresh**: Access tokens are automatically refreshed when they expire
- **Long-term stability**: The refresh token doesn't expire (or lasts much longer)
- **Production-ready**: This is the standard approach for long-running applications
- **No manual intervention**: Set it up once and forget about it

## Step 1: Create Dropbox App Credentials

1. Go to https://www.dropbox.com/developers/apps
2. Click "Create app"
3. Choose:
   - **API**: Scoped access
   - **Access**: Full Dropbox or App folder (depending on your needs)
   - **Name**: Give your app a unique name (e.g., "ArtGrabber Bot")
4. Click "Create app"

## Step 2: Configure OAuth Redirect URI

1. In your app's settings page, scroll to **OAuth 2**
2. Under **Redirect URIs**, add: `http://localhost:8888/oauth/callback`
3. Click "Add"
4. Note down your **App key** and **App secret** (you'll need these in the next step)

## Step 3: Run OAuth Setup Tool

The OAuth setup tool will guide you through the authorization process and generate your refresh token.

```bash
# Set your app credentials
export DROPBOX_APP_KEY="your_app_key_here"
export DROPBOX_APP_SECRET="your_app_secret_here"

# Run the setup tool
go run cmd/oauth-setup/main.go
```

Or if you've already built it:

```bash
./oauth-setup
```

The tool will:
1. Print a URL for you to visit
2. Open your browser and ask you to authorize the app
3. Redirect back to localhost and display your refresh token
4. Print the environment variables you need to set

## Step 4: Update Your Environment Variables

After running the OAuth setup, set your environment variables with the credentials:

```bash
export DROPBOX_APP_KEY="your_app_key"
export DROPBOX_APP_SECRET="your_app_secret"
export DROPBOX_REFRESH_TOKEN="your_refresh_token_from_setup"
```

## Step 5: Run Your Bot

Start your bot as usual:

```bash
./artgrabber
```

You should see a log message indicating it's using OAuth2 refresh token authentication:

```
Using Dropbox OAuth2 refresh token authentication
Successfully initialized Dropbox OAuth2 token source
```

## Troubleshooting

### "Redirect URI mismatch" error

Make sure you added `http://localhost:8888/oauth/callback` to your app's Redirect URIs in the Dropbox App Console.

### "Invalid refresh token" error

Your refresh token may have been revoked. Run the OAuth setup tool again to get a new one.

### Port 8888 is already in use

The OAuth setup tool uses port 8888 temporarily. If it's in use, stop the process using that port or wait for the OAuth setup to complete (it only runs for 5 minutes max).

## Security Notes

- Keep your **App Secret** and **Refresh Token** secure - treat them like passwords
- Don't commit them to version control
- Use environment variables or secure secret management
- If compromised, you can revoke access in the Dropbox App Console and generate new credentials
