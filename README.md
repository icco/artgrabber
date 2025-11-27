# ArtGrabber

A Golang Discord bot that watches a folder for new images and automatically uploads them to a Discord channel.

## Features

- 📁 Watches a directory and all subdirectories for new image files
- 🖼️ Supports common image formats: JPG, PNG, GIF, WebP, BMP
- 🤖 Automatically uploads new images to a specified Discord channel
- 🔄 Recursive directory watching (monitors all subdirectories)
- 🛡️ Duplicate prevention with cooldown system
- 📊 File size validation (respects Discord's 8MB limit)
- 🌐 Built-in HTTP server with health check endpoints
- 📝 Structured JSON logging with zerolog
- ✅ Graceful shutdown handling

## Setup

### 1. Create a Discord Bot

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click "New Application" and give it a name
3. Go to the "Bot" section and click "Add Bot"
4. Under "Token", click "Reset Token" and copy the token (you'll need this)
5. Enable "MESSAGE CONTENT INTENT" under "Privileged Gateway Intents"
6. Go to "OAuth2" > "URL Generator"
   - Select scopes: `bot`
   - Select bot permissions: `Send Messages`, `Attach Files`
   - Copy the generated URL and open it in your browser to invite the bot to your server

### 2. Get Your Channel ID

1. Enable Developer Mode in Discord (Settings > Advanced > Developer Mode)
2. Right-click on the channel where you want images posted
3. Click "Copy Channel ID"

### 3. Configure the Bot

Set the following environment variables:

```bash
export DISCORD_BOT_TOKEN="your-bot-token-here"
export DISCORD_CHANNEL_ID="your-channel-id-here"
export WATCH_DIR="$HOME/Dropbox/Photos/gallery-dl"  # Optional, defaults to this path
export PORT="8080"  # Optional, defaults to 8080
```

Or create a `.env` file (see `.env.example`)

### 4. Run the Bot

```bash
# Build and run
go build -o artgrabber
./artgrabber

# Or run directly
go run main.go
```

## Usage

Once the bot is running:

1. It will automatically watch the configured directory and all subdirectories
2. When a new image file is created or modified, it will be uploaded to Discord
3. The bot will log all activity to the console in JSON format
4. The HTTP server will be available for health checks
5. Press Ctrl+C to gracefully stop the bot

## Configuration

| Environment Variable | Required | Default | Description |
|---------------------|----------|---------|-------------|
| `DISCORD_BOT_TOKEN` | Yes | - | Your Discord bot token |
| `DISCORD_CHANNEL_ID` | Yes | - | The Discord channel ID to upload images to |
| `WATCH_DIR` | No | `~/Dropbox/Photos/gallery-dl` | The directory to watch for new images |
| `PORT` | No | `8080` | HTTP server port for health checks |

## HTTP Endpoints

The bot includes a built-in HTTP server for monitoring:

- `GET /health` - Basic health check (always returns 200 if server is running)
- `GET /ready` - Readiness check (returns 200 if Discord is connected, 503 otherwise)

## How It Works

1. The bot starts and recursively adds all directories under `WATCH_DIR` to the file watcher
2. When a new directory is created, it's automatically added to the watch list
3. When a new image file is created or modified, the bot:
   - Waits 500ms to ensure the file is fully written
   - Checks if it's an image file (by extension)
   - Verifies the file size is under 8MB
   - Uploads it to the configured Discord channel
   - Tracks the upload to prevent duplicates (5-second cooldown)

## Supported Image Formats

- JPEG (.jpg, .jpeg)
- PNG (.png)
- GIF (.gif)
- WebP (.webp)
- BMP (.bmp)

## Troubleshooting

**Bot doesn't upload images:**
- Verify the bot has proper permissions in Discord (Send Messages, Attach Files)
- Check that the channel ID is correct
- Ensure the watch directory exists and is accessible

**"File size exceeds Discord limit" error:**
- Discord has an 8MB file size limit for regular users
- Consider compressing images or upgrading to Discord Nitro for 50MB limit

**Bot crashes on startup:**
- Verify your Discord token is valid
- Check that the watch directory exists
- Ensure you have read permissions on the directory

## License

See LICENSE file for details.