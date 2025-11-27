# ArtGrabber

A Golang Discord bot that monitors a Dropbox folder for new images and automatically uploads them to a Discord channel.

## Features

- ☁️ Monitors Dropbox folder and all subdirectories via Dropbox API
- 🖼️ Supports common image formats: JPG, PNG, GIF, WebP, BMP
- 🤖 Automatically uploads new images to a specified Discord channel
- 🔄 Recursive folder monitoring (checks all subdirectories)
- 💾 SQLite state management for tracking processed files (survives restarts)
- 📊 File size validation (respects Discord's 8MB limit)
- 🌐 Built-in HTTP server with health check endpoints
- 📝 Structured JSON logging with zerolog
- ✅ Graceful shutdown handling
- 🐳 Docker support with multi-stage builds and persistent storage
- 🛠️ Task automation with Taskfile

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

### 3. Create a Dropbox App

1. Go to [Dropbox App Console](https://www.dropbox.com/developers/apps)
2. Click "Create app"
3. Choose "Scoped access"
4. Choose "Full Dropbox" or "App folder" access
5. Give it a name
6. Go to the "Permissions" tab and enable:
   - `files.metadata.read`
   - `files.content.read`
7. Go to the "Settings" tab and generate an access token

### 4. Configure the Bot

Set the following environment variables:

```bash
export DISCORD_BOT_TOKEN="your-bot-token-here"
export DISCORD_CHANNEL_ID="your-channel-id-here"
export DROPBOX_ACCESS_TOKEN="your-dropbox-token-here"
export DROPBOX_FOLDER="/Photos/gallery-dl"  # Optional, defaults to this path
export DATA_DIR="/data"  # Optional, defaults to /data
export POLL_INTERVAL="5m"  # Optional, defaults to 5 minutes
export PORT="8080"  # Optional, defaults to 8080
```

Or create a `.env` file (see `.env.example`)

### 5. Run the Bot

#### Using Task (recommended)

```bash
# Install task (if not already installed)
# macOS: brew install go-task/tap/go-task
# Linux: sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin

# Build and run
task build
./artgrabber

# Or run directly
task run

# See all available tasks
task --list
```

#### Using Go directly

```bash
# Build and run
go build -o artgrabber
./artgrabber

# Or run directly
go run main.go
```

#### Using Docker

```bash
# Build Docker image
docker build -t artgrabber .

# Run with environment file and persistent storage
docker run --rm \
  --env-file .env \
  -v artgrabber-data:/data \
  -p 8080:8080 \
  artgrabber

# Or with Task
task docker:build
task docker:run
```

## Usage

Once the bot is running:

1. It will poll the configured Dropbox folder and all subdirectories at the specified interval
2. When a new image file is detected, it will be downloaded and uploaded to Discord
3. The bot tracks processed files in a SQLite database (stored in `/data/artgrabber.db`)
4. The bot will log all activity to the console in JSON format
5. The HTTP server will be available for health checks
6. Press Ctrl+C to gracefully stop the bot

## Configuration

| Environment Variable | Required | Default | Description |
|---------------------|----------|---------|-------------|
| `DISCORD_BOT_TOKEN` | Yes | - | Your Discord bot token |
| `DISCORD_CHANNEL_ID` | Yes | - | The Discord channel ID to upload images to |
| `DROPBOX_ACCESS_TOKEN` | Yes | - | Your Dropbox API access token |
| `DROPBOX_FOLDER` | No | `/Photos/gallery-dl` | The Dropbox folder to monitor for new images |
| `POLL_INTERVAL` | No | `5m` | How often to check for new files (e.g., "30s", "5m", "1h") |
| `PORT` | No | `8080` | HTTP server port for health checks |

## HTTP Endpoints

The bot includes a built-in HTTP server for monitoring:

- `GET /health` - Basic health check (always returns 200 if server is running)
- `GET /ready` - Readiness check (returns 200 if Discord is connected, 503 otherwise)

## How It Works

1. The bot starts and initializes a SQLite database in `/data/artgrabber.db` to track processed files
2. Every `POLL_INTERVAL` (default: 5 minutes), the bot:
   - Queries the Dropbox API to list all files in the configured folder recursively
   - Checks each file against the database to see if it's been processed
   - For new image files:
     - Verifies the file size is under 8MB
     - Downloads the file from Dropbox
     - Uploads it to the configured Discord channel
     - Records the file in the database (path, size, modification time)
3. If the container restarts, the database persists (when using Docker volumes) so previously uploaded files won't be re-uploaded

## Supported Image Formats

- JPEG (.jpg, .jpeg)
- PNG (.png)
- GIF (.gif)
- WebP (.webp)
- BMP (.bmp)

## Development

This project uses [Task](https://taskfile.dev) for task automation. Available tasks:

```bash
# Build the binary
task build

# Run the bot
task run

# Run tests
task test

# Run linters and formatters
task lint

# Tidy go modules
task tidy

# Build Docker image
task docker:build

# Run Docker container
task docker:run

# Build for multiple platforms
task build-all

# Clean build artifacts
task clean
```

### Docker Development

The project includes a multi-stage Dockerfile for optimal image size:

```bash
# Build the image
docker build -t artgrabber:dev .

# Run with volume mount for persistent database
docker run --rm \
  -e DISCORD_BOT_TOKEN=your_token \
  -e DISCORD_CHANNEL_ID=your_channel \
  -e DROPBOX_ACCESS_TOKEN=your_dropbox_token \
  -e DROPBOX_FOLDER=/Photos/gallery-dl \
  -e POLL_INTERVAL=5m \
  -v artgrabber-data:/data \
  -p 8080:8080 \
  artgrabber:dev
```

**Important**: The `/data` volume mount is required for the SQLite database to persist across container restarts.

## Troubleshooting

**Bot doesn't upload images:**
- Verify the bot has proper permissions in Discord (Send Messages, Attach Files)
- Check that the channel ID is correct
- Ensure the Dropbox access token is valid and has the required permissions
- Verify the Dropbox folder path is correct (case-sensitive)

**"File size exceeds Discord limit" error:**
- Discord has an 8MB file size limit for regular users
- Consider compressing images or upgrading to Discord Nitro for 50MB limit

**Bot crashes on startup:**
- Verify your Discord token is valid
- Ensure your Dropbox access token is valid
- Check that the Dropbox folder path exists
- Verify `/data` directory is writable (for SQLite database)

**Images are uploaded multiple times:**
- Ensure the `/data` volume is properly mounted and persisting between restarts
- Check that the database file `/data/artgrabber.db` exists and is not corrupted

## License

See LICENSE file for details.