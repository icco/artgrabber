# ArtGrabber

A Discord bot that monitors a Dropbox folder for new images and automatically uploads them to a Discord channel.

## Features

- Monitors Dropbox folder recursively via OAuth2
- Supports JPG, PNG, GIF, WebP, BMP
- Automatic token refresh (no manual intervention)
- SQLite tracking (no duplicate uploads)
- Health check endpoints
- Docker support
- **Voting system**: React with number emojis (1️⃣-5️⃣) to copy images to wallpapers folder

## Setup

### 1. Discord Setup

1. Create a bot at [Discord Developer Portal](https://discord.com/developers/applications)
2. Copy the bot token
3. Enable "MESSAGE CONTENT INTENT" in Bot settings
4. Invite bot with permissions: `Send Messages`, `Attach Files`, `Add Reactions`, `Read Message History`
5. Enable Developer Mode in Discord and copy your channel ID

### 2. Dropbox OAuth Setup

Run the OAuth setup tool to get your credentials:

```bash
go run cmd/oauth-setup/main.go
```

See [OAUTH_SETUP.md](OAUTH_SETUP.md) for detailed instructions.

### 3. Configure Environment

```bash
# Required
export DISCORD_BOT_TOKEN="your-bot-token"
export DISCORD_CHANNEL_ID="your-channel-id"
export DROPBOX_APP_KEY="your-app-key"
export DROPBOX_APP_SECRET="your-app-secret"
export DROPBOX_REFRESH_TOKEN="your-refresh-token"

# Optional
export DROPBOX_FOLDER="/Photos/gallery-dl"
export WALLPAPERS_FOLDER="/photos/wallpapers"
export POLL_INTERVAL="5m"
export PORT="8080"
```

Or use `.env` file (see `.env.example`)

### 4. Run

**Go:**
```bash
go build -o artgrabber
./artgrabber
```

**Docker:**
```bash
docker build -t artgrabber .
docker run --rm --env-file .env -v artgrabber-data:/data -p 8080:8080 artgrabber
```

**Task:** (see `task --list` for all commands)
```bash
task build && ./artgrabber
```

## How It Works

1. Bot polls Dropbox folder every `POLL_INTERVAL` (default: 5 minutes)
2. New images are downloaded and uploaded to Discord with numbered reactions (1️⃣-5️⃣)
3. SQLite database tracks processed files to prevent duplicates
4. Access tokens refresh automatically via OAuth2
5. Users can vote for images by clicking the number reactions
6. Voted images are automatically copied to the wallpapers folder in Dropbox

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DISCORD_BOT_TOKEN` | Yes | - | Discord bot token |
| `DISCORD_CHANNEL_ID` | Yes | - | Target Discord channel |
| `DROPBOX_APP_KEY` | Yes | - | Dropbox app key |
| `DROPBOX_APP_SECRET` | Yes | - | Dropbox app secret |
| `DROPBOX_REFRESH_TOKEN` | Yes | - | OAuth refresh token |
| `DROPBOX_FOLDER` | No | `/Photos/gallery-dl` | Folder to monitor |
| `WALLPAPERS_FOLDER` | No | `/photos/wallpapers` | Folder for voted images |
| `POLL_INTERVAL` | No | `5m` | Check interval |
| `PORT` | No | `8080` | HTTP server port |

## Endpoints

- `GET /` - Status page with last upload info
- `GET /health` - Health check
- `GET /ready` - Readiness check (Discord connection)

## Using the Voting Feature

When the bot posts images to Discord:

1. Each image path is numbered with emoji reactions (1️⃣, 2️⃣, 3️⃣, 4️⃣, 5️⃣)
2. The bot automatically adds these reactions to the message
3. Click any number reaction to vote for that image
4. The bot will copy the voted image to your configured wallpapers folder in Dropbox
5. A confirmation message is posted showing which file was copied and who voted

**Example:**
```
1️⃣ /Photos/gallery-dl/art/image1.jpg
2️⃣ /Photos/gallery-dl/art/image2.jpg
3️⃣ /Photos/gallery-dl/art/image3.jpg
```

Click 2️⃣ → Bot copies `image2.jpg` to `/photos/wallpapers/`

## Development

Uses [Task](https://taskfile.dev) for automation. Run `task --list` to see all commands.

Common tasks:
```bash
task build      # Build binary
task run        # Run bot
task lint       # Lint and format
task test       # Run tests
```

## Troubleshooting

**Images not uploading:**
- Check Discord bot permissions (Send Messages, Attach Files, Add Reactions, Read Message History)
- Verify channel ID is correct
- Confirm Dropbox OAuth credentials are valid
- Check folder path (case-sensitive)

**Token expired errors:**
- Run `go run cmd/oauth-setup/main.go` to get fresh credentials
- Verify all three OAuth variables are set (APP_KEY, APP_SECRET, REFRESH_TOKEN)

**Duplicate uploads:**
- Ensure `/data` volume persists between restarts
- Check `/data/artgrabber.db` exists and is not corrupted

**Files too large:**
- Discord limit: 8MB (50MB with Nitro)
- Bot automatically skips files over limit

## License

MIT - See LICENSE file.