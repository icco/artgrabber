# artgrabber

A Discord bot written in Golang for grabbing and sharing art content.

## Features

- Basic Discord bot setup with event handlers
- Command handling system
- Configurable via environment variables

## Prerequisites

- Go 1.24 or higher
- A Discord bot token (see setup instructions below)

## Setup

### 1. Create a Discord Bot

1. Go to the [Discord Developer Portal](https://discord.com/developers/applications)
2. Click "New Application" and give it a name
3. Navigate to the "Bot" section in the left sidebar
4. Click "Add Bot"
5. Under the "Token" section, click "Copy" to copy your bot token
6. Under "Privileged Gateway Intents", enable:
   - MESSAGE CONTENT INTENT
   - SERVER MEMBERS INTENT (optional)

### 2. Configure the Bot

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and replace `your_discord_bot_token_here` with your actual bot token

### 3. Invite the Bot to Your Server

1. In the Discord Developer Portal, go to "OAuth2" > "URL Generator"
2. Select the following scopes:
   - `bot`
3. Select the following bot permissions:
   - Read Messages/View Channels
   - Send Messages
   - Read Message History
4. Copy the generated URL and open it in your browser to invite the bot to your server

## Running the Bot

### Development

```bash
# Load environment variables and run
source .env
go run main.go
```

### Production

```bash
# Build the binary
go build -o artgrabber

# Run with environment variable
DISCORD_BOT_TOKEN=your_token ./artgrabber
```

## Available Commands

- `!ping` - Check if the bot is responsive
- `!help` - Display help message with available commands

## Development

### Building

```bash
go build -v
```

### Running Tests

```bash
go test ./...
```

### Dependencies

This project uses the following main dependencies:
- [discordgo](https://github.com/bwmarrin/discordgo) - Discord API wrapper for Go

## Project Structure

```
.
├── main.go           # Main bot implementation
├── go.mod            # Go module definition
├── go.sum            # Go module checksums
├── .env.example      # Example environment configuration
├── .gitignore        # Git ignore rules
└── README.md         # This file
```

## License

See [LICENSE](LICENSE) file for details.