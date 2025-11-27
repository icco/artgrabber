package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/bwmarrin/discordgo"
)

var (
	// Bot token from environment
	Token string
)

func init() {
	Token = os.Getenv("DISCORD_BOT_TOKEN")
	if Token == "" {
		log.Fatal("DISCORD_BOT_TOKEN environment variable is required")
	}
}

func main() {
	// Create a new Discord session using the provided bot token
	dg, err := discordgo.New("Bot " + Token)
	if err != nil {
		log.Fatalf("Error creating Discord session: %v", err)
	}

	// Register the messageCreate func as a callback for MessageCreate events
	dg.AddHandler(messageCreate)

	// Register the ready event handler
	dg.AddHandler(ready)

	// Set intents for the bot
	dg.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsDirectMessages | discordgo.IntentsMessageContent

	// Open a websocket connection to Discord and begin listening
	err = dg.Open()
	if err != nil {
		log.Fatalf("Error opening connection: %v", err)
	}
	defer dg.Close()

	// Wait here until CTRL-C or other term signal is received
	fmt.Println("Bot is now running. Press CTRL-C to exit.")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
}

// ready is called when the bot is connected to Discord
func ready(s *discordgo.Session, event *discordgo.Ready) {
	log.Printf("Bot is ready! Logged in as: %v", event.User.Username)
	// Set the playing status
	s.UpdateGameStatus(0, "Art Grabber | !help")
}

// messageCreate is called whenever a message is created in a channel the bot can see
func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	// Ignore all messages created by the bot itself
	if m.Author.ID == s.State.User.ID {
		return
	}

	// Respond to !ping command
	if m.Content == "!ping" {
		_, err := s.ChannelMessageSend(m.ChannelID, "Pong!")
		if err != nil {
			log.Printf("Error sending message: %v", err)
		}
	}

	// Respond to !help command
	if m.Content == "!help" {
		helpMessage := `**Art Grabber Bot Commands:**
!ping - Check if the bot is responsive
!help - Display this help message

This bot is designed to grab and share art content.`
		_, err := s.ChannelMessageSend(m.ChannelID, helpMessage)
		if err != nil {
			log.Printf("Error sending message: %v", err)
		}
	}
}
