package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/fsnotify/fsnotify"
)

var (
	token     string
	channelID string
	watchDir  string
)

func main() {
	// Load configuration from environment variables
	token = os.Getenv("DISCORD_TOKEN")
	channelID = os.Getenv("DISCORD_CHANNEL_ID")
	watchDir = os.Getenv("WATCH_DIR")

	if token == "" {
		log.Fatal("DISCORD_TOKEN environment variable is required")
	}
	if channelID == "" {
		log.Fatal("DISCORD_CHANNEL_ID environment variable is required")
	}
	if watchDir == "" {
		// Default to ~/Dropbox/Photos/gallery-dl/
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("Failed to get user home directory:", err)
		}
		watchDir = filepath.Join(home, "Dropbox", "Photos", "gallery-dl")
	}

	log.Printf("Starting ArtGrabber bot...")
	log.Printf("Watching directory: %s", watchDir)
	log.Printf("Discord channel ID: %s", channelID)

	// Create Discord session
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Fatal("Error creating Discord session:", err)
	}

	// Open Discord connection
	err = dg.Open()
	if err != nil {
		log.Fatal("Error opening Discord connection:", err)
	}
	defer dg.Close()

	log.Println("Bot is now running. Watching for new files...")

	// Create file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("Error creating file watcher:", err)
	}
	defer watcher.Close()

	// Add the main directory and all subdirectories to the watcher
	err = addDirRecursive(watcher, watchDir)
	if err != nil {
		log.Fatal("Error adding directories to watcher:", err)
	}

	// Track recently uploaded files to avoid duplicates
	recentUploads := make(map[string]time.Time)
	uploadCooldown := 5 * time.Second

	// Watch for file system events
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// Only process create and write events
				if event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write {
					// Check if it's a new directory, and if so, add it to the watcher
					if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
						err := addDirRecursive(watcher, event.Name)
						if err != nil {
							log.Printf("Error adding new directory to watcher: %v", err)
						}
						continue
					}

					// Check if it's an image file
					if isImageFile(event.Name) {
						// Check cooldown to avoid duplicate uploads
						if lastUpload, exists := recentUploads[event.Name]; exists {
							if time.Since(lastUpload) < uploadCooldown {
								continue
							}
						}

						// Small delay to ensure file is fully written
						time.Sleep(500 * time.Millisecond)

						log.Printf("New image detected: %s", event.Name)
						err := uploadImageToDiscord(dg, channelID, event.Name)
						if err != nil {
							log.Printf("Error uploading image: %v", err)
						} else {
							recentUploads[event.Name] = time.Now()
							log.Printf("Successfully uploaded: %s", filepath.Base(event.Name))
						}
					}
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("Watcher error:", err)
			}
		}
	}()

	// Cleanup old entries from recentUploads map periodically
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			for path, uploadTime := range recentUploads {
				if now.Sub(uploadTime) > 5*time.Minute {
					delete(recentUploads, path)
				}
			}
		}
	}()

	// Wait for interrupt signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
	log.Println("Shutting down...")
}

// addDirRecursive adds a directory and all its subdirectories to the watcher
func addDirRecursive(watcher *fsnotify.Watcher, dir string) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			err = watcher.Add(path)
			if err != nil {
				return fmt.Errorf("failed to watch %s: %w", path, err)
			}
			log.Printf("Watching: %s", path)
		}
		return nil
	})
	return err
}

// isImageFile checks if a file is an image based on extension
func isImageFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	imageExtensions := []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
	for _, imgExt := range imageExtensions {
		if ext == imgExt {
			return true
		}
	}
	return false
}

// uploadImageToDiscord uploads an image file to the specified Discord channel
func uploadImageToDiscord(s *discordgo.Session, channelID, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Get file info for size check
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	// Discord has a file size limit (8MB for free, 50MB for Nitro)
	// We'll use 8MB as the safe limit
	maxSize := int64(8 * 1024 * 1024)
	if fileInfo.Size() > maxSize {
		return fmt.Errorf("file size (%d bytes) exceeds Discord limit (8MB)", fileInfo.Size())
	}

	filename := filepath.Base(filePath)

	// Send the file to Discord
	_, err = s.ChannelFileSend(channelID, filename, file)
	if err != nil {
		return fmt.Errorf("failed to send file to Discord: %w", err)
	}

	return nil
}
