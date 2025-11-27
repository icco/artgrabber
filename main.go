package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/fsnotify/fsnotify"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	token     string
	channelID string
	watchDir  string
	port      string
)

func main() {
	// Initialize zerolog for JSON logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

	// Load configuration from environment variables
	token = os.Getenv("DISCORD_BOT_TOKEN")
	channelID = os.Getenv("DISCORD_CHANNEL_ID")
	watchDir = os.Getenv("WATCH_DIR")
	port = os.Getenv("PORT")

	if token == "" {
		log.Fatal().Msg("DISCORD_BOT_TOKEN environment variable is required")
	}
	if channelID == "" {
		log.Fatal().Msg("DISCORD_CHANNEL_ID environment variable is required")
	}
	if watchDir == "" {
		// Default to ~/Dropbox/Photos/gallery-dl/
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get user home directory")
		}
		watchDir = filepath.Join(home, "Dropbox", "Photos", "gallery-dl")
	}
	if port == "" {
		port = "8080"
	}

	log.Info().
		Str("watch_dir", watchDir).
		Str("channel_id", channelID).
		Str("port", port).
		Msg("Starting ArtGrabber bot")

	// Create Discord session
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating Discord session")
	}

	// Open Discord connection
	err = dg.Open()
	if err != nil {
		log.Fatal().Err(err).Msg("Error opening Discord connection")
	}
	defer dg.Close()

	log.Info().Msg("Bot is now running. Watching for new files...")

	// Create file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating file watcher")
	}
	defer watcher.Close()

	// Add the main directory and all subdirectories to the watcher
	err = addDirRecursive(watcher, watchDir)
	if err != nil {
		log.Fatal().Err(err).Msg("Error adding directories to watcher")
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
							log.Error().Err(err).Str("directory", event.Name).Msg("Error adding new directory to watcher")
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

						log.Info().Str("file", event.Name).Msg("New image detected")
						err := uploadImageToDiscord(dg, channelID, event.Name)
						if err != nil {
							log.Error().Err(err).Str("file", event.Name).Msg("Error uploading image")
						} else {
							recentUploads[event.Name] = time.Now()
							log.Info().Str("filename", filepath.Base(event.Name)).Msg("Successfully uploaded")
						}
					}
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Error().Err(err).Msg("Watcher error")
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

	// Setup Chi web server
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(zerologMiddleware)
	r.Use(middleware.Recoverer)

	// Health check endpoints
	r.Get("/health", healthCheckHandler)
	r.Get("/ready", readyCheckHandler(dg))

	// Start HTTP server
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	go func() {
		log.Info().Str("port", port).Msg("Starting HTTP server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP server error")
		}
	}()

	// Wait for interrupt signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	log.Info().Msg("Shutting down gracefully...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("HTTP server shutdown error")
	}

	log.Info().Msg("Shutdown complete")
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
			log.Debug().Str("path", path).Msg("Watching directory")
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

// zerologMiddleware adds zerolog logging to HTTP requests
func zerologMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", ww.Status()).
			Int("size", ww.BytesWritten()).
			Dur("duration_ms", time.Since(start)).
			Str("remote_addr", r.RemoteAddr).
			Str("request_id", middleware.GetReqID(r.Context())).
			Msg("HTTP request")
	})
}

// healthCheckHandler returns a simple health check
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// readyCheckHandler returns readiness status including Discord connection
func readyCheckHandler(dg *discordgo.Session) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Check if Discord session is ready
		if dg == nil || dg.DataReady == false {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"not_ready","discord":"disconnected"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready","discord":"connected"}`))
	}
}
