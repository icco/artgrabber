package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox"
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/files"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	_ "modernc.org/sqlite"
)

var (
	discordToken   string
	channelID      string
	dropboxToken   string
	dropboxFolder  string
	pollInterval   time.Duration
	port           string
	dataDir        string
	db             *sql.DB
)

func main() {
	// Initialize zerolog for JSON logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

	// Load configuration from environment variables
	discordToken = os.Getenv("DISCORD_BOT_TOKEN")
	channelID = os.Getenv("DISCORD_CHANNEL_ID")
	dropboxToken = os.Getenv("DROPBOX_ACCESS_TOKEN")
	dropboxFolder = os.Getenv("DROPBOX_FOLDER")
	dataDir = os.Getenv("DATA_DIR")
	port = os.Getenv("PORT")
	pollIntervalStr := os.Getenv("POLL_INTERVAL")

	if discordToken == "" {
		log.Fatal().Msg("DISCORD_BOT_TOKEN environment variable is required")
	}
	if channelID == "" {
		log.Fatal().Msg("DISCORD_CHANNEL_ID environment variable is required")
	}
	if dropboxToken == "" {
		log.Fatal().Msg("DROPBOX_ACCESS_TOKEN environment variable is required")
	}
	if dropboxFolder == "" {
		dropboxFolder = "/Photos/gallery-dl"
	}
	if dataDir == "" {
		dataDir = "/data"
	}
	if port == "" {
		port = "8080"
	}
	if pollIntervalStr == "" {
		pollInterval = 5 * time.Minute
	} else {
		var err error
		pollInterval, err = time.ParseDuration(pollIntervalStr)
		if err != nil {
			log.Fatal().Err(err).Msg("Invalid POLL_INTERVAL format")
		}
	}

	log.Info().
		Str("dropbox_folder", dropboxFolder).
		Str("channel_id", channelID).
		Str("data_dir", dataDir).
		Str("port", port).
		Dur("poll_interval", pollInterval).
		Msg("Starting ArtGrabber bot")

	// Initialize database
	var err error
	db, err = initDB()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize database")
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing database")
		}
	}()

	// Create Discord session
	dg, err := discordgo.New("Bot " + discordToken)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating Discord session")
	}

	// Open Discord connection
	err = dg.Open()
	if err != nil {
		log.Fatal().Err(err).Msg("Error opening Discord connection")
	}
	defer func() {
		if err := dg.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing Discord connection")
		}
	}()

	log.Info().Msg("Bot is now running. Polling Dropbox for new files...")

	// Create Dropbox client
	config := dropbox.Config{
		Token: dropboxToken,
	}
	dbxClient := files.New(config)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start polling Dropbox for new files
	go pollDropbox(ctx, dbxClient, dg)

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
		Addr:              ":" + port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
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

	// Cancel polling context
	cancel()

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("HTTP server shutdown error")
	}

	log.Info().Msg("Shutdown complete")
}

// initDB initializes the SQLite database
func initDB() (*sql.DB, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "artgrabber.db")
	database, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create table for tracking processed files
	schema := `
	CREATE TABLE IF NOT EXISTS processed_files (
		path TEXT PRIMARY KEY,
		size INTEGER NOT NULL,
		modified TEXT NOT NULL,
		processed_at TEXT NOT NULL,
		uploaded BOOLEAN NOT NULL DEFAULT 1
	);
	CREATE INDEX IF NOT EXISTS idx_processed_at ON processed_files(processed_at);
	`

	if _, err := database.Exec(schema); err != nil {
		database.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	log.Info().Str("db_path", dbPath).Msg("Database initialized")
	return database, nil
}

// pollDropbox continuously polls Dropbox for new files
func pollDropbox(ctx context.Context, dbxClient files.Client, dg *discordgo.Session) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// Run immediately on start
	scanDropboxFolder(ctx, dbxClient, dg)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Stopping Dropbox polling")
			return
		case <-ticker.C:
			scanDropboxFolder(ctx, dbxClient, dg)
		}
	}
}

// scanDropboxFolder scans the Dropbox folder for new image files
func scanDropboxFolder(ctx context.Context, dbxClient files.Client, dg *discordgo.Session) {
	log.Debug().Msg("Scanning Dropbox folder")

	listArg := files.NewListFolderArg(dropboxFolder)
	listArg.Recursive = true

	result, err := dbxClient.ListFolder(listArg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list Dropbox folder")
		return
	}

	processEntries(ctx, result.Entries, dbxClient, dg)

	// Handle pagination
	for result.HasMore {
		continueArg := files.NewListFolderContinueArg(result.Cursor)
		result, err = dbxClient.ListFolderContinue(continueArg)
		if err != nil {
			log.Error().Err(err).Msg("Failed to continue listing Dropbox folder")
			return
		}
		processEntries(ctx, result.Entries, dbxClient, dg)
	}
}

// processEntries processes a batch of Dropbox entries
func processEntries(ctx context.Context, entries []files.IsMetadata, dbxClient files.Client, dg *discordgo.Session) {
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Only process files, not folders
		fileMetadata, ok := entry.(*files.FileMetadata)
		if !ok {
			continue
		}

		// Check if it's an image file
		if !isImageFile(fileMetadata.Name) {
			continue
		}

		// Check if we've already processed this file
		if isFileProcessed(fileMetadata) {
			continue
		}

		log.Info().
			Str("path", fileMetadata.PathDisplay).
			Str("name", fileMetadata.Name).
			Int64("size", int64(fileMetadata.Size)).
			Msg("New image detected")

		// Download and upload the file
		if err := downloadAndUpload(ctx, dbxClient, dg, fileMetadata); err != nil {
			log.Error().
				Err(err).
				Str("path", fileMetadata.PathDisplay).
				Msg("Failed to process file")
		} else {
			// Mark file as processed
			if err := markFileProcessed(fileMetadata); err != nil {
				log.Error().
					Err(err).
					Str("path", fileMetadata.PathDisplay).
					Msg("Failed to mark file as processed")
			}
		}
	}
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

// isFileProcessed checks if a file has already been processed
func isFileProcessed(metadata *files.FileMetadata) bool {
	var count int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM processed_files WHERE path = ? AND size = ? AND modified = ?",
		metadata.PathLower,
		metadata.Size,
		metadata.ServerModified.Format(time.RFC3339),
	).Scan(&count)

	if err != nil {
		log.Error().Err(err).Msg("Failed to check if file is processed")
		return false
	}

	return count > 0
}

// markFileProcessed marks a file as processed in the database
func markFileProcessed(metadata *files.FileMetadata) error {
	_, err := db.Exec(
		"INSERT OR REPLACE INTO processed_files (path, size, modified, processed_at, uploaded) VALUES (?, ?, ?, ?, ?)",
		metadata.PathLower,
		metadata.Size,
		metadata.ServerModified.Format(time.RFC3339),
		time.Now().Format(time.RFC3339),
		true,
	)
	return err
}

// downloadAndUpload downloads a file from Dropbox and uploads it to Discord
func downloadAndUpload(ctx context.Context, dbxClient files.Client, dg *discordgo.Session, metadata *files.FileMetadata) error {
	// Discord has a file size limit (8MB for free, 50MB for Nitro)
	maxSize := uint64(8 * 1024 * 1024)
	if metadata.Size > maxSize {
		return fmt.Errorf("file size (%d bytes) exceeds Discord limit (8MB)", metadata.Size)
	}

	// Download file from Dropbox
	downloadArg := files.NewDownloadArg(metadata.PathLower)
	_, content, err := dbxClient.Download(downloadArg)
	if err != nil {
		return fmt.Errorf("failed to download from Dropbox: %w", err)
	}
	defer content.Close()

	// Read file content into memory
	data, err := io.ReadAll(content)
	if err != nil {
		return fmt.Errorf("failed to read file content: %w", err)
	}

	// Create a reader from the data
	reader := strings.NewReader(string(data))

	// Send the file to Discord
	_, err = dg.ChannelFileSend(channelID, metadata.Name, reader)
	if err != nil {
		return fmt.Errorf("failed to send file to Discord: %w", err)
	}

	log.Info().
		Str("filename", metadata.Name).
		Str("path", metadata.PathDisplay).
		Msg("Successfully uploaded to Discord")

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
	if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
		log.Error().Err(err).Msg("Error writing health check response")
	}
}

// readyCheckHandler returns readiness status including Discord connection
func readyCheckHandler(dg *discordgo.Session) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Check if Discord session is ready
		if dg == nil || !dg.DataReady {
			w.WriteHeader(http.StatusServiceUnavailable)
			if _, err := w.Write([]byte(`{"status":"not_ready","discord":"disconnected"}`)); err != nil {
				log.Error().Err(err).Msg("Error writing ready check response")
			}
			return
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"status":"ready","discord":"connected"}`)); err != nil {
			log.Error().Err(err).Msg("Error writing ready check response")
		}
	}
}
