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
	"slices"
	"strings"
	"sync"
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
	discordToken  string
	channelID     string
	dropboxToken  string
	dropboxFolder string
	pollInterval  time.Duration
	port          string
	dataDir       string
	db            *sql.DB

	// Rate limiting: maximum one upload per minute
	lastUploadTime  time.Time
	uploadMutex     sync.Mutex
	uploadRateLimit = time.Minute
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

	// Homepage
	r.Get("/", homepageHandler)

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
	if err := os.MkdirAll(dataDir, 0750); err != nil {
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
		if closeErr := database.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("Error closing database after schema creation failure")
		}
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
	const maxBatchSize = 5
	var batch []*files.FileMetadata

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

		// Add to batch
		batch = append(batch, fileMetadata)

		// Process batch when we have 5 files or this is the last entry
		if len(batch) >= maxBatchSize {
			processBatch(ctx, batch, dbxClient, dg)
			batch = nil
		}
	}

	// Process any remaining files in the batch
	if len(batch) > 0 {
		processBatch(ctx, batch, dbxClient, dg)
	}
}

// processBatch processes a batch of files and uploads them in a single message
func processBatch(ctx context.Context, batch []*files.FileMetadata, dbxClient files.Client, dg *discordgo.Session) {
	// Check rate limit before processing
	uploadMutex.Lock()
	timeSinceLastUpload := time.Since(lastUploadTime)
	if timeSinceLastUpload < uploadRateLimit {
		uploadMutex.Unlock()
		return
	}
	uploadMutex.Unlock()

	log.Info().
		Int("batch_size", len(batch)).
		Msg("Processing batch of images")

	// Download and upload the batch
	if err := downloadAndUploadBatch(ctx, dbxClient, dg, batch); err != nil {
		log.Error().
			Err(err).
			Int("batch_size", len(batch)).
			Msg("Failed to process batch")
	} else {
		// Mark all files as processed
		for _, fileMetadata := range batch {
			if err := markFileProcessed(fileMetadata); err != nil {
				log.Error().
					Err(err).
					Str("path", fileMetadata.PathDisplay).
					Msg("Failed to mark file as processed")
			}
		}

		// Update last upload time after successful upload
		uploadMutex.Lock()
		lastUploadTime = time.Now()
		uploadMutex.Unlock()

		log.Info().
			Int("batch_size", len(batch)).
			Msg("Rate limit: batch upload complete, will wait 1 minute before next upload")
	}
}

// isImageFile checks if a file is an image based on extension
func isImageFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	imageExtensions := []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
	return slices.Contains(imageExtensions, ext)
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

// downloadAndUploadBatch downloads multiple files from Dropbox and uploads them in a single Discord message
func downloadAndUploadBatch(ctx context.Context, dbxClient files.Client, dg *discordgo.Session, batch []*files.FileMetadata) error {
	// Create cache directory if it doesn't exist
	cacheDir := filepath.Join(dataDir, "cache")
	if err := os.MkdirAll(cacheDir, 0750); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Discord has a file size limit (8MB for free, 50MB for Nitro)
	maxSize := uint64(8 * 1024 * 1024)

	// Download all files and prepare Discord file objects
	var discordFiles []*discordgo.File
	var cacheFiles []string
	var paths []string
	var fileNames []string

	// Clean up cache files when done
	defer func() {
		for _, cacheFile := range cacheFiles {
			if removeErr := os.Remove(cacheFile); removeErr != nil {
				log.Error().Err(removeErr).Str("file", cacheFile).Msg("Error removing cache file")
			}
		}
	}()

	for _, metadata := range batch {
		// Check file size
		if metadata.Size > maxSize {
			log.Warn().
				Str("path", metadata.PathDisplay).
				Uint64("size", metadata.Size).
				Msg("Skipping file: exceeds Discord limit (8MB)")
			continue
		}

		// Create a temporary file in the cache directory
		cacheFile := filepath.Join(cacheDir, filepath.Base(metadata.PathLower))

		// Download file from Dropbox to cache
		downloadArg := files.NewDownloadArg(metadata.PathLower)
		_, content, err := dbxClient.Download(downloadArg)
		if err != nil {
			log.Error().
				Err(err).
				Str("path", metadata.PathDisplay).
				Msg("Failed to download from Dropbox")
			continue
		}

		// Write to cache file
		// #nosec G304 -- cacheFile is safely constructed using filepath.Join with filepath.Base, preventing directory traversal
		outFile, err := os.Create(cacheFile)
		if err != nil {
			if closeErr := content.Close(); closeErr != nil {
				log.Error().Err(closeErr).Msg("Error closing Dropbox content stream")
			}
			log.Error().
				Err(err).
				Str("path", metadata.PathDisplay).
				Msg("Failed to create cache file")
			continue
		}

		if _, err := io.Copy(outFile, content); err != nil {
			if closeErr := content.Close(); closeErr != nil {
				log.Error().Err(closeErr).Msg("Error closing Dropbox content stream")
			}
			if closeErr := outFile.Close(); closeErr != nil {
				log.Error().Err(closeErr).Msg("Error closing cache file")
			}
			log.Error().
				Err(err).
				Str("path", metadata.PathDisplay).
				Msg("Failed to write to cache file")
			continue
		}

		if closeErr := content.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("Error closing Dropbox content stream")
		}
		if closeErr := outFile.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("Error closing cache file")
		}

		// Open the cached file for reading
		// #nosec G304 -- cacheFile is safely constructed using filepath.Join with filepath.Base, preventing directory traversal
		cachedFile, err := os.Open(cacheFile)
		if err != nil {
			log.Error().
				Err(err).
				Str("path", metadata.PathDisplay).
				Msg("Failed to open cached file")
			continue
		}

		discordFiles = append(discordFiles, &discordgo.File{
			Name:   metadata.Name,
			Reader: cachedFile,
		})
		cacheFiles = append(cacheFiles, cacheFile)
		paths = append(paths, metadata.PathDisplay)
		fileNames = append(fileNames, metadata.Name)

		log.Info().
			Str("path", metadata.PathDisplay).
			Str("name", metadata.Name).
			Uint64("size", metadata.Size).
			Msg("Downloaded image for batch upload")
	}

	// If no files were successfully downloaded, return an error
	if len(discordFiles) == 0 {
		return fmt.Errorf("no files were successfully downloaded from batch")
	}

	// Close all file handles after sending
	defer func() {
		for _, df := range discordFiles {
			if closer, ok := df.Reader.(io.Closer); ok {
				if closeErr := closer.Close(); closeErr != nil {
					log.Error().Err(closeErr).Msg("Error closing file reader")
				}
			}
		}
	}()

	// Create message content with all file paths
	messageContent := strings.Join(paths, "\n")

	// Send all files to Discord in a single message
	_, err := dg.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
		Content: messageContent,
		Files:   discordFiles,
	})
	if err != nil {
		return fmt.Errorf("failed to send files to Discord: %w", err)
	}

	log.Info().
		Int("file_count", len(discordFiles)).
		Strs("files", fileNames).
		Msg("Successfully uploaded batch to Discord")

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

// homepageHandler displays the homepage with last image stats
func homepageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var lastProcessed sql.NullString
	var totalCount int
	var lastPath sql.NullString

	// Get the most recent processed file
	err := db.QueryRow(`
		SELECT processed_at, path
		FROM processed_files
		ORDER BY processed_at DESC
		LIMIT 1
	`).Scan(&lastProcessed, &lastPath)

	if err != nil && err != sql.ErrNoRows {
		log.Error().Err(err).Msg("Error querying last processed file")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get total count
	err = db.QueryRow(`SELECT COUNT(*) FROM processed_files`).Scan(&totalCount)
	if err != nil {
		log.Error().Err(err).Msg("Error querying total count")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Format the time
	var timeStr string
	var relativeTime string
	if lastProcessed.Valid {
		parsedTime, err := time.Parse(time.RFC3339, lastProcessed.String)
		if err == nil {
			timeStr = parsedTime.Format("2006-01-02 15:04:05 MST")

			// Calculate relative time
			duration := time.Since(parsedTime)
			switch {
			case duration < time.Minute:
				relativeTime = "just now"
			case duration < time.Hour:
				minutes := int(duration.Minutes())
				if minutes == 1 {
					relativeTime = "1 minute ago"
				} else {
					relativeTime = fmt.Sprintf("%d minutes ago", minutes)
				}
			case duration < 24*time.Hour:
				hours := int(duration.Hours())
				if hours == 1 {
					relativeTime = "1 hour ago"
				} else {
					relativeTime = fmt.Sprintf("%d hours ago", hours)
				}
			default:
				days := int(duration.Hours() / 24)
				if days == 1 {
					relativeTime = "1 day ago"
				} else {
					relativeTime = fmt.Sprintf("%d days ago", days)
				}
			}
		}
	} else {
		timeStr = "Never"
		relativeTime = "No images processed yet"
	}

	// Get filename from path
	var filename string
	if lastPath.Valid {
		filename = filepath.Base(lastPath.String)
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ArtGrabber Status</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            margin-top: 0;
        }
        .stat {
            margin: 20px 0;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 4px;
            border-left: 4px solid #5865F2;
        }
        .label {
            font-weight: 600;
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .value {
            font-size: 24px;
            color: #333;
            margin-top: 5px;
        }
        .relative-time {
            color: #666;
            font-size: 16px;
            margin-top: 5px;
        }
        .filename {
            color: #5865F2;
            font-family: monospace;
            font-size: 14px;
            margin-top: 5px;
            word-break: break-all;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            color: #999;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎨 ArtGrabber Status</h1>

        <div class="stat">
            <div class="label">Last Image Grabbed</div>
            <div class="value">%s</div>
            <div class="relative-time">%s</div>
            %s
        </div>

        <div class="stat">
            <div class="label">Total Images Processed</div>
            <div class="value">%d</div>
        </div>

        <div class="footer">
            Polling every %s • <a href="/health">Health</a> • <a href="/ready">Ready</a>
        </div>
    </div>
</body>
</html>`, timeStr, relativeTime, func() string {
		if filename != "" {
			return fmt.Sprintf(`<div class="filename">%s</div>`, filename)
		}
		return ""
	}(), totalCount, pollInterval)

	if _, err := w.Write([]byte(html)); err != nil {
		log.Error().Err(err).Msg("Error writing homepage response")
	}
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
