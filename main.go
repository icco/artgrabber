package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
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
	"golang.org/x/oauth2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ImageFile represents an image file discovered in Dropbox
// Table name is "processed_files" for backwards compatibility
type ImageFile struct {
	Path        string     `gorm:"primaryKey"`
	ContentHash *string    `gorm:"uniqueIndex"` // Dropbox content hash for dedup; NULL when unavailable
	Size        uint64     `gorm:"not null"`
	Modified    time.Time  `gorm:"not null"`
	ProcessedAt time.Time  `gorm:"not null;index"` // When first discovered
	DeliveredAt *time.Time `gorm:"index"`          // When sent to Discord; nil means not yet delivered
}

// TableName keeps the same table name for backwards compatibility
func (ImageFile) TableName() string {
	return "processed_files"
}

// MessageTracking represents a Discord message with file tracking for voting
type MessageTracking struct {
	MessageID string    `gorm:"primaryKey;not null"`
	FilePath  string    `gorm:"not null"`
	FileIndex int       `gorm:"primaryKey;not null"`
	CreatedAt time.Time `gorm:"not null;index"`
}

var (
	discordToken        string
	channelID           string
	dropboxAppKey       string
	dropboxAppSecret    string
	dropboxRefreshToken string
	dropboxFolder       string
	wallpapersFolder    string
	pollInterval        time.Duration
	port                string
	dataDir             string
	db                  *gorm.DB
	dropboxTokenSource  oauth2.TokenSource // For auto-refreshing tokens

	// Message tracking for voting
	messageTrackingTTL = 24 * time.Hour // Keep message tracking for 24 hours

	// Voting emoji constants
	numberEmojis = []string{"1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"}
	emojiToIndex = map[string]int{
		"1️⃣": 0, "2️⃣": 1, "3️⃣": 2, "4️⃣": 3, "5️⃣": 4,
		"6️⃣": 5, "7️⃣": 6, "8️⃣": 7, "9️⃣": 8, "🔟": 9,
	}
)

func main() {
	// Initialize zerolog for JSON logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

	// Load configuration from environment variables
	discordToken = os.Getenv("DISCORD_BOT_TOKEN")
	channelID = os.Getenv("DISCORD_CHANNEL_ID")
	dropboxAppKey = os.Getenv("DROPBOX_APP_KEY")
	dropboxAppSecret = os.Getenv("DROPBOX_APP_SECRET")
	dropboxRefreshToken = os.Getenv("DROPBOX_REFRESH_TOKEN")
	dropboxFolder = os.Getenv("DROPBOX_FOLDER")
	wallpapersFolder = os.Getenv("WALLPAPERS_FOLDER")
	dataDir = os.Getenv("DATA_DIR")
	port = os.Getenv("PORT")
	pollIntervalStr := os.Getenv("POLL_INTERVAL")

	if discordToken == "" {
		log.Fatal().Msg("DISCORD_BOT_TOKEN environment variable is required")
	}
	if channelID == "" {
		log.Fatal().Msg("DISCORD_CHANNEL_ID environment variable is required")
	}
	if dropboxAppKey == "" || dropboxAppSecret == "" || dropboxRefreshToken == "" {
		log.Fatal().Msg("Dropbox OAuth credentials required: DROPBOX_APP_KEY, DROPBOX_APP_SECRET, and DROPBOX_REFRESH_TOKEN. Run 'go run cmd/oauth-setup/main.go' to set up.")
	}

	log.Info().Msg("Using Dropbox OAuth2 refresh token authentication")
	// Initialize token source for automatic refresh
	initDropboxTokenSource()
	if dropboxFolder == "" {
		dropboxFolder = "/Photos/gallery-dl"
	}
	if wallpapersFolder == "" {
		wallpapersFolder = "/Photos/Wallpapers"
	}
	if dataDir == "" {
		dataDir = "/data"
	}
	if port == "" {
		port = "8080"
	}
	if pollIntervalStr == "" {
		pollInterval = 10 * time.Minute
	} else {
		var err error
		pollInterval, err = time.ParseDuration(pollIntervalStr)
		if err != nil {
			log.Fatal().Err(err).Msg("Invalid POLL_INTERVAL format")
		}
	}

	log.Info().
		Str("dropbox_folder", dropboxFolder).
		Str("wallpapers_folder", wallpapersFolder).
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
		sqlDB, err := db.DB()
		if err != nil {
			log.Error().Err(err).Msg("Error getting database instance")
			return
		}
		if err := sqlDB.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing database")
		}
	}()

	// Create Discord session
	dg, err := discordgo.New("Bot " + discordToken)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating Discord session")
	}

	// Add reaction handler for voting
	dg.AddHandler(messageReactionAddHandler)

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

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start polling Dropbox for new files (client is created on each poll cycle)
	go pollDropbox(ctx, dg)

	// Start periodic delivery of images (every 30 minutes)
	go deliverImagesPeriodically(ctx, dg)

	// Start cleanup routine for message tracking
	go cleanupOldMessageTracking(ctx)

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

// initDropboxTokenSource initializes the OAuth2 token source for automatic token refresh
func initDropboxTokenSource() {
	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     dropboxAppKey,
		ClientSecret: dropboxAppSecret,
		Endpoint:     dropbox.OAuthEndpoint(""),
	}

	// Create token from refresh token
	tok := &oauth2.Token{
		RefreshToken: dropboxRefreshToken,
	}

	// Create token source that will automatically refresh the token
	dropboxTokenSource = oauth2Config.TokenSource(context.Background(), tok)

	// Test that we can get a token
	_, err := dropboxTokenSource.Token()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get access token from refresh token")
	}

	log.Info().Msg("Successfully initialized Dropbox OAuth2 token source")
}

// createDropboxClient creates a Dropbox client using OAuth2 token source
func createDropboxClient() files.Client {
	// Get the current access token (this will automatically refresh if needed)
	currentToken, err := dropboxTokenSource.Token()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get access token from token source")
	}

	// Create Dropbox config and client
	config := dropbox.Config{
		Token: currentToken.AccessToken,
	}

	return files.New(config)
}

// initDB initializes the GORM database
func initDB() (*gorm.DB, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "artgrabber.db")
	database, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// AutoMigrate will create/update the table schema
	if err := database.AutoMigrate(&ImageFile{}, &MessageTracking{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database schema: %w", err)
	}

	log.Info().Str("db_path", dbPath).Msg("Database initialized")
	return database, nil
}

// messageReactionAddHandler handles reactions added to messages for voting
func messageReactionAddHandler(s *discordgo.Session, r *discordgo.MessageReactionAdd) {
	// Ignore reactions from the bot itself
	if r.UserID == s.State.User.ID {
		return
	}

	// Only process reactions in the configured channel
	if r.ChannelID != channelID {
		return
	}

	// Map emoji to index
	index, validEmoji := emojiToIndex[r.Emoji.Name]
	if !validEmoji {
		// Not a valid voting emoji
		return
	}

	// Get the file path from database
	selectedPath, err := getFilePathByMessageAndIndex(r.MessageID, index)
	if err != nil {
		log.Error().
			Err(err).
			Str("message_id", r.MessageID).
			Int("index", index).
			Msg("Failed to get file path from database")
		return
	}

	if selectedPath == "" {
		// No file found for this message/index (not our message or invalid index)
		return
	}

	log.Info().
		Str("message_id", r.MessageID).
		Str("user_id", r.UserID).
		Str("emoji", r.Emoji.Name).
		Int("index", index).
		Str("file_path", selectedPath).
		Msg("User voted for file")

	// Copy the file to Photos/Wallpapers
	destinationPath := filepath.Join(wallpapersFolder, filepath.Base(selectedPath))

	// Create Dropbox client
	dbxClient := createDropboxClient()

	// Copy the file in Dropbox
	// Use autorename to avoid conflicts if file already exists
	copyArg := files.NewRelocationArg(selectedPath, destinationPath)
	copyArg.Autorename = true
	copyResult, err := dbxClient.CopyV2(copyArg)
	if err != nil {
		log.Error().
			Err(err).
			Str("source", selectedPath).
			Str("destination", destinationPath).
			Msg("Failed to copy file in Dropbox")

		// Check if error is due to file already existing
		errorMsg := fmt.Sprintf("❌ Failed to copy `%s` to wallpapers folder: %v",
			filepath.Base(selectedPath), err)

		_, sendErr := s.ChannelMessageSend(r.ChannelID, errorMsg)
		if sendErr != nil {
			log.Error().Err(sendErr).Msg("Failed to send error message")
		}
		return
	}

	// Get the final path (may be renamed if autorename was triggered)
	finalPath := destinationPath
	if copyResult != nil && copyResult.Metadata != nil {
		if fileMetadata, ok := copyResult.Metadata.(*files.FileMetadata); ok {
			finalPath = fileMetadata.PathDisplay
		}
	}

	log.Info().
		Str("source", selectedPath).
		Str("destination", finalPath).
		Msg("Successfully copied file to wallpapers")

	// Send confirmation message to channel
	// Use UserID as fallback if User() API call fails
	userName := r.UserID
	user, err := s.User(r.UserID)
	if err == nil && user != nil {
		userName = user.Username
	}

	confirmMsg := fmt.Sprintf("✅ Copied `%s` to `%s` (voted by %s)",
		filepath.Base(selectedPath), wallpapersFolder, userName)

	_, err = s.ChannelMessageSend(r.ChannelID, confirmMsg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to send confirmation message")
	}
}

// cleanupOldMessageTracking periodically removes old entries from the message tracking database
func cleanupOldMessageTracking(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Stopping message tracking cleanup")
			return
		case <-ticker.C:
			cutoffTime := time.Now().Add(-messageTrackingTTL)
			result := db.Where("created_at < ?", cutoffTime).Delete(&MessageTracking{})
			if result.Error != nil {
				log.Error().Err(result.Error).Msg("Failed to cleanup old message tracking entries")
				continue
			}

			if result.RowsAffected > 0 {
				log.Info().
					Int64("removed_count", result.RowsAffected).
					Msg("Cleaned up old message tracking entries")
			}
		}
	}
}

// pollDropbox continuously polls Dropbox for new files
func pollDropbox(ctx context.Context, dg *discordgo.Session) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// Run immediately on start
	dbxClient := createDropboxClient()
	scanDropboxFolder(ctx, dbxClient, dg)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Stopping Dropbox polling")
			return
		case <-ticker.C:
			// Recreate client on each poll to ensure fresh token
			dbxClient = createDropboxClient()
			scanDropboxFolder(ctx, dbxClient, dg)
		}
	}
}

// scanDropboxFolder scans the Dropbox folder for new image files and stores them in the database
func scanDropboxFolder(ctx context.Context, dbxClient files.Client, dg *discordgo.Session) {
	log.Debug().Msg("Scanning Dropbox folder")

	listArg := files.NewListFolderArg(dropboxFolder)
	listArg.Recursive = true

	result, err := dbxClient.ListFolder(listArg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list Dropbox folder")
		return
	}

	storeDiscoveredFiles(ctx, result.Entries)

	// Handle pagination
	for result.HasMore {
		continueArg := files.NewListFolderContinueArg(result.Cursor)
		result, err = dbxClient.ListFolderContinue(continueArg)
		if err != nil {
			log.Error().Err(err).Msg("Failed to continue listing Dropbox folder")
			return
		}
		storeDiscoveredFiles(ctx, result.Entries)
	}

	// Note: Image delivery is handled separately by deliverImagesPeriodically
}

// storeDiscoveredFiles stores discovered image files in the database
func storeDiscoveredFiles(ctx context.Context, entries []files.IsMetadata) {
	now := time.Now()

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return
		default:
		}

		fileMetadata, ok := entry.(*files.FileMetadata)
		if !ok || !isImageFile(fileMetadata.Name) {
			continue
		}

		var contentHash *string
		if fileMetadata.ContentHash != "" {
			h := fileMetadata.ContentHash
			contentHash = &h
		}

		// Upsert on path conflict: update metadata if the file was seen before at the
		// same path (e.g. size or modification time changed). delivered_at is not listed
		// in DoUpdates so delivery state is never reset.
		// If a content_hash unique-index conflict occurs instead (same content at a new
		// path), the insert is rejected by the DB constraint; that is intentional dedup.
		result := db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "path"}},
			DoUpdates: clause.AssignmentColumns([]string{"size", "modified", "processed_at", "content_hash"}),
		}).Create(&ImageFile{
			Path:        fileMetadata.PathLower,
			ContentHash: contentHash,
			Size:        fileMetadata.Size,
			Modified:    fileMetadata.ServerModified,
			ProcessedAt: now,
		})
		if result.Error != nil {
			log.Error().
				Err(result.Error).
				Str("path", fileMetadata.PathDisplay).
				Msg("Failed to store discovered file")
		}
	}
}

// deliverImagesPeriodically delivers images every 30 minutes
func deliverImagesPeriodically(ctx context.Context, dg *discordgo.Session) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	// Run immediately on start
	dbxClient := createDropboxClient()
	sendRandomImages(ctx, dbxClient, dg)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Stopping periodic image delivery")
			return
		case <-ticker.C:
			// Recreate client on each delivery to ensure fresh token
			dbxClient = createDropboxClient()
			sendRandomImages(ctx, dbxClient, dg)
		}
	}
}

// sendRandomImages queries the database for N random undelivered images and sends them
func sendRandomImages(ctx context.Context, dbxClient files.Client, dg *discordgo.Session) {
	const maxBatchSize = 10

	// Query for random files that haven't been delivered yet
	var undeliveredFiles []ImageFile
	err := db.Model(&ImageFile{}).
		Where("delivered_at IS NULL").
		Order("RANDOM()").
		Limit(maxBatchSize).
		Find(&undeliveredFiles).Error

	if err != nil {
		log.Error().Err(err).Msg("Failed to query random undelivered images")
		return
	}

	if len(undeliveredFiles) == 0 {
		log.Debug().Msg("No undelivered images found")
		return
	}

	log.Info().
		Int("count", len(undeliveredFiles)).
		Msg("Found random undelivered images to send")

	// Fetch metadata from Dropbox for each file
	var batch []*files.FileMetadata
	for _, img := range undeliveredFiles {
		metadata, err := dbxClient.GetMetadata(&files.GetMetadataArg{
			Path: img.Path,
		})
		if err != nil {
			log.Error().
				Err(err).
				Str("path", img.Path).
				Msg("Failed to get file metadata from Dropbox, marking as delivered to skip")
			// Mark as delivered so we don't keep retrying a missing file
			now := time.Now()
			_ = markAsDelivered(img.Path, now)
			continue
		}

		fileMetadata, ok := metadata.(*files.FileMetadata)
		if !ok {
			log.Warn().
				Str("path", img.Path).
				Msg("Metadata is not a file")
			continue
		}

		batch = append(batch, fileMetadata)
	}

	if len(batch) > 0 {
		processBatch(ctx, batch, dbxClient, dg)
	}
}

// processBatch processes a batch of files and uploads them in a single message
func processBatch(ctx context.Context, batch []*files.FileMetadata, dbxClient files.Client, dg *discordgo.Session) {
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
		// Mark all files as delivered
		now := time.Now()
		for _, fileMetadata := range batch {
			if err := markAsDelivered(fileMetadata.PathLower, now); err != nil {
				log.Error().
					Err(err).
					Str("path", fileMetadata.PathDisplay).
					Msg("Failed to mark file as delivered")
			}
		}

	}
}

// isImageFile checks if a file is an image based on extension
func isImageFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	imageExtensions := []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
	return slices.Contains(imageExtensions, ext)
}

// markAsDelivered marks a file as delivered in the database
func markAsDelivered(path string, deliveredAt time.Time) error {
	result := db.Model(&ImageFile{}).
		Where("path = ?", path).
		Updates(map[string]interface{}{
			"delivered_at": deliveredAt,
		})
	return result.Error
}

// storeMessageTracking stores the message ID and associated file paths in the database
func storeMessageTracking(messageID string, filePaths []string) error {
	createdAt := time.Now()
	var trackingRecords []MessageTracking

	for i, filePath := range filePaths {
		trackingRecords = append(trackingRecords, MessageTracking{
			MessageID: messageID,
			FilePath:  filePath,
			FileIndex: i,
			CreatedAt: createdAt,
		})
	}

	result := db.Create(&trackingRecords)
	if result.Error != nil {
		return fmt.Errorf("failed to insert message tracking: %w", result.Error)
	}

	return nil
}

// getFilePathByMessageAndIndex retrieves the file path for a given message ID and emoji index
func getFilePathByMessageAndIndex(messageID string, index int) (string, error) {
	var tracking MessageTracking
	result := db.Where("message_id = ? AND file_index = ?", messageID, index).First(&tracking)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", nil // No file found for this message/index
		}
		return "", fmt.Errorf("failed to query message tracking: %w", result.Error)
	}

	return tracking.FilePath, nil
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

	// Create message content with numbered file paths
	// Use emoji numbers for voting (1️⃣ through 🔟)
	var messageLines []string
	for i, path := range paths {
		if i < len(numberEmojis) {
			messageLines = append(messageLines, fmt.Sprintf("%s %s", numberEmojis[i], path))
		} else {
			messageLines = append(messageLines, path)
		}
	}
	messageContent := strings.Join(messageLines, "\n")

	// Send all files to Discord in a single message
	msg, err := dg.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
		Content: messageContent,
		Files:   discordFiles,
	})
	if err != nil {
		return fmt.Errorf("failed to send files to Discord: %w", err)
	}

	// Store the message ID with the file paths for voting in database
	if err := storeMessageTracking(msg.ID, paths); err != nil {
		log.Error().
			Err(err).
			Str("message_id", msg.ID).
			Msg("Failed to store message tracking in database")
		// Continue anyway since the files were uploaded
	}

	// Add number reactions to the message for voting (only up to 10 files)
	for i := 0; i < len(paths) && i < len(numberEmojis); i++ {
		if reactErr := dg.MessageReactionAdd(channelID, msg.ID, numberEmojis[i]); reactErr != nil {
			log.Error().
				Err(reactErr).
				Str("emoji", numberEmojis[i]).
				Msg("Failed to add reaction")
		}
	}

	log.Info().
		Int("file_count", len(discordFiles)).
		Strs("files", fileNames).
		Str("message_id", msg.ID).
		Msg("Successfully uploaded batch to Discord")

	return nil
}

// formatBytes formats bytes into a human readable string
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
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

	var lastDeliveredFile ImageFile
	var totalCount, deliveredCount, pendingCount int64
	var totalSize uint64
	var oldestFile, newestFile ImageFile

	// Get the most recent delivered file
	err := db.Where("delivered_at IS NOT NULL").Order("delivered_at DESC").First(&lastDeliveredFile).Error
	hasLastDelivered := err == nil

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().Err(err).Msg("Error querying last delivered file")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get total count of all files
	err = db.Model(&ImageFile{}).Count(&totalCount).Error
	if err != nil {
		log.Error().Err(err).Msg("Error querying total count")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get count of delivered files
	err = db.Model(&ImageFile{}).Where("delivered_at IS NOT NULL").Count(&deliveredCount).Error
	if err != nil {
		log.Error().Err(err).Msg("Error querying delivered count")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get count of pending files
	err = db.Model(&ImageFile{}).Where("delivered_at IS NULL").Count(&pendingCount).Error
	if err != nil {
		log.Error().Err(err).Msg("Error querying pending count")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get total size of all files
	err = db.Model(&ImageFile{}).Select("COALESCE(SUM(size), 0)").Scan(&totalSize).Error
	if err != nil {
		log.Error().Err(err).Msg("Error querying total size")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get oldest file (by modified date)
	err = db.Order("modified ASC").First(&oldestFile).Error
	hasOldest := err == nil
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().Err(err).Msg("Error querying oldest file")
	}

	// Get newest file (by modified date)
	err = db.Order("modified DESC").First(&newestFile).Error
	hasNewest := err == nil
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().Err(err).Msg("Error querying newest file")
	}

	// Format the time
	var timeStr string
	var relativeTime string
	if hasLastDelivered && lastDeliveredFile.DeliveredAt != nil {
		timeStr = lastDeliveredFile.DeliveredAt.Format("2006-01-02 15:04:05 MST")

		// Calculate relative time
		duration := time.Since(*lastDeliveredFile.DeliveredAt)
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
	} else {
		timeStr = "Never"
		relativeTime = "No images processed yet"
	}

	// Get filename from path
	var filename string
	if hasLastDelivered {
		filename = filepath.Base(lastDeliveredFile.Path)
	}

	// Format date range
	var dateRangeStr string
	if hasOldest && hasNewest {
		dateRangeStr = fmt.Sprintf("%s to %s",
			oldestFile.Modified.Format("Jan 2006"),
			newestFile.Modified.Format("Jan 2006"))
	} else {
		dateRangeStr = "N/A"
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
        .stat.pending {
            border-left-color: #FFA500;
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
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stats-grid .stat {
            margin: 0;
        }
        .stat-small .value {
            font-size: 20px;
        }
        .subtext {
            color: #888;
            font-size: 13px;
            margin-top: 3px;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            color: #999;
            font-size: 14px;
        }
        .footer a {
            color: #5865F2;
            text-decoration: none;
        }
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎨 ArtGrabber Status</h1>

        <div class="stat">
            <div class="label">Last Image Delivered</div>
            <div class="value">%s</div>
            <div class="relative-time">%s</div>
            %s
        </div>

        <div class="stats-grid">
            <div class="stat stat-small">
                <div class="label">Total Discovered</div>
                <div class="value">%d</div>
                <div class="subtext">images indexed</div>
            </div>
            <div class="stat stat-small">
                <div class="label">Delivered</div>
                <div class="value">%d</div>
                <div class="subtext">sent to Discord</div>
            </div>
            <div class="stat stat-small pending">
                <div class="label">Pending</div>
                <div class="value">%d</div>
                <div class="subtext">awaiting delivery</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat stat-small">
                <div class="label">Total Size</div>
                <div class="value">%s</div>
                <div class="subtext">across all images</div>
            </div>
            <div class="stat stat-small">
                <div class="label">Date Range</div>
                <div class="value" style="font-size: 18px;">%s</div>
                <div class="subtext">file modified dates</div>
            </div>
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
	}(), totalCount, deliveredCount, pendingCount, formatBytes(totalSize), dateRangeStr, pollInterval)

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
