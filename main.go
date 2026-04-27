package main

import (
	"context"
	"errors"
	"fmt"
	"html"
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
	"github.com/icco/gutil/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const service = "artgrabber"

var log = logging.Must(logging.NewLogger(service))

// ImageFile is an image discovered in Dropbox; the table is "processed_files"
// for backwards compatibility.
type ImageFile struct {
	Path        string     `gorm:"primaryKey"`
	ContentHash *string    `gorm:"uniqueIndex"` // Dropbox content hash for dedup; NULL when unavailable
	Size        uint64     `gorm:"not null"`
	Modified    time.Time  `gorm:"not null"`
	ProcessedAt time.Time  `gorm:"not null;index"` // When first discovered
	DeliveredAt *time.Time `gorm:"index"`          // When sent to Discord; nil means not yet delivered
}

// TableName pins the legacy table name.
func (ImageFile) TableName() string {
	return "processed_files"
}

// MessageTracking pairs a Discord message ID + emoji index to a file path.
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

	numberEmojis = []string{"1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"}
	emojiToIndex = map[string]int{
		"1️⃣": 0, "2️⃣": 1, "3️⃣": 2, "4️⃣": 3, "5️⃣": 4,
		"6️⃣": 5, "7️⃣": 6, "8️⃣": 7, "9️⃣": 8, "🔟": 9,
	}
)

func main() {
	ctx, cancel := context.WithCancel(logging.NewContext(context.Background(), log))
	defer cancel()

	registry := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		log.Fatalw("otel prometheus exporter", zap.Error(err))
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	otel.SetMeterProvider(mp)
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := mp.Shutdown(shutdownCtx); err != nil {
			log.Warnw("meter provider shutdown", zap.Error(err))
		}
	}()

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
		log.Fatalw("DISCORD_BOT_TOKEN environment variable is required")
	}
	if channelID == "" {
		log.Fatalw("DISCORD_CHANNEL_ID environment variable is required")
	}
	if dropboxAppKey == "" || dropboxAppSecret == "" || dropboxRefreshToken == "" {
		log.Fatalw("Dropbox OAuth credentials required: DROPBOX_APP_KEY, DROPBOX_APP_SECRET, and DROPBOX_REFRESH_TOKEN. Run 'go run cmd/oauth-setup/main.go' to set up.")
	}

	log.Infow("Using Dropbox OAuth2 refresh token authentication")
	initDropboxTokenSource(ctx)
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
			log.Fatalw("Invalid POLL_INTERVAL format", zap.Error(err))
		}
	}

	log.Infow("Starting ArtGrabber bot",
		"dropbox_folder", dropboxFolder,
		"wallpapers_folder", wallpapersFolder,
		"channel_id", channelID,
		"data_dir", dataDir,
		"port", port,
		"poll_interval", pollInterval,
	)

	db, err = initDB()
	if err != nil {
		log.Fatalw("Failed to initialize database", zap.Error(err))
	}
	defer func() {
		sqlDB, err := db.DB()
		if err != nil {
			log.Errorw("Error getting database instance", zap.Error(err))
			return
		}
		if err := sqlDB.Close(); err != nil {
			log.Errorw("Error closing database", zap.Error(err))
		}
	}()

	dg, err := discordgo.New("Bot " + discordToken)
	if err != nil {
		log.Fatalw("Error creating Discord session", zap.Error(err))
	}

	dg.AddHandler(messageReactionAddHandler)

	if err := dg.Open(); err != nil {
		log.Fatalw("Error opening Discord connection", zap.Error(err))
	}
	defer func() {
		if err := dg.Close(); err != nil {
			log.Errorw("Error closing Discord connection", zap.Error(err))
		}
	}()

	log.Infow("Bot is now running. Polling Dropbox for new files...")

	go pollDropbox(ctx, dg)
	go deliverImagesPeriodically(ctx, dg)
	go cleanupOldMessageTracking(ctx)

	r := chi.NewRouter()
	r.Use(logging.Middleware(log.Desugar()))
	r.Use(routeTag)

	r.Get("/", homepageHandler)
	r.Get("/health", healthCheckHandler)
	r.Get("/ready", readyCheckHandler(dg))
	r.Method(http.MethodGet, "/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	handler := otelhttp.NewHandler(r, service,
		otelhttp.WithFilter(func(req *http.Request) bool {
			return req.URL.Path != "/metrics"
		}),
	)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Infow("Starting HTTP server", "port", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalw("HTTP server error", zap.Error(err))
		}
	}()

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	log.Infow("Shutting down gracefully...")

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Errorw("HTTP server shutdown error", zap.Error(err))
	}

	log.Infow("Shutdown complete")
}

// initDropboxTokenSource initializes the OAuth2 token source for automatic token refresh.
func initDropboxTokenSource(ctx context.Context) {
	oauth2Config := &oauth2.Config{
		ClientID:     dropboxAppKey,
		ClientSecret: dropboxAppSecret,
		Endpoint:     dropbox.OAuthEndpoint(""),
	}

	tok := &oauth2.Token{
		RefreshToken: dropboxRefreshToken,
	}

	dropboxTokenSource = oauth2Config.TokenSource(ctx, tok)

	if _, err := dropboxTokenSource.Token(); err != nil {
		log.Fatalw("Failed to get access token from refresh token", zap.Error(err))
	}

	log.Infow("Successfully initialized Dropbox OAuth2 token source")
}

// createDropboxClient creates a Dropbox client using OAuth2 token source.
func createDropboxClient() files.Client {
	currentToken, err := dropboxTokenSource.Token()
	if err != nil {
		log.Fatalw("Failed to get access token from token source", zap.Error(err))
	}

	config := dropbox.Config{
		Token: currentToken.AccessToken,
	}

	return files.New(config)
}

// initDB initializes the GORM database.
func initDB() (*gorm.DB, error) {
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "artgrabber.db")
	database, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := database.AutoMigrate(&ImageFile{}, &MessageTracking{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database schema: %w", err)
	}

	log.Infow("Database initialized", "db_path", dbPath)
	return database, nil
}

// messageReactionAddHandler routes a vote reaction to the matching tracked file.
func messageReactionAddHandler(s *discordgo.Session, r *discordgo.MessageReactionAdd) {
	if r.UserID == s.State.User.ID {
		return
	}
	if r.ChannelID != channelID {
		return
	}

	index, validEmoji := emojiToIndex[r.Emoji.Name]
	if !validEmoji {
		return
	}

	selectedPath, err := getFilePathByMessageAndIndex(r.MessageID, index)
	if err != nil {
		log.Errorw("Failed to get file path from database",
			"message_id", r.MessageID,
			"index", index,
			zap.Error(err),
		)
		return
	}

	if selectedPath == "" {
		return
	}

	log.Infow("User voted for file",
		"message_id", r.MessageID,
		"user_id", r.UserID,
		"emoji", r.Emoji.Name,
		"index", index,
		"file_path", selectedPath,
	)

	destinationPath := filepath.Join(wallpapersFolder, filepath.Base(selectedPath))
	dbxClient := createDropboxClient()

	// Autorename avoids name collisions in the wallpapers folder.
	copyArg := files.NewRelocationArg(selectedPath, destinationPath)
	copyArg.Autorename = true
	copyResult, err := dbxClient.CopyV2(copyArg)
	if err != nil {
		log.Errorw("Failed to copy file in Dropbox",
			"source", selectedPath,
			"destination", destinationPath,
			zap.Error(err),
		)

		errorMsg := fmt.Sprintf("❌ Failed to copy `%s` to wallpapers folder: %v",
			filepath.Base(selectedPath), err)

		if _, sendErr := s.ChannelMessageSend(r.ChannelID, errorMsg); sendErr != nil {
			log.Errorw("Failed to send error message", zap.Error(sendErr))
		}
		return
	}

	finalPath := destinationPath
	if copyResult != nil && copyResult.Metadata != nil {
		if fileMetadata, ok := copyResult.Metadata.(*files.FileMetadata); ok {
			finalPath = fileMetadata.PathDisplay
		}
	}

	log.Infow("Successfully copied file to wallpapers",
		"source", selectedPath,
		"destination", finalPath,
	)

	userName := r.UserID
	user, err := s.User(r.UserID)
	if err == nil && user != nil {
		userName = user.Username
	}

	confirmMsg := fmt.Sprintf("✅ Copied `%s` to `%s` (voted by %s)",
		filepath.Base(selectedPath), wallpapersFolder, userName)

	if _, err = s.ChannelMessageSend(r.ChannelID, confirmMsg); err != nil {
		log.Errorw("Failed to send confirmation message", zap.Error(err))
	}
}

// cleanupOldMessageTracking periodically removes old entries from the message tracking database.
func cleanupOldMessageTracking(ctx context.Context) {
	l := logging.FromContext(ctx)
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			l.Infow("Stopping message tracking cleanup")
			return
		case <-ticker.C:
			cutoffTime := time.Now().Add(-messageTrackingTTL)
			result := db.Where("created_at < ?", cutoffTime).Delete(&MessageTracking{})
			if result.Error != nil {
				l.Errorw("Failed to cleanup old message tracking entries", zap.Error(result.Error))
				continue
			}

			if result.RowsAffected > 0 {
				l.Infow("Cleaned up old message tracking entries",
					"removed_count", result.RowsAffected,
				)
			}
		}
	}
}

// pollDropbox continuously polls Dropbox for new files.
func pollDropbox(ctx context.Context, dg *discordgo.Session) {
	l := logging.FromContext(ctx)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	dbxClient := createDropboxClient()
	scanDropboxFolder(ctx, dbxClient, dg)

	for {
		select {
		case <-ctx.Done():
			l.Infow("Stopping Dropbox polling")
			return
		case <-ticker.C:
			dbxClient = createDropboxClient()
			scanDropboxFolder(ctx, dbxClient, dg)
		}
	}
}

// scanDropboxFolder lists the configured folder and persists new images.
func scanDropboxFolder(ctx context.Context, dbxClient files.Client, dg *discordgo.Session) {
	l := logging.FromContext(ctx)
	l.Debugw("Scanning Dropbox folder")

	listArg := files.NewListFolderArg(dropboxFolder)
	listArg.Recursive = true

	result, err := dbxClient.ListFolder(listArg)
	if err != nil {
		l.Errorw("Failed to list Dropbox folder", zap.Error(err))
		return
	}

	storeDiscoveredFiles(ctx, result.Entries)

	for result.HasMore {
		continueArg := files.NewListFolderContinueArg(result.Cursor)
		result, err = dbxClient.ListFolderContinue(continueArg)
		if err != nil {
			l.Errorw("Failed to continue listing Dropbox folder", zap.Error(err))
			return
		}
		storeDiscoveredFiles(ctx, result.Entries)
	}
}

// storeDiscoveredFiles stores discovered image files in the database.
func storeDiscoveredFiles(ctx context.Context, entries []files.IsMetadata) {
	l := logging.FromContext(ctx)
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

		// Upsert by path; delivered_at stays untouched so delivery state survives.
		// A content_hash collision means the same bytes already live at a different
		// path — that error is intentional dedup, handled below.
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
			if strings.Contains(result.Error.Error(), "UNIQUE constraint failed: processed_files.content_hash") {
				l.Debugw("Skipping file with duplicate content hash",
					"path", fileMetadata.PathDisplay,
				)
			} else {
				l.Errorw("Failed to store discovered file",
					"path", fileMetadata.PathDisplay,
					zap.Error(result.Error),
				)
			}
		}
	}
}

// deliverImagesPeriodically delivers images every 30 minutes.
func deliverImagesPeriodically(ctx context.Context, dg *discordgo.Session) {
	l := logging.FromContext(ctx)
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	dbxClient := createDropboxClient()
	sendRandomImages(ctx, dbxClient, dg)

	for {
		select {
		case <-ctx.Done():
			l.Infow("Stopping periodic image delivery")
			return
		case <-ticker.C:
			dbxClient = createDropboxClient()
			sendRandomImages(ctx, dbxClient, dg)
		}
	}
}

// sendRandomImages queries the database for N random undelivered images and sends them.
func sendRandomImages(ctx context.Context, dbxClient files.Client, dg *discordgo.Session) {
	l := logging.FromContext(ctx)
	const maxBatchSize = 10

	var undeliveredFiles []ImageFile
	err := db.Model(&ImageFile{}).
		Where("delivered_at IS NULL").
		Order("RANDOM()").
		Limit(maxBatchSize).
		Find(&undeliveredFiles).Error

	if err != nil {
		l.Errorw("Failed to query random undelivered images", zap.Error(err))
		return
	}

	if len(undeliveredFiles) == 0 {
		l.Debugw("No undelivered images found")
		return
	}

	l.Infow("Found random undelivered images to send",
		"count", len(undeliveredFiles),
	)

	var batch []*files.FileMetadata
	for _, img := range undeliveredFiles {
		metadata, err := dbxClient.GetMetadata(&files.GetMetadataArg{
			Path: img.Path,
		})
		if err != nil {
			l.Errorw("Failed to get file metadata from Dropbox, marking as delivered to skip",
				"path", img.Path,
				zap.Error(err),
			)
			now := time.Now()
			_ = markAsDelivered(img.Path, now)
			continue
		}

		fileMetadata, ok := metadata.(*files.FileMetadata)
		if !ok {
			l.Warnw("Metadata is not a file", "path", img.Path)
			continue
		}

		batch = append(batch, fileMetadata)
	}

	if len(batch) > 0 {
		processBatch(ctx, batch, dbxClient, dg)
	}
}

// processBatch processes a batch of files and uploads them in a single message.
func processBatch(ctx context.Context, batch []*files.FileMetadata, dbxClient files.Client, dg *discordgo.Session) {
	l := logging.FromContext(ctx)
	l.Infow("Processing batch of images",
		"batch_size", len(batch),
	)

	if err := downloadAndUploadBatch(ctx, dbxClient, dg, batch); err != nil {
		l.Errorw("Failed to process batch",
			"batch_size", len(batch),
			zap.Error(err),
		)
		return
	}

	now := time.Now()
	for _, fileMetadata := range batch {
		if err := markAsDelivered(fileMetadata.PathLower, now); err != nil {
			l.Errorw("Failed to mark file as delivered",
				"path", fileMetadata.PathDisplay,
				zap.Error(err),
			)
		}
	}
}

// isImageFile reports whether name has a recognized image extension.
func isImageFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	imageExtensions := []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
	return slices.Contains(imageExtensions, ext)
}

// markAsDelivered records the delivery time for a file by path.
func markAsDelivered(path string, deliveredAt time.Time) error {
	result := db.Model(&ImageFile{}).
		Where("path = ?", path).
		Updates(map[string]interface{}{
			"delivered_at": deliveredAt,
		})
	return result.Error
}

// storeMessageTracking persists per-file rows for a Discord message so reactions
// can be mapped back to the chosen file.
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

// getFilePathByMessageAndIndex returns the file path for a (messageID, index)
// pair, or "" if no match exists.
func getFilePathByMessageAndIndex(messageID string, index int) (string, error) {
	var tracking MessageTracking
	result := db.Where("message_id = ? AND file_index = ?", messageID, index).First(&tracking)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("failed to query message tracking: %w", result.Error)
	}
	return tracking.FilePath, nil
}

// downloadAndUploadBatch downloads multiple files from Dropbox and uploads them in a single Discord message.
func downloadAndUploadBatch(ctx context.Context, dbxClient files.Client, dg *discordgo.Session, batch []*files.FileMetadata) error {
	l := logging.FromContext(ctx)

	cacheDir := filepath.Join(dataDir, "cache")
	if err := os.MkdirAll(cacheDir, 0750); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Discord has a file size limit (8MB for free, 50MB for Nitro).
	maxSize := uint64(8 * 1024 * 1024)

	var discordFiles []*discordgo.File
	var cacheFiles []string
	var paths []string
	var fileNames []string

	defer func() {
		for _, cacheFile := range cacheFiles {
			if removeErr := os.Remove(cacheFile); removeErr != nil {
				l.Errorw("Error removing cache file", "file", cacheFile, zap.Error(removeErr))
			}
		}
	}()

	for _, metadata := range batch {
		if metadata.Size > maxSize {
			l.Warnw("Skipping file: exceeds Discord limit (8MB)",
				"path", metadata.PathDisplay,
				"size", metadata.Size,
			)
			continue
		}

		cacheFile := filepath.Join(cacheDir, filepath.Base(metadata.PathLower))

		downloadArg := files.NewDownloadArg(metadata.PathLower)
		_, content, err := dbxClient.Download(downloadArg)
		if err != nil {
			l.Errorw("Failed to download from Dropbox",
				"path", metadata.PathDisplay,
				zap.Error(err),
			)
			continue
		}

		// #nosec G304 -- cacheFile is safely constructed using filepath.Join with filepath.Base, preventing directory traversal
		outFile, err := os.Create(cacheFile)
		if err != nil {
			if closeErr := content.Close(); closeErr != nil {
				l.Errorw("Error closing Dropbox content stream", zap.Error(closeErr))
			}
			l.Errorw("Failed to create cache file",
				"path", metadata.PathDisplay,
				zap.Error(err),
			)
			continue
		}

		if _, err := io.Copy(outFile, content); err != nil {
			if closeErr := content.Close(); closeErr != nil {
				l.Errorw("Error closing Dropbox content stream", zap.Error(closeErr))
			}
			if closeErr := outFile.Close(); closeErr != nil {
				l.Errorw("Error closing cache file", zap.Error(closeErr))
			}
			l.Errorw("Failed to write to cache file",
				"path", metadata.PathDisplay,
				zap.Error(err),
			)
			continue
		}

		if closeErr := content.Close(); closeErr != nil {
			l.Errorw("Error closing Dropbox content stream", zap.Error(closeErr))
		}
		if closeErr := outFile.Close(); closeErr != nil {
			l.Errorw("Error closing cache file", zap.Error(closeErr))
		}

		// #nosec G304 -- cacheFile is safely constructed using filepath.Join with filepath.Base, preventing directory traversal
		cachedFile, err := os.Open(cacheFile)
		if err != nil {
			l.Errorw("Failed to open cached file",
				"path", metadata.PathDisplay,
				zap.Error(err),
			)
			continue
		}

		discordFiles = append(discordFiles, &discordgo.File{
			Name:   metadata.Name,
			Reader: cachedFile,
		})
		cacheFiles = append(cacheFiles, cacheFile)
		paths = append(paths, metadata.PathDisplay)
		fileNames = append(fileNames, metadata.Name)

		l.Infow("Downloaded image for batch upload",
			"path", metadata.PathDisplay,
			"name", metadata.Name,
			"size", metadata.Size,
		)
	}

	if len(discordFiles) == 0 {
		return fmt.Errorf("no files were successfully downloaded from batch")
	}

	defer func() {
		for _, df := range discordFiles {
			if closer, ok := df.Reader.(io.Closer); ok {
				if closeErr := closer.Close(); closeErr != nil {
					l.Errorw("Error closing file reader", zap.Error(closeErr))
				}
			}
		}
	}()

	// Use emoji numbers for voting (1️⃣ through 🔟).
	var messageLines []string
	for i, path := range paths {
		if i < len(numberEmojis) {
			messageLines = append(messageLines, fmt.Sprintf("%s %s", numberEmojis[i], path))
		} else {
			messageLines = append(messageLines, path)
		}
	}
	messageContent := strings.Join(messageLines, "\n")

	msg, err := dg.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
		Content: messageContent,
		Files:   discordFiles,
	})
	if err != nil {
		return fmt.Errorf("failed to send files to Discord: %w", err)
	}

	if err := storeMessageTracking(msg.ID, paths); err != nil {
		l.Errorw("Failed to store message tracking in database",
			"message_id", msg.ID,
			zap.Error(err),
		)
	}

	for i := 0; i < len(paths) && i < len(numberEmojis); i++ {
		if reactErr := dg.MessageReactionAdd(channelID, msg.ID, numberEmojis[i]); reactErr != nil {
			l.Errorw("Failed to add reaction",
				"emoji", numberEmojis[i],
				zap.Error(reactErr),
			)
		}
	}

	l.Infow("Successfully uploaded batch to Discord",
		"file_count", len(discordFiles),
		"files", fileNames,
		"message_id", msg.ID,
	)

	return nil
}

// formatBytes renders n as a human-readable size string.
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

// routeTag stamps the chi route pattern onto otelhttp metric labels.
func routeTag(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		labeler, ok := otelhttp.LabelerFromContext(r.Context())
		if !ok {
			return
		}
		if pattern := chi.RouteContext(r.Context()).RoutePattern(); pattern != "" {
			labeler.Add(semconv.HTTPRoute(pattern))
		}
	})
}

// homepageHandler displays the homepage with last image stats.
func homepageHandler(w http.ResponseWriter, r *http.Request) {
	l := logging.FromContext(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var lastDeliveredFile ImageFile
	var totalCount, deliveredCount, pendingCount int64
	var totalSize uint64
	var oldestFile, newestFile ImageFile

	err := db.Where("delivered_at IS NOT NULL").Order("delivered_at DESC").First(&lastDeliveredFile).Error
	hasLastDelivered := err == nil

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		l.Errorw("Error querying last delivered file", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = db.Model(&ImageFile{}).Count(&totalCount).Error
	if err != nil {
		l.Errorw("Error querying total count", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = db.Model(&ImageFile{}).Where("delivered_at IS NOT NULL").Count(&deliveredCount).Error
	if err != nil {
		l.Errorw("Error querying delivered count", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = db.Model(&ImageFile{}).Where("delivered_at IS NULL").Count(&pendingCount).Error
	if err != nil {
		l.Errorw("Error querying pending count", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = db.Model(&ImageFile{}).Select("COALESCE(SUM(size), 0)").Scan(&totalSize).Error
	if err != nil {
		l.Errorw("Error querying total size", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = db.Order("modified ASC").First(&oldestFile).Error
	hasOldest := err == nil
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		l.Errorw("Error querying oldest file", zap.Error(err))
	}

	err = db.Order("modified DESC").First(&newestFile).Error
	hasNewest := err == nil
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		l.Errorw("Error querying newest file", zap.Error(err))
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

	// Get filename from path and HTML-escape it to prevent stored XSS.
	// The path originates from Dropbox file metadata stored in the local DB;
	// a maliciously-named file (e.g. `<script>…</script>.jpg`) would otherwise
	// inject arbitrary HTML/JS into this page.
	var filename string
	if hasLastDelivered {
		filename = html.EscapeString(filepath.Base(lastDeliveredFile.Path))
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

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
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

	if _, err := w.Write([]byte(htmlContent)); err != nil {
		l.Errorw("Error writing homepage response", zap.Error(err))
	}
}

// healthCheckHandler returns a simple health check.
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	l := logging.FromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
		l.Errorw("Error writing health check response", zap.Error(err))
	}
}

// readyCheckHandler returns readiness status including Discord connection.
func readyCheckHandler(dg *discordgo.Session) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l := logging.FromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")

		if dg == nil || !dg.DataReady {
			w.WriteHeader(http.StatusServiceUnavailable)
			if _, err := w.Write([]byte(`{"status":"not_ready","discord":"disconnected"}`)); err != nil {
				l.Errorw("Error writing ready check response", zap.Error(err))
			}
			return
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"status":"ready","discord":"connected"}`)); err != nil {
			l.Errorw("Error writing ready check response", zap.Error(err))
		}
	}
}
