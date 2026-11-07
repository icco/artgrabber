package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

const (
	legacySQLiteFile = "artgrabber.db"
	importBatchSize  = 1000
)

// importSQLite copies rows from the legacy SQLite database at path into dst
// once, then renames the file so later starts skip it. The import is skipped
// when dst already has files, so a fresh scan is never overwritten.
func importSQLite(ctx context.Context, dst *gorm.DB, path string) error {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat legacy database: %w", err)
	}

	var existing int64
	if err := dst.WithContext(ctx).Model(&ImageFile{}).Count(&existing).Error; err != nil {
		return fmt.Errorf("count existing files: %w", err)
	}

	if existing == 0 {
		fileCount, trackingCount, err := copySQLite(ctx, dst, path)
		if err != nil {
			return err
		}
		log.Infow("Imported legacy SQLite database",
			"path", path,
			"files", fileCount,
			"message_tracking", trackingCount,
		)
	} else {
		log.Warnw("Postgres already has files, skipping legacy SQLite import", "path", path, "files", existing)
	}

	if err := os.Rename(path, path+".imported"); err != nil {
		return fmt.Errorf("rename legacy database: %w", err)
	}
	return nil
}

// copySQLite copies every row from the SQLite database at path into dst in a
// single transaction.
func copySQLite(ctx context.Context, dst *gorm.DB, path string) (int, int, error) {
	src, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return 0, 0, fmt.Errorf("open legacy database: %w", err)
	}
	srcDB, err := src.DB()
	if err != nil {
		return 0, 0, fmt.Errorf("get legacy database connection: %w", err)
	}
	defer func() { _ = srcDB.Close() }()

	var fileCount, trackingCount int
	err = dst.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var batch []ImageFile
		result := src.WithContext(ctx).FindInBatches(&batch, importBatchSize, func(_ *gorm.DB, _ int) error {
			fileCount += len(batch)
			return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&batch).Error
		})
		if result.Error != nil {
			return fmt.Errorf("copy files: %w", result.Error)
		}

		if !src.Migrator().HasTable(&MessageTracking{}) {
			return nil
		}
		var tracking []MessageTracking
		if err := src.WithContext(ctx).Find(&tracking).Error; err != nil {
			return fmt.Errorf("read message tracking: %w", err)
		}
		trackingCount = len(tracking)
		if trackingCount == 0 {
			return nil
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(&tracking, importBatchSize).Error; err != nil {
			return fmt.Errorf("copy message tracking: %w", err)
		}
		return nil
	})
	return fileCount, trackingCount, err
}
