package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func writeLegacySQLite(t *testing.T, path string, files []ImageFile, tracking []MessageTracking) {
	t.Helper()
	src, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := src.AutoMigrate(&ImageFile{}, &MessageTracking{}); err != nil {
		t.Fatal(err)
	}
	if len(files) > 0 {
		if err := src.Create(&files).Error; err != nil {
			t.Fatal(err)
		}
	}
	if len(tracking) > 0 {
		if err := src.Create(&tracking).Error; err != nil {
			t.Fatal(err)
		}
	}
	sqlDB, err := src.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestImportSQLiteCopiesRowsOnce(t *testing.T) {
	setupTestDB(t)
	path := filepath.Join(t.TempDir(), legacySQLiteFile)
	delivered := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	hash := "alice-hash"
	writeLegacySQLite(t, path,
		[]ImageFile{
			{Path: "/alice.jpg", ContentHash: &hash, Size: 10, Modified: delivered, ProcessedAt: delivered, DeliveredAt: &delivered},
			{Path: "/bob.png", Size: 20, Modified: delivered, ProcessedAt: delivered},
		},
		[]MessageTracking{{MessageID: "1", FilePath: "/alice.jpg", FileIndex: 0, CreatedAt: delivered}},
	)

	if err := importSQLite(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}

	var alice ImageFile
	if err := db.Where("path = ?", "/alice.jpg").First(&alice).Error; err != nil {
		t.Fatal(err)
	}
	if alice.DeliveredAt == nil || !alice.DeliveredAt.Equal(delivered) {
		t.Fatalf("alice delivered_at = %v, want %v", alice.DeliveredAt, delivered)
	}
	var fileCount, trackingCount int64
	if err := db.Model(&ImageFile{}).Count(&fileCount).Error; err != nil || fileCount != 2 {
		t.Fatalf("files = %d, error = %v", fileCount, err)
	}
	if err := db.Model(&MessageTracking{}).Count(&trackingCount).Error; err != nil || trackingCount != 1 {
		t.Fatalf("message tracking = %d, error = %v", trackingCount, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("legacy database still at %s: %v", path, err)
	}
	if _, err := os.Stat(path + ".imported"); err != nil {
		t.Fatal(err)
	}

	if err := importSQLite(context.Background(), db, path); err != nil {
		t.Fatalf("second import: %v", err)
	}
}

func TestImportSQLiteSkipsWhenPostgresHasFiles(t *testing.T) {
	setupTestDB(t)
	if err := db.Create(&ImageFile{Path: "/carol.jpg", Size: 1}).Error; err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), legacySQLiteFile)
	writeLegacySQLite(t, path, []ImageFile{{Path: "/dave.jpg", Size: 1}}, nil)

	if err := importSQLite(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}

	var count int64
	if err := db.Model(&ImageFile{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("files = %d, error = %v", count, err)
	}
	if _, err := os.Stat(path + ".imported"); err != nil {
		t.Fatal(err)
	}
}
