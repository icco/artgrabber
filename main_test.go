package main

import (
	"context"
	"testing"

	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/files"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestStoreDiscoveredFilesSkipsDuplicateContentHash(t *testing.T) {
	testDB, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := testDB.AutoMigrate(&ImageFile{}); err != nil {
		t.Fatal(err)
	}
	previousDB := db
	db = testDB
	t.Cleanup(func() { db = previousDB })

	entries := []files.IsMetadata{
		&files.FileMetadata{Metadata: files.Metadata{Name: "one.jpg", PathLower: "/one.jpg", PathDisplay: "/one.jpg"}, ContentHash: "same", Size: 1},
		&files.FileMetadata{Metadata: files.Metadata{Name: "two.jpg", PathLower: "/two.jpg", PathDisplay: "/two.jpg"}, ContentHash: "same", Size: 1},
	}
	storeDiscoveredFiles(context.Background(), entries)

	var count int64
	if err := db.Model(&ImageFile{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("stored files = %d, want 1", count)
	}
}

func TestRandomUndeliveredImagesSkipsOversizedFiles(t *testing.T) {
	testDB, err := gorm.Open(sqlite.Open("file:oversized?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := testDB.AutoMigrate(&ImageFile{}); err != nil {
		t.Fatal(err)
	}
	previousDB := db
	db = testDB
	t.Cleanup(func() { db = previousDB })

	for _, f := range []ImageFile{
		{Path: "/alice.jpg", Size: discordMaxFileSize},
		{Path: "/bob.png", Size: discordMaxFileSize + 1},
	} {
		if err := db.Create(&f).Error; err != nil {
			t.Fatal(err)
		}
	}

	got, err := randomUndeliveredImages(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != "/alice.jpg" {
		t.Fatalf("randomUndeliveredImages = %+v, want only /alice.jpg", got)
	}
}
