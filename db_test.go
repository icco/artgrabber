package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testDSN matches the Postgres service in .github/workflows/test.yml.
const testDSN = "postgres://postgres:postgres@localhost:5432/artgrabber_test?sslmode=disable" //nolint:gosec // test-only credential

// setupTestDB points db at a fresh Postgres schema that is dropped on cleanup.
func setupTestDB(t *testing.T) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = testDSN
	}
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("connect to test Postgres: %v", err)
	}
	adminDB, err := admin.DB()
	if err != nil {
		t.Fatal(err)
	}

	schema := schemaName(t.Name())
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("create schema %s: %v", schema, err)
	}

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	testDB, err := initDB(u.String())
	if err != nil {
		t.Fatal(err)
	}
	previousDB := db
	db = testDB
	t.Cleanup(func() {
		db = previousDB
		if sqlDB, err := testDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
		if err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error; err != nil {
			t.Errorf("drop schema %s: %v", schema, err)
		}
		_ = adminDB.Close()
	})
}

// schemaName turns a test name into a unique, valid Postgres identifier.
func schemaName(testName string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '_'
		}
	}, testName)
	if len(safe) > 40 {
		safe = safe[:40]
	}
	return fmt.Sprintf("t_%s_%d", safe, time.Now().UnixNano())
}
