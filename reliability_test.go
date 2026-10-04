package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox"
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/files"
	"golang.org/x/oauth2"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

type rotatingTokenSource struct{ calls int }

type failingTokenSource struct{}

func (failingTokenSource) Token() (*oauth2.Token, error) {
	return nil, errors.New("temporary token refresh failure")
}

func (s *rotatingTokenSource) Token() (*oauth2.Token, error) {
	s.calls++
	// Force expiry between pages without a real four-hour scan or a sleep.
	return &oauth2.Token{AccessToken: fmt.Sprintf("token-%d", s.calls), Expiry: time.Now().Add(-time.Hour)}, nil
}

func TestDropboxClientRefreshesTokenBetweenPages(t *testing.T) {
	oldSource, oldTransport := dropboxTokenSource, http.DefaultTransport
	t.Cleanup(func() { dropboxTokenSource, http.DefaultTransport = oldSource, oldTransport })
	source := &rotatingTokenSource{}
	dropboxTokenSource = source
	requests := 0
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if got, want := r.Header.Get("Authorization"), fmt.Sprintf("Bearer token-%d", requests); got != want {
			t.Errorf("authorization = %q, want %q", got, want)
		}
		return jsonResponse(`{"entries":[],"cursor":"next","has_more":false}`), nil
	})
	client := createDropboxClient()
	if _, err := client.ListFolder(files.NewListFolderArg("/images")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListFolderContinue(files.NewListFolderContinueArg("next")); err != nil {
		t.Fatal(err)
	}
	if source.calls != 2 {
		t.Fatalf("token source calls = %d, want 2", source.calls)
	}
}

func TestDropboxRefreshFailureIsReturned(t *testing.T) {
	oldSource := dropboxTokenSource
	t.Cleanup(func() { dropboxTokenSource = oldSource })
	dropboxTokenSource = failingTokenSource{}
	client := createDropboxClient()
	if _, err := client.ListFolder(files.NewListFolderArg("/images")); err == nil {
		t.Fatal("expected refresh error, without exiting the process")
	}
}

func setupReliabilityDB(t *testing.T) {
	t.Helper()
	oldDB, oldDir := db, dataDir
	dataDir = t.TempDir()
	var err error
	db, err = initDB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close(); db, dataDir = oldDB, oldDir })
}

func TestDatabaseSerializesConcurrentWriters(t *testing.T) {
	setupReliabilityDB(t)
	var mode string
	if err := db.Raw("PRAGMA journal_mode").Scan(&mode).Error; err != nil || mode != "wal" {
		t.Fatalf("journal mode = %q, error = %v", mode, err)
	}
	sqlDB, _ := db.DB()
	if sqlDB.Stats().MaxOpenConnections != 1 {
		t.Fatal("SQLite writers are not serialized")
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			if err := storeMessageTracking(fmt.Sprint(i), []string{"/one.jpg", "/two.jpg"}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	var count int64
	if err := db.Model(&MessageTracking{}).Count(&count).Error; err != nil || count != 40 {
		t.Fatalf("tracking rows = %d, error = %v", count, err)
	}
}

type reliabilityDropbox struct {
	files.Client
	metadataError error
}

func (c reliabilityDropbox) GetMetadata(*files.GetMetadataArg) (files.IsMetadata, error) {
	return nil, c.metadataError
}

func (c reliabilityDropbox) Download(arg *files.DownloadArg) (*files.FileMetadata, io.ReadCloser, error) {
	if arg.Path == "/failed/image.jpg" {
		return nil, nil, io.ErrUnexpectedEOF
	}
	if arg.Path == "/partial/image.jpg" {
		return nil, &partialReader{}, nil
	}
	return nil, io.NopCloser(strings.NewReader(arg.Path)), nil
}

type partialReader struct{}

func (*partialReader) Read(p []byte) (int, error) { return copy(p, "partial"), io.ErrUnexpectedEOF }
func (*partialReader) Close() error               { return nil }

func TestMetadataFailureRemainsPending(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		skipped bool
	}{
		{"transient", errors.New("expired_access_token/"), false},
		{"deleted", files.GetMetadataAPIError{EndpointError: &files.GetMetadataError{
			Tagged: dropbox.Tagged{Tag: files.GetMetadataErrorPath},
			Path:   &files.LookupError{Tagged: dropbox.Tagged{Tag: files.LookupErrorNotFound}},
		}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupReliabilityDB(t)
			if err := db.Create(&ImageFile{Path: "/one.jpg"}).Error; err != nil {
				t.Fatal(err)
			}
			sendRandomImages(context.Background(), reliabilityDropbox{metadataError: tc.err}, nil)
			var image ImageFile
			if err := db.First(&image).Error; err != nil {
				t.Fatal(err)
			}
			if got := image.DeliveredAt != nil; got != tc.skipped {
				t.Fatalf("skipped = %v, want %v", got, tc.skipped)
			}
		})
	}
}

func TestPartialBatchOnlyMarksUploadedFilesDelivered(t *testing.T) {
	setupReliabilityDB(t)
	paths := []string{"/one/image.jpg", "/two/image.jpg", "/failed/image.jpg", "/partial/image.jpg"}
	var batch []*files.FileMetadata
	for _, path := range paths {
		if err := db.Create(&ImageFile{Path: path}).Error; err != nil {
			t.Fatal(err)
		}
		batch = append(batch, &files.FileMetadata{Metadata: files.Metadata{Name: "image.jpg", PathLower: path, PathDisplay: path}})
	}
	session, err := discordgo.New("Bot test")
	if err != nil {
		t.Fatal(err)
	}
	session.Client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			reader, err := r.MultipartReader()
			if err != nil {
				t.Fatal(err)
			}
			var uploaded []string
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				content, err := io.ReadAll(part)
				if err != nil {
					t.Fatal(err)
				}
				if part.FileName() != "" {
					uploaded = append(uploaded, string(content))
				}
			}
			if strings.Join(uploaded, ",") != strings.Join(paths[:2], ",") {
				t.Fatalf("uploaded content = %v, want %v", uploaded, paths[:2])
			}
		}
		return jsonResponse(`{"id":"message"}`), nil
	})}
	processBatch(context.Background(), batch, reliabilityDropbox{}, session)
	for i, path := range paths {
		var image ImageFile
		if err := db.First(&image, "path = ?", path).Error; err != nil {
			t.Fatal(err)
		}
		if got, want := image.DeliveredAt != nil, i < 2; got != want {
			t.Errorf("%s delivered = %v, want %v", path, got, want)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dataDir, "cache"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("cache entries = %v, error = %v", entries, err)
	}
}

func TestDiscordUploadFailureLeavesFilesPending(t *testing.T) {
	setupReliabilityDB(t)
	path := "/one/image.jpg"
	if err := db.Create(&ImageFile{Path: path}).Error; err != nil {
		t.Fatal(err)
	}
	session, err := discordgo.New("Bot test")
	if err != nil {
		t.Fatal(err)
	}
	session.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("Discord unavailable")
	})}
	batch := []*files.FileMetadata{{Metadata: files.Metadata{Name: "image.jpg", PathLower: path, PathDisplay: path}}}
	processBatch(context.Background(), batch, reliabilityDropbox{}, session)
	var image ImageFile
	if err := db.First(&image).Error; err != nil {
		t.Fatal(err)
	}
	if image.DeliveredAt != nil {
		t.Fatal("failed upload was marked delivered")
	}
	entries, err := os.ReadDir(filepath.Join(dataDir, "cache"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("cache entries = %v, error = %v", entries, err)
	}
}
