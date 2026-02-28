package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox"
	"golang.org/x/oauth2"
)

const (
	callbackPort = "8888"
	callbackPath = "/oauth/callback"
)

func main() {
	fmt.Println("=== Dropbox OAuth Setup ===")
	fmt.Println()

	// Get app credentials from environment
	appKey := os.Getenv("DROPBOX_APP_KEY")
	appSecret := os.Getenv("DROPBOX_APP_SECRET")

	if appKey == "" || appSecret == "" {
		fmt.Println("Error: DROPBOX_APP_KEY and DROPBOX_APP_SECRET environment variables are required")
		fmt.Println()
		fmt.Println("To get these credentials:")
		fmt.Println("1. Go to https://www.dropbox.com/developers/apps")
		fmt.Println("2. Create an app (or use an existing one)")
		fmt.Println("3. Get your App Key and App Secret from the app settings")
		fmt.Println("4. Add http://localhost:8888/oauth/callback to your app's Redirect URIs")
		fmt.Println()
		fmt.Println("Then run:")
		fmt.Printf("  export DROPBOX_APP_KEY=your_app_key\n")
		fmt.Printf("  export DROPBOX_APP_SECRET=your_app_secret\n")
		fmt.Printf("  go run cmd/oauth-setup/main.go\n")
		os.Exit(1)
	}

	// Create OAuth2 config
	config := &oauth2.Config{
		ClientID:     appKey,
		ClientSecret: appSecret,
		Endpoint:     dropbox.OAuthEndpoint(""),
		RedirectURL:  fmt.Sprintf("http://localhost:%s%s", callbackPort, callbackPath),
		Scopes:       []string{"files.metadata.read", "files.content.read", "files.content.write"},
	}

	// Generate random state for CSRF protection
	state := generateState()

	// Channel to receive the authorization code
	codeChan := make(chan string, 1)
	errorChan := make(chan error, 1)

	// Start local web server to handle callback
	server := &http.Server{
		Addr:              ":" + callbackPort,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	http.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		// Verify state parameter
		if r.URL.Query().Get("state") != state {
			errorChan <- fmt.Errorf("invalid state parameter")
			if _, err := fmt.Fprintf(w, "Error: Invalid state parameter"); err != nil {
				fmt.Printf("Failed to write error response: %v\n", err)
			}
			return
		}

		// Get authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			errorMsg := r.URL.Query().Get("error")
			if errorMsg == "" {
				errorMsg = "unknown error"
			}
			errorChan <- fmt.Errorf("authorization failed: %s", errorMsg)
			if _, err := io.WriteString(w, "Error: Authorization failed - "+html.EscapeString(errorMsg)); err != nil {
				fmt.Printf("Failed to write error response: %v\n", err)
			}
			return
		}

		// Send code through channel
		codeChan <- code

		// Show success page
		if _, err := fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>OAuth Success</title></head>
<body>
<h1>✅ Authorization Successful!</h1>
<p>You can close this window and return to your terminal.</p>
</body>
</html>`); err != nil {
			fmt.Printf("Failed to write success response: %v\n", err)
		}
	})

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errorChan <- fmt.Errorf("server error: %w", err)
		}
	}()

	// Generate authorization URL with offline access (for refresh token)
	// Dropbox requires token_access_type=offline to get a refresh token
	authURL := config.AuthCodeURL(state, oauth2.SetAuthURLParam("token_access_type", "offline"))

	fmt.Println("Please visit this URL to authorize the application:")
	fmt.Println()
	fmt.Println(authURL)
	fmt.Println()
	fmt.Println("Waiting for authorization...")

	// Wait for callback or error
	var code string
	select {
	case code = <-codeChan:
		// Success
	case err := <-errorChan:
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	case <-time.After(5 * time.Minute):
		fmt.Println("Error: Timeout waiting for authorization")
		os.Exit(1)
	}

	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		fmt.Printf("Warning: Server shutdown error: %v\n", err)
	}

	// Exchange authorization code for tokens
	fmt.Println("Exchanging authorization code for tokens...")
	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		fmt.Printf("Error exchanging code for token: %v\n", err)
		os.Exit(1)
	}

	// Display the refresh token
	fmt.Println()
	fmt.Println("✅ Success! Here's your refresh token:")
	fmt.Println()
	fmt.Printf("  %s\n", token.RefreshToken)
	fmt.Println()
	fmt.Println("Add this to your environment variables:")
	fmt.Println()
	fmt.Printf("  export DROPBOX_REFRESH_TOKEN=%s\n", token.RefreshToken)
	fmt.Printf("  export DROPBOX_APP_KEY=%s\n", appKey)
	fmt.Printf("  export DROPBOX_APP_SECRET=%s\n", appSecret)
	fmt.Println()
	fmt.Println("You can now remove DROPBOX_ACCESS_TOKEN from your environment.")
	fmt.Println("The bot will automatically refresh access tokens as needed.")
}

// generateState generates a random state string for CSRF protection
func generateState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}
