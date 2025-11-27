.PHONY: build run clean test

# Build the bot
build:
	go build -o artgrabber main.go

# Run the bot directly
run:
	go run main.go

# Clean build artifacts
clean:
	rm -f artgrabber

# Run tests
test:
	go test -v ./...

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o artgrabber-linux-amd64 main.go
	GOOS=darwin GOARCH=amd64 go build -o artgrabber-darwin-amd64 main.go
	GOOS=darwin GOARCH=arm64 go build -o artgrabber-darwin-arm64 main.go
	GOOS=windows GOARCH=amd64 go build -o artgrabber-windows-amd64.exe main.go
