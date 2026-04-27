# Build stage
FROM golang:1.26-alpine AS builder

# Install build dependencies (including C dependencies for sqlite3)
RUN apk add --no-cache git ca-certificates gcc musl-dev sqlite-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY main.go ./
COPY db ./db

# Build the application with CGO enabled
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o artgrabber .

# Runtime stage
FROM alpine:3.23

LABEL org.opencontainers.image.source=https://github.com/icco/artgrabber
LABEL org.opencontainers.image.description="ghcr.io/icco/artgrabber container image"
LABEL org.opencontainers.image.licenses=MIT

# Install ca-certificates for HTTPS and sqlite runtime library.
# Build tools (gcc, git, etc.) are NOT needed at runtime.
RUN apk --no-cache add ca-certificates sqlite-libs

WORKDIR /app

# Create a non-root group and user, then set up the /data directory.
# adduser -S on Alpine does NOT create a matching group automatically;
# the group must be created explicitly before chown app:app will work.
RUN addgroup -S -g 1000 app && \
    adduser -S -u 1000 -G app app && \
    mkdir -p /data && \
    chown app:app /data

# Copy the binary from builder
COPY --from=builder /app/artgrabber .

# Run as non-root
USER app

# Expose the HTTP server port
EXPOSE 8080

# Define volume for persistent database storage
VOLUME ["/data"]

# Run the bot
CMD ["./artgrabber"]
