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

# Build the application with CGO enabled
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o artgrabber .

# Runtime stage
FROM alpine:3.21

# Install ca-certificates for HTTPS and sqlite runtime library.
# Build tools (gcc, git, etc.) are NOT needed at runtime.
RUN apk --no-cache add ca-certificates sqlite-libs

WORKDIR /app

# Create a non-root user and set up the /data directory with correct ownership.
RUN adduser -S -u 1001 app && \
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
