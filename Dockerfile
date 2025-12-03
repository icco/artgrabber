# Build stage
FROM golang:1.25-alpine AS builder

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
FROM alpine:latest

# Install ca-certificates for HTTPS and sqlite runtime libraries
RUN apk --no-cache add ca-certificates sqlite-libs

WORKDIR /root/

# Create /data directory for SQLite database
RUN mkdir -p /data && chmod 755 /data

# Copy the binary from builder
COPY --from=builder /app/artgrabber .

# Expose the HTTP server port
EXPOSE 8080

# Define volume for persistent database storage
VOLUME ["/data"]

# Run the bot
CMD ["./artgrabber"]
