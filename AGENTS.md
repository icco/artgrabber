# AGENTS.md

Guidance for coding agents working on artgrabber.

## Project Overview

A bot written in Go (`github.com/icco/artgrabber`) for syncing art and wallpapers to Dropbox.

## Commands (Taskfile)

Run via `task <name>`:
- `task build` — Build `artgrabber` binary
- `task run` — Run bot directly
- `task test` — Run tests (`go test -v ./...`)
- `task lint` — Run `go fmt` and `go vet`
- `task oauth` — Run OAuth setup tool (`go run cmd/oauth-setup/main.go`)
- `task tidy` — Tidy Go modules

## Architecture & Layout

- `main.go` — Entrypoint and sync execution.
- `cmd/oauth-setup/` — CLI helper for Dropbox OAuth token acquisition.
- `lib/` — Dropbox client and image fetching logic.

## Conventions

- PR titles and commits must follow Conventional Commits with lowercase subjects.
- Ensure `task lint` and `task test` pass before submitting PRs.
- Never commit OAuth tokens or secrets.
