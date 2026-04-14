# Sluice

CDR (Content Disarm & Reconstruction) engine for the Culvert forward proxy.
Single Go binary, gRPC + mTLS, Docker-native.

## Build & Test

go build -o sluice ./cmd/sluice
go test -race -count=1 ./...
go test -coverprofile=coverage.out ./... (threshold: 60%)

## Code Conventions

- Package layout: cmd/ for entrypoint, internal/ for everything else
- Go version: 1.25 (match Culvert)
- Logging: structured JSON via slog (Go 1.21+ stdlib)
- Errors: return fmt.Errorf("context: %w", err)
- Concurrency: bounded worker pool, context.Context on every operation
- File I/O: always io.LimitReader, always filepath.Clean + containment
- No unsafe, no os/exec, no CGO
- Tests: _test.go in same package (whitebox)
