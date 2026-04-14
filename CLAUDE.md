# Sluice

CDR (Content Disarm & Reconstruction) engine for the Culvert forward proxy.
Single Go binary, gRPC + mTLS, Docker-native.

## Architecture invariants (do not violate)

- **No public HTTP endpoints.** The testing UI is localhost + HTTPS +
  bearer-auth + off-by-default. All admin ops go through CLI (`docker exec`)
  or mTLS gRPC.
- **No admin GUI in Sluice.** All identity / policy / RBAC lives in Culvert.
  A second identity plane = split brain forever.
- **No user accounts, no role-based access control.** Culvert owns identity.
- **Stateless CDR engine.** Every gRPC call is self-contained. No caching.
- **Profile = name in, flags mapped internally.** Sluice never learns who
  the user is. Mode (ENFORCE / REPORT_ONLY / BYPASS_WITH_REPORT) is
  server-enforced — REPORT_ONLY MUST return original bytes even if the
  profile would modify them.

## Build & Test

```
make tools         # install protoc + protoc-gen-go + protoc-gen-go-grpc
make proto         # regenerate proto/sluicev1/*.pb.go
make build
make test
make bench
```

- `go test -race -count=1 ./...`
- `go test -coverprofile=coverage.out ./...` (threshold: 60%)

## Code Conventions

- Package layout: `cmd/` for entrypoint, `internal/` for everything else,
  generated protos at `proto/sluicev1/`.
- Go version: 1.25 (match Culvert Control Plane).
- Logging: structured JSON via `slog` (Go 1.21+ stdlib).
- Errors: return `fmt.Errorf("context: %w", err)`.
- Concurrency: bounded worker pool, `context.Context` on every operation.
- File I/O: always `io.LimitReader`, always `filepath.Clean` + containment.
- No `unsafe`, no `os/exec`, no CGO.
- Tests: `_test.go` in same package (whitebox).

## gRPC contract

Source of truth: `proto/sluicev1/sluice.proto`. Generated stubs are committed
to git; CI runs `make proto` and fails on drift.

Contract invariants:
- `SanitizeResponse.Result` is ALWAYS first message; chunks follow.
  Never interleaved. Culvert's client reads first message, branches on
  `Status`, then drains.
- Oversize files → `InvalidArgument` + `file_too_large:` prefix.
  (Never `ResourceExhausted` — that means server overload to the client.)
- Unknown `profile_name` → `Status=ERROR` with
  `error_message="unknown_profile: <name>"`. Never silently fall back.
- Empty `profile_name` ≡ `"default"`.
- `Threat.severity` ∈ `{low, medium, high, critical}` (Culvert alerts branch on this).
- `policy_version` → log only, never a Prometheus label.
- `tags` → whitelisted keys only as Prom labels
  (`direction`, `dest_category`); others log-only. Cap: 16 keys / 64 B key / 256 B value.
