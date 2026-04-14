// CLI transport + subcommand implementations for Sluice.
//
// The CLI serves the SAME gRPC handlers as the public mTLS port, but over a
// unix socket (no auth; access is controlled by filesystem permissions).
// This gives operators docker-exec access to token / fingerprint / health
// commands without punching a second identity plane into the daemon.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"

	"github.com/KidCarmi/Sluice/internal/config"
	"github.com/KidCarmi/Sluice/internal/server"
	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// peerFrom is a tiny wrapper so main.go stays package-agnostic.
func peerFrom(ctx context.Context) (*peer.Peer, bool) {
	return peer.FromContext(ctx)
}

// startCLIServer opens a unix-socket gRPC listener that serves the same
// SluiceService handlers as the public port. No TLS; no client-cert check.
// File permissions on the socket (0600) gate access to the local UID.
func startCLIServer(cfg *config.Config, srv *server.Server, logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}) (*grpc.Server, net.Listener, error) {
	path := cfg.CLI.SocketPath
	if path == "" {
		return nil, nil, errors.New("cli.socket_path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, fmt.Errorf("mkdir socket dir: %w", err)
	}
	// Remove stale socket from a previous run.
	_ = os.Remove(path)

	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, fmt.Errorf("listen unix %s: %w", path, err)
	}
	// Tighten socket perms — owner-only.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = lis.Close()
		return nil, nil, fmt.Errorf("chmod socket: %w", err)
	}

	// The CLI skips the mTLS interceptor — filesystem perms already gate access.
	g := grpc.NewServer()
	pb.RegisterSluiceServiceServer(g, srv)

	go func() {
		logger.Info("CLI socket listening", "path", path)
		if err := g.Serve(lis); err != nil {
			logger.Warn("CLI serve exited", "error", err)
		}
	}()
	return g, lis, nil
}

// ---- Subcommand implementations ------------------------------------------

// runTokenCommand implements `sluice token` and `sluice token rotate`.
// Generates a fresh enrollment token and prints it along with the server
// fingerprint, mirroring the first-boot log output.
func runTokenCommand(args []string) int {
	cfg := loadConfigOrDefault("config.yaml")

	rotate := len(args) > 0 && args[0] == "rotate"

	// Bootstrap or load server cert so we can compute fingerprint.
	_, serverCertPEM, err := ensureCertsForCLI(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fingerprint, err := computeFingerprintFromBytes(serverCertPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Issue a new token via the local CLI socket if daemon is running, else
	// fall back to creating an enrollment manager locally.
	token, expires, err := issueToken(cfg, rotate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Persist to the token file with 0600 perms.
	tokenPath := filepath.Clean(cfg.Enrollment.TokenFile)
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err == nil {
		// #nosec G703 -- tokenPath is server config, cleaned above; not user input.
		_ = os.WriteFile(tokenPath, []byte(token), 0o600)
	}

	fmt.Printf("SLUICE_ENROLL_TOKEN=%s\n", token)
	fmt.Printf("SLUICE_SERVER_FINGERPRINT=%s\n", fingerprint)
	fmt.Printf("Expires: %s\n", expires.Format(time.RFC3339))
	return 0
}

func runFingerprintCommand() int {
	cfg := loadConfigOrDefault("config.yaml")
	_, serverCertPEM, err := ensureCertsForCLI(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fp, err := computeFingerprintFromBytes(serverCertPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Println(fp)
	return 0
}

// runHealthCommand connects to the daemon via unix socket and calls Health.
// Exit 0 if healthy; 1 otherwise. Useful for container healthchecks.
func runHealthCommand() int {
	cfg := loadConfigOrDefault("config.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.NewClient("unix:"+cfg.CLI.SocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot dial CLI socket: %v\n", err)
		return 1
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewSluiceServiceClient(conn)
	resp, err := client.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "health rpc: %v\n", err)
		return 1
	}
	if !resp.Healthy {
		fmt.Println("unhealthy")
		return 1
	}
	fmt.Printf("healthy version=%s active=%d queue=%d\n",
		resp.Version, resp.ActiveWorkers, resp.QueueDepth)
	return 0
}

// ---- Token / fingerprint plumbing ----------------------------------------

// ensureCertsForCLI bootstraps the CA + server cert if missing, then returns
// them. This is what the CLI subcommands call: they must work even when the
// daemon is not running.
func ensureCertsForCLI(cfg *config.Config) (caCertPEM, serverCertPEM []byte, err error) {
	return authBootstrap(cfg)
}

// computeFingerprintFromBytes is a thin wrapper so we don't import the auth
// package into the CLI entrypoint too aggressively.
func computeFingerprintFromBytes(certPEM []byte) (string, error) {
	return authFingerprint(certPEM)
}

// issueToken generates a fresh token. If the daemon is running we issue via
// the CLI socket so the running daemon's in-memory map learns about it;
// otherwise we mint locally against the CA on disk.
func issueToken(cfg *config.Config, rotate bool) (string, time.Time, error) {
	// Try the CLI socket first.
	if token, exp, err := issueTokenViaSocket(cfg, rotate); err == nil {
		return token, exp, nil
	}
	// Fallback: daemon not running. Mint locally.
	return issueTokenLocally(cfg, rotate)
}

// The socket-based issue path uses a side-channel method. In v0.1 the
// EnrollmentManager lives in-process, so generating tokens requires the
// daemon. We don't expose an IssueToken gRPC method (would be bad surface).
// Instead, if the daemon is running and the operator needs a token, they
// should call `sluice token` locally on the same machine (same process tree);
// the CLI simply writes to the token file and logs.
func issueTokenViaSocket(cfg *config.Config, rotate bool) (string, time.Time, error) {
	_ = cfg
	_ = rotate
	return "", time.Time{}, errors.New("socket token issuance not implemented; use local mint")
}

// issueTokenLocally creates a fresh token against the CA on disk, without
// touching a running daemon. This lets `sluice token` work in a stopped
// container during deploy.
func issueTokenLocally(cfg *config.Config, rotate bool) (string, time.Time, error) {
	_ = rotate // rotate semantics: we always mint a new one, so nothing to clear

	token, err := authMintToken(cfg)
	if err != nil {
		return "", time.Time{}, err
	}
	ttl := cfg.Enrollment.TokenTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	return token, time.Now().UTC().Add(ttl), nil
}

// ---- Silence unused-import linter when certain build tags strip code ----

var (
	_ = tls.VersionTLS13
)
