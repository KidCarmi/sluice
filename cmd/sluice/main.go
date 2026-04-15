// Sluice CDR Engine — entrypoint.
//
// Modes (selected via first positional argument):
//
//	sluice                     (daemon) run the gRPC server + optional testing UI
//	sluice --health            one-shot liveness probe (prints "healthy" and exits)
//	sluice token [rotate]      print current token + server fingerprint
//	sluice fingerprint         print server cert SHA-256 fingerprint
//	sluice health              local health check via CLI unix socket
//	sluice version             print version + build info
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/KidCarmi/Sluice/internal/auth"
	"github.com/KidCarmi/Sluice/internal/config"
	"github.com/KidCarmi/Sluice/internal/sanitizer"
	"github.com/KidCarmi/Sluice/internal/server"
	"github.com/KidCarmi/Sluice/internal/web"
	"github.com/KidCarmi/Sluice/internal/worker"
	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// version is the default value used for local dev builds. Release images
// override this via `-ldflags="-X main.version=..."` in the publish workflow.
var version = "0.2.0"

func main() {
	// Subcommand dispatch happens before flag parsing so we can take
	// positional arguments like `sluice token rotate`.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "token":
			os.Exit(runTokenCommand(os.Args[2:]))
		case "fingerprint":
			os.Exit(runFingerprintCommand())
		case "health":
			os.Exit(runHealthCommand())
		case "version":
			fmt.Printf("sluice %s\n", version)
			os.Exit(0)
		case "node":
			os.Exit(runNodeCommand(os.Args[2:]))
		case "cert":
			os.Exit(runCertCommand(os.Args[2:]))
		}
	}

	configPath := flag.String("config", "config.yaml", "path to config file")
	healthCheck := flag.Bool("health", false, "run health check and exit")
	flag.Parse()

	if *healthCheck {
		fmt.Println("healthy")
		os.Exit(0)
	}

	cfg := loadConfigOrDefault(*configPath)
	logger := newLogger(cfg)
	slog.SetDefault(logger)

	logger.Info("starting sluice",
		"version", version,
		"grpc_addr", cfg.Server.GRPCAddr,
		"testing_ui", cfg.TestingUI.Enabled,
	)

	// Sanitizer dispatcher + worker pool
	dispatcher := buildDispatcher(logger)
	if err := selfTest(dispatcher, logger); err != nil {
		logger.Error("startup self-test failed", "error", err)
		os.Exit(1)
	}
	logger.Info("startup self-test passed")

	pool := worker.NewPool(worker.PoolConfig{
		MaxWorkers: cfg.Workers.MaxConcurrent,
		QueueDepth: cfg.Workers.QueueDepth,
		JobTimeout: cfg.Workers.Timeout,
	}, func(ctx context.Context, job worker.Job) (interface{}, error) {
		return dispatcher.Dispatch(ctx, job.Data, job.Filename)
	})

	// Ensure /data dir exists so token / socket writes don't fail.
	ensureDataDir(cfg, logger)

	// Bootstrap server cert + CA (idempotent).
	caCertPEM, serverCertPEM, err := auth.BootstrapServerCerts(
		cfg.Server.TLS.CertFile,
		cfg.Server.TLS.KeyFile,
		cfg.Server.TLS.CAFile,
		tlsHosts(cfg),
	)
	if err != nil {
		logger.Error("bootstrapping server certs", "error", err)
		os.Exit(1)
	}
	caKeyPEM, err := auth.LoadCAKey(cfg.Server.TLS.CAFile)
	if err != nil {
		logger.Error("loading CA key", "error", err)
		os.Exit(1)
	}
	fingerprint, err := auth.CertFingerprintSHA256(serverCertPEM)
	if err != nil {
		logger.Error("computing server cert fingerprint", "error", err)
		os.Exit(1)
	}

	// Enrollment manager with SHA-256 + TTL.
	enroller, err := auth.NewEnrollmentManager(caCertPEM, caKeyPEM, logger)
	if err != nil {
		logger.Error("creating enrollment manager", "error", err)
		os.Exit(1)
	}
	if ttl := cfg.Enrollment.TokenTTL; ttl > 0 {
		enroller.SetTTL(ttl)
	}

	// First-boot enrollment token (only if token file is missing).
	if cfg.Enrollment.Enabled {
		ensureFirstBootToken(enroller, cfg, fingerprint, logger)
	}

	// Web handler (for the testing UI — guarded by cfg.TestingUI.Enabled)
	webHandler := web.NewHandler(dispatcher, pool, logger, cfg.Limits.MaxFileSize)

	// Build gRPC server with mTLS + interceptors.
	tlsCfg, err := auth.LoadTLSConfigOptionalClient(
		cfg.Server.TLS.CertFile,
		cfg.Server.TLS.KeyFile,
		cfg.Server.TLS.CAFile,
	)
	if err != nil {
		logger.Error("loading TLS config", "error", err)
		os.Exit(1)
	}

	// Client cert ledger — persists issued certs for revocation. Enrollment
	// manager writes records; interceptor reads them.
	ledgerPath := filepath.Join(filepath.Dir(cfg.Enrollment.TokenFile), "clients.json")
	clientLedger, err := auth.NewClientLedger(ledgerPath)
	if err != nil {
		logger.Error("loading client ledger", "error", err)
		os.Exit(1)
	}
	enroller.SetLedger(clientLedger)

	// Server-cert fingerprint tracker — owns current + rotated fingerprint
	// during dual-pin migrations. Starts with just the current fingerprint.
	fpTracker := auth.NewFingerprintTracker(fingerprint)

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.MaxRecvMsgSize(4<<20), // 4 MB per-message
		grpc.MaxSendMsgSize(4<<20),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.UnaryInterceptor(newAuthUnaryInterceptor(clientLedger, logger)),
		grpc.StreamInterceptor(newAuthStreamInterceptor(clientLedger, logger)),
	)

	sluiceServer := server.New(dispatcher, pool, enroller, logger, version, cfg.Limits.MaxFileSize, cfg.Server.GRPCAddr)
	sluiceServer.SetLedger(clientLedger)
	sluiceServer.SetFingerprintTracker(fpTracker)
	pb.RegisterSluiceServiceServer(grpcServer, sluiceServer)

	// Public mTLS listener.
	grpcLis, err := net.Listen("tcp", cfg.Server.GRPCAddr)
	if err != nil {
		logger.Error("gRPC listen", "addr", cfg.Server.GRPCAddr, "error", err)
		os.Exit(1)
	}
	go func() {
		logger.Info("gRPC server listening (mTLS)", "addr", cfg.Server.GRPCAddr)
		if err := grpcServer.Serve(grpcLis); err != nil {
			logger.Error("gRPC serve", "error", err)
		}
	}()

	// Local CLI transport: same handlers, different listener (unix socket).
	cliServer, cliLis, err := startCLIServer(cfg, sluiceServer, logger)
	if err != nil {
		logger.Warn("CLI socket disabled", "error", err)
	}

	// Optional testing UI (HTTPS + bearer auth + rate limit).
	var httpServer *http.Server
	if cfg.TestingUI.Enabled {
		bannerTestingUI(cfg, logger)
		httpServer = startTestingUI(cfg, webHandler, logger)
	} else {
		logger.Info("testing UI is disabled (production default)")
	}

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("shutting down", "signal", sig)

	// Ordered shutdown: stop accepting, drain in-flight, then close transports.
	webHandler.Stop()
	pool.Stop()
	shutdownGracefully(grpcServer, logger)
	if cliServer != nil {
		cliServer.Stop()
	}
	_ = cliLis // closed by cliServer.Stop
	if httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Error("http shutdown", "error", err)
		}
	}
	logger.Info("shutdown complete")
}

// shutdownGracefully wraps grpc.Server.GracefulStop with a hard timeout.
// Without the wrapper a stuck in-flight stream can hang forever.
func shutdownGracefully(s *grpc.Server, logger *slog.Logger) {
	done := make(chan struct{})
	go func() {
		s.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(35 * time.Second):
		logger.Warn("grpc GracefulStop timed out, forcing Stop")
		s.Stop()
	}
}

// newAuthUnaryInterceptor returns a unary interceptor that:
//  1. Allows Enroll without a client cert (chicken-and-egg bootstrap).
//  2. Rejects any other RPC without a verified client cert.
//  3. Rejects any RPC whose presenting cert is in the revocation ledger.
//
// The ledger may be nil (tests); in that case revocation checks are skipped.
func newAuthUnaryInterceptor(ledger *auth.ClientLedger, logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if rpcAllowedWithoutClientCert(info.FullMethod) {
			return handler(ctx, req)
		}
		if err := enforceVerifiedAndNotRevoked(ctx, ledger, info.FullMethod, logger); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func newAuthStreamInterceptor(ledger *auth.ClientLedger, logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if rpcAllowedWithoutClientCert(info.FullMethod) {
			return handler(srv, ss)
		}
		if err := enforceVerifiedAndNotRevoked(ss.Context(), ledger, info.FullMethod, logger); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// enforceVerifiedAndNotRevoked is the shared check body for unary + stream
// interceptors: valid mTLS peer + unrevoked fingerprint.
func enforceVerifiedAndNotRevoked(ctx context.Context, ledger *auth.ClientLedger, method string, logger *slog.Logger) error {
	cert, ok := verifiedClientCert(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "mTLS client certificate required")
	}
	if ledger != nil {
		fp := "sha256:" + sha256HexOfDER(cert.Raw)
		if ledger.IsRevoked(fp) {
			logger.Warn("rejected RPC from revoked client",
				"method", method,
				"common_name", cert.Subject.CommonName,
				"fingerprint", fp,
			)
			return status.Error(codes.PermissionDenied, "client certificate has been revoked")
		}
	}
	return nil
}

// verifiedClientCert returns the first cert in the verified chain, or (nil, false)
// if the peer did not present a cert that passed verification.
func verifiedClientCert(ctx context.Context) (*x509.Certificate, bool) {
	p, ok := peerFrom(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, false
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, false
	}
	if len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return nil, false
	}
	return ti.State.VerifiedChains[0][0], true
}

// sha256HexOfDER mirrors server.sha256HexOfDER — kept local to avoid an
// import cycle (main → server → auth would be fine, but main → auth only
// keeps this layer lightweight).
func sha256HexOfDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// rpcAllowedWithoutClientCert is the explicit allow-list of RPCs that do not
// require a verified client cert. Enroll is the only entry (chicken-and-egg).
func rpcAllowedWithoutClientCert(method string) bool {
	// method is like "/sluice.v1.SluiceService/Enroll"
	return strings.HasSuffix(method, "/Enroll")
}

// ---- First-boot token + banner --------------------------------------------

func ensureFirstBootToken(enroller *auth.EnrollmentManager, cfg *config.Config, fingerprint string, logger *slog.Logger) {
	tokenPath := cfg.Enrollment.TokenFile
	if _, err := os.Stat(tokenPath); err == nil {
		// Token file already exists — do not re-log. Operator ran `sluice token` once.
		return
	}
	token, err := enroller.GenerateToken()
	if err != nil {
		logger.Error("generating first-boot enrollment token", "error", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		logger.Warn("creating token dir", "error", err)
	}
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		logger.Warn("writing token file", "error", err)
	}
	ttl := cfg.Enrollment.TokenTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	expires := time.Now().UTC().Add(ttl).Format(time.RFC3339)
	logger.Info("SLUICE_ENROLL_TOKEN",
		"token", token,
		"fingerprint", fingerprint,
		"expires", expires,
		"ttl", ttl.String(),
	)
	// Human-friendly stderr banner so operators can grep it out of docker logs.
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "SLUICE_ENROLL_TOKEN=%s\n", token)
	fmt.Fprintf(os.Stderr, "SLUICE_SERVER_FINGERPRINT=%s\n", fingerprint)
	fmt.Fprintf(os.Stderr, "Expires: %s (%s)\n", expires, ttl)
	fmt.Fprintf(os.Stderr, "\n")
}

func bannerTestingUI(cfg *config.Config, logger *slog.Logger) {
	scheme := "http"
	if cfg.TestingUI.UseTLS {
		scheme = "https"
	}
	banner := []string{
		"",
		"  ⚠  SLUICE TESTING UI IS ENABLED",
		"  ⚠  This exposes the sanitization engine over " + strings.ToUpper(scheme) + ".",
		"  ⚠  Do NOT enable in production. Bind to localhost only.",
		"  ⚠  Listening on " + scheme + "://" + cfg.TestingUI.Addr + " (auth required)",
		"",
	}
	for _, line := range banner {
		fmt.Fprintln(os.Stderr, line)
	}
	logger.Warn("testing UI enabled",
		"addr", cfg.TestingUI.Addr,
		"tls", cfg.TestingUI.UseTLS,
		"auth", cfg.TestingUI.RequireAuth,
	)
}

// ---- Helpers ---------------------------------------------------------------

func loadConfigOrDefault(path string) *config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		cfg = config.Default()
		slog.Warn("using default config", "reason", err)
	}
	return cfg
}

func newLogger(cfg *config.Config) *slog.Logger {
	var h slog.Handler
	opts := &slog.HandlerOptions{Level: parseLogLevel(cfg.Logging.Level)}
	if cfg.Logging.Format == "json" {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h)
}

func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func buildDispatcher(logger *slog.Logger) *sanitizer.Dispatcher {
	d := sanitizer.NewDispatcher()
	d.Register(sanitizer.NewOfficeSanitizer(logger))
	d.Register(sanitizer.NewPDFSanitizer(logger))
	d.Register(sanitizer.NewImageSanitizer(logger))
	d.Register(sanitizer.NewSVGSanitizer(logger))
	d.Register(sanitizer.NewArchiveSanitizer(d, logger))
	return d
}

func tlsHosts(cfg *config.Config) []string {
	return []string{"localhost", "127.0.0.1", "::1"}
}

func ensureDataDir(cfg *config.Config, logger *slog.Logger) {
	paths := []string{
		filepath.Dir(cfg.Enrollment.TokenFile),
		filepath.Dir(cfg.Server.TLS.CAFile),
		filepath.Dir(cfg.CLI.SocketPath),
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" || p == "." || seen[p] {
			continue
		}
		seen[p] = true
		if err := os.MkdirAll(p, 0o700); err != nil {
			logger.Warn("creating dir", "path", p, "error", err)
		}
	}
}

// ---- Self-test -------------------------------------------------------------

func selfTest(d *sanitizer.Dispatcher, logger *slog.Logger) error {
	tests := []struct {
		name string
		data []byte
	}{
		{"test.pdf", []byte("%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF")},
		{"test.docx", miniZIP("word/document.xml", "<w:document/>")},
		{"test.png", miniPNG()},
		{"test.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><circle r="1"/></svg>`)},
		{"test.zip", miniZIP("hello.txt", "hello")},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, tt := range tests {
		result, err := d.Dispatch(ctx, tt.data, tt.name)
		if err != nil && result == nil {
			return fmt.Errorf("self-test %s: %w", tt.name, err)
		}
		if result != nil && result.Status == sanitizer.StatusError {
			logger.Debug("self-test warning", "file", tt.name, "status", "error")
		}
	}
	return nil
}

func miniZIP(name, content string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create(name)
	_, _ = f.Write([]byte(content))
	_ = w.Close()
	return buf.Bytes()
}

func miniPNG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.White)
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// ---- unused-fallback guards (silence linter for tls.VersionTLS13 import) ---

var (
	_ = tls.VersionTLS13
	_ = errors.New
)
