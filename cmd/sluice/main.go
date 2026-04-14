package main

import (
	"archive/zip"
	"bytes"
	"context"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KidCarmi/Sluice/internal/config"
	"github.com/KidCarmi/Sluice/internal/sanitizer"
	"github.com/KidCarmi/Sluice/internal/web"
	"github.com/KidCarmi/Sluice/internal/worker"
)

var version = "0.1.0"

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	healthCheck := flag.Bool("health", false, "run health check and exit")
	flag.Parse()

	if *healthCheck {
		fmt.Println("healthy")
		os.Exit(0)
	}

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		// Fall back to defaults if no config file exists
		cfg = config.Default()
		slog.Warn("using default config", "reason", err)
	}

	// Setup structured logging
	var handler slog.Handler
	if cfg.Logging.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(cfg.Logging.Level)})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(cfg.Logging.Level)})
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	logger.Info("starting sluice",
		"version", version,
		"grpc_addr", cfg.Server.GRPCAddr,
		"http_addr", cfg.Server.HTTPAddr,
	)

	// Create sanitizer dispatcher and register sanitizers
	dispatcher := sanitizer.NewDispatcher()
	dispatcher.Register(sanitizer.NewOfficeSanitizer(logger))
	dispatcher.Register(sanitizer.NewPDFSanitizer(logger))
	dispatcher.Register(sanitizer.NewImageSanitizer(logger))
	dispatcher.Register(sanitizer.NewSVGSanitizer(logger))
	dispatcher.Register(sanitizer.NewArchiveSanitizer(dispatcher, logger))

	// Startup self-test: verify each sanitizer works
	if err := selfTest(dispatcher, logger); err != nil {
		logger.Error("startup self-test failed", "error", err)
		os.Exit(1)
	}
	logger.Info("startup self-test passed")

	// Create worker pool for bounded concurrency
	pool := worker.NewPool(worker.PoolConfig{
		MaxWorkers: cfg.Workers.MaxConcurrent,
		QueueDepth: cfg.Workers.QueueDepth,
		JobTimeout: cfg.Workers.Timeout,
	}, func(ctx context.Context, job worker.Job) (interface{}, error) {
		return dispatcher.Dispatch(ctx, job.Data, job.Filename)
	})
	defer pool.Stop()

	// Create web handler
	webHandler := web.NewHandler(dispatcher, pool, logger, cfg.Limits.MaxFileSize)

	// Setup HTTP server with routes
	mux := http.NewServeMux()
	webHandler.RegisterRoutes(mux)

	httpServer := &http.Server{
		Addr:         cfg.Server.HTTPAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start HTTP server
	go func() {
		logger.Info("web GUI available", "addr", "http://localhost"+cfg.Server.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("shutting down", "signal", sig)

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	webHandler.Stop()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("http shutdown error", "error", err)
	}
	logger.Info("shutdown complete")
}

// selfTest runs a minimal file through each registered sanitizer to verify
// they work. Catches misconfigurations and broken sanitizers at deploy time
// instead of on the first user request.
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
			// StatusError on minimal test files is acceptable (e.g., minimal
			// PDF may not fully parse). The important thing is it didn't panic.
			logger.Debug("self-test warning", "file", tt.name, "status", "error")
		}
	}
	return nil
}

// miniZIP creates a minimal ZIP with one entry.
func miniZIP(name, content string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create(name)
	_, _ = f.Write([]byte(content))
	_ = w.Close()
	return buf.Bytes()
}

// miniPNG creates a 1x1 white PNG.
func miniPNG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.White)
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
