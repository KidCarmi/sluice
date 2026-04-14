package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KidCarmi/Sluice/internal/config"
	"github.com/KidCarmi/Sluice/internal/sanitizer"
	"github.com/KidCarmi/Sluice/internal/web"
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

	// Create web handler
	webHandler := web.NewHandler(dispatcher, logger, cfg.Limits.MaxFileSize)

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
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("http shutdown error", "error", err)
	}
	logger.Info("shutdown complete")
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
