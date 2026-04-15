package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// maxConfigSize is the maximum size of a config file we will read.
// Config files should be small; this guards against accidentally opening
// something huge.
const maxConfigSize = 1 << 20 // 1 MB

// Config is the top-level configuration for Sluice.
type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Workers      WorkersConfig      `yaml:"workers"`
	Limits       LimitsConfig       `yaml:"limits"`
	Sanitization SanitizationConfig `yaml:"sanitization"`
	Logging      LoggingConfig      `yaml:"logging"`
	Metrics      MetricsConfig      `yaml:"metrics"`
	Enrollment   EnrollmentConfig   `yaml:"enrollment"`
	TestingUI    TestingUIConfig    `yaml:"testing_ui"`
	CLI          CLIConfig          `yaml:"cli"`
}

// ServerConfig holds the listener addresses and TLS material.
type ServerConfig struct {
	GRPCAddr string    `yaml:"grpc_addr"`
	HTTPAddr string    `yaml:"http_addr"`
	TLS      TLSConfig `yaml:"tls"`
}

// TLSConfig points to the certificate, key, and CA files.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}

// WorkersConfig controls the processing worker pool.
type WorkersConfig struct {
	MaxConcurrent int           `yaml:"max_concurrent"`
	QueueDepth    int           `yaml:"queue_depth"`
	Timeout       time.Duration `yaml:"timeout"`
}

// LimitsConfig caps file sizes accepted by the engine.
type LimitsConfig struct {
	MaxFileSize         int64 `yaml:"max_file_size"`
	MaxDecompressedSize int64 `yaml:"max_decompressed_size"`
}

// SanitizationConfig holds per-format sanitization rules.
type SanitizationConfig struct {
	Office OfficeSanitization `yaml:"office"`
	PDF    PDFSanitization    `yaml:"pdf"`
}

// OfficeSanitization controls what gets stripped from Office documents.
type OfficeSanitization struct {
	Enabled                  bool `yaml:"enabled"`
	StripMacros              bool `yaml:"strip_macros"`
	StripOLEObjects          bool `yaml:"strip_ole_objects"`
	StripActiveX             bool `yaml:"strip_activex"`
	StripExternalConnections bool `yaml:"strip_external_connections"`
	ReEncodeImages           bool `yaml:"re_encode_images"`
}

// PDFSanitization controls what gets stripped from PDF documents.
type PDFSanitization struct {
	Enabled            bool `yaml:"enabled"`
	StripJavaScript    bool `yaml:"strip_javascript"`
	StripLaunchActions bool `yaml:"strip_launch_actions"`
	StripAttachments   bool `yaml:"strip_attachments"`
	StripXFA           bool `yaml:"strip_xfa"`
}

// LoggingConfig controls log output.
type LoggingConfig struct {
	Format string `yaml:"format"`
	Level  string `yaml:"level"`
}

// MetricsConfig holds the Prometheus scrape endpoint address.
type MetricsConfig struct {
	PrometheusAddr string `yaml:"prometheus_addr"`
}

// EnrollmentConfig controls the enrollment subsystem.
type EnrollmentConfig struct {
	Enabled   bool          `yaml:"enabled"`
	TokenFile string        `yaml:"token_file"`
	TokenTTL  time.Duration `yaml:"token_ttl"` // default 24h if zero
}

// TestingUIConfig controls the browser-based testing UI. OFF by default in
// production. Must stay bound to localhost, require auth, and rate-limit.
type TestingUIConfig struct {
	// Enabled gates the entire UI. Default: false.
	Enabled bool `yaml:"enabled"`
	// Addr is the listener address. Default: 127.0.0.1:8080 (never 0.0.0.0).
	Addr string `yaml:"addr"`
	// RequireAuth forces bearer-token authentication.
	RequireAuth bool `yaml:"require_auth"`
	// AuthTokenFile stores the bearer token. Auto-generated on first boot.
	AuthTokenFile string `yaml:"auth_token_file"`
	// MaxUploadsPerHour per source IP.
	MaxUploadsPerHour int `yaml:"max_uploads_per_hour"`
	// MaxFileSize applies only to the testing UI (separate from engine cap).
	MaxFileSize int64 `yaml:"max_file_size"`
	// UseTLS makes the testing UI HTTPS using the server cert. Default: true.
	UseTLS bool `yaml:"use_tls"`
}

// CLIConfig controls the local CLI unix-socket transport.
type CLIConfig struct {
	// SocketPath is the unix socket local CLI operators connect to.
	// Default: /data/sluice.sock. 0600, owner-only.
	SocketPath string `yaml:"socket_path"`
}

// Default returns a Config populated with sane defaults.
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			GRPCAddr: ":8443",
			HTTPAddr: ":8080",
			TLS: TLSConfig{
				// Default TLS material lives under /data so it survives
				// container restarts via the mounted volume. Bootstrap
				// mints these on first boot if they don't exist.
				CertFile: "/data/server.pem",
				KeyFile:  "/data/server-key.pem",
				CAFile:   "/data/ca.pem",
			},
		},
		Workers: WorkersConfig{
			MaxConcurrent: 10,
			QueueDepth:    50,
			Timeout:       30 * time.Second,
		},
		Limits: LimitsConfig{
			MaxFileSize:         50 << 20,  // 50 MB
			MaxDecompressedSize: 100 << 20, // 100 MB
		},
		Sanitization: SanitizationConfig{
			Office: OfficeSanitization{
				Enabled:                  true,
				StripMacros:              true,
				StripOLEObjects:          true,
				StripActiveX:             true,
				StripExternalConnections: true,
				ReEncodeImages:           true,
			},
			PDF: PDFSanitization{
				Enabled:            true,
				StripJavaScript:    true,
				StripLaunchActions: true,
				StripAttachments:   true,
				StripXFA:           true,
			},
		},
		Logging: LoggingConfig{
			Format: "json",
			Level:  "info",
		},
		Metrics: MetricsConfig{
			PrometheusAddr: ":9090",
		},
		Enrollment: EnrollmentConfig{
			Enabled:   true,
			TokenFile: "/data/enrollment_token",
			TokenTTL:  24 * time.Hour,
		},
		TestingUI: TestingUIConfig{ // #nosec G101 -- this is a default config block, AuthTokenFile is a path not a credential
			Enabled:           false, // OFF by default — prod hardening
			Addr:              "127.0.0.1:8080",
			RequireAuth:       true,
			AuthTokenFile:     "/data/ui_token", // #nosec G101 -- path, not a secret
			MaxUploadsPerHour: 20,
			MaxFileSize:       10 << 20, // 10 MB for testing UI
			UseTLS:            true,
		},
		CLI: CLIConfig{
			SocketPath: "/data/sluice.sock",
		},
	}
}

// Load reads a YAML config file from path and returns a parsed Config.
func Load(path string) (*Config, error) {
	path = filepath.Clean(path)
	f, err := os.Open(path) // #nosec G304 -- path is from CLI flag or constant, not user input
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = f.Close() }()

	lr := io.LimitReader(f, maxConfigSize)

	cfg := Default()
	dec := yaml.NewDecoder(lr)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// validate checks that required fields are present and within acceptable
// ranges.
func validate(cfg *Config) error {
	if cfg.Server.GRPCAddr == "" {
		return fmt.Errorf("server.grpc_addr must not be empty")
	}
	if cfg.Server.HTTPAddr == "" {
		return fmt.Errorf("server.http_addr must not be empty")
	}
	if cfg.Workers.MaxConcurrent <= 0 {
		return fmt.Errorf("workers.max_concurrent must be > 0, got %d", cfg.Workers.MaxConcurrent)
	}
	if cfg.Workers.QueueDepth < 0 {
		return fmt.Errorf("workers.queue_depth must be >= 0, got %d", cfg.Workers.QueueDepth)
	}
	if cfg.Workers.MaxConcurrent > 1000 {
		return fmt.Errorf("workers.max_concurrent exceeds safe limit (1000), got %d", cfg.Workers.MaxConcurrent)
	}
	if cfg.Workers.Timeout > 0 && cfg.Workers.Timeout < time.Second {
		return fmt.Errorf("workers.timeout must be >= 1s, got %v", cfg.Workers.Timeout)
	}
	if cfg.Limits.MaxFileSize <= 0 {
		return fmt.Errorf("limits.max_file_size must be > 0, got %d", cfg.Limits.MaxFileSize)
	}
	if cfg.Limits.MaxFileSize > 500*1024*1024 {
		return fmt.Errorf("limits.max_file_size exceeds safe limit (500MB), got %d", cfg.Limits.MaxFileSize)
	}
	return nil
}
