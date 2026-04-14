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
	Enabled   bool   `yaml:"enabled"`
	TokenFile string `yaml:"token_file"`
}

// Default returns a Config populated with sane defaults.
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			GRPCAddr: ":8443",
			HTTPAddr: ":8080",
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
	if cfg.Limits.MaxFileSize <= 0 {
		return fmt.Errorf("limits.max_file_size must be > 0, got %d", cfg.Limits.MaxFileSize)
	}
	return nil
}
