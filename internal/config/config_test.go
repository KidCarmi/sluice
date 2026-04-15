package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestLoadValidConfig(t *testing.T) {
	const yamlContent = `
server:
  grpc_addr: ":9443"
  http_addr: ":9080"
  tls:
    cert_file: /tmp/cert.pem
    key_file: /tmp/key.pem
    ca_file: /tmp/ca.pem

workers:
  max_concurrent: 4
  queue_depth: 20
  timeout: 15s

limits:
  max_file_size: 10485760
  max_decompressed_size: 20971520

sanitization:
  office:
    enabled: true
    strip_macros: true
    strip_ole_objects: false
    strip_activex: true
    strip_external_connections: true
    re_encode_images: false
  pdf:
    enabled: false
    strip_javascript: true
    strip_launch_actions: false
    strip_attachments: true
    strip_xfa: false

logging:
  format: text
  level: debug

metrics:
  prometheus_addr: ":9191"

enrollment:
  enabled: false
  token_file: /tmp/token
`

	path := writeTempConfig(t, yamlContent)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Server
	assertEqual(t, "Server.GRPCAddr", ":9443", cfg.Server.GRPCAddr)
	assertEqual(t, "Server.HTTPAddr", ":9080", cfg.Server.HTTPAddr)
	assertEqual(t, "Server.TLS.CertFile", "/tmp/cert.pem", cfg.Server.TLS.CertFile)
	assertEqual(t, "Server.TLS.KeyFile", "/tmp/key.pem", cfg.Server.TLS.KeyFile)
	assertEqual(t, "Server.TLS.CAFile", "/tmp/ca.pem", cfg.Server.TLS.CAFile)

	// Workers
	assertEqual(t, "Workers.MaxConcurrent", 4, cfg.Workers.MaxConcurrent)
	assertEqual(t, "Workers.QueueDepth", 20, cfg.Workers.QueueDepth)
	assertEqual(t, "Workers.Timeout", 15*time.Second, cfg.Workers.Timeout)

	// Limits
	assertEqual(t, "Limits.MaxFileSize", int64(10485760), cfg.Limits.MaxFileSize)
	assertEqual(t, "Limits.MaxDecompressedSize", int64(20971520), cfg.Limits.MaxDecompressedSize)

	// Sanitization - Office
	assertEqual(t, "Sanitization.Office.Enabled", true, cfg.Sanitization.Office.Enabled)
	assertEqual(t, "Sanitization.Office.StripMacros", true, cfg.Sanitization.Office.StripMacros)
	assertEqual(t, "Sanitization.Office.StripOLEObjects", false, cfg.Sanitization.Office.StripOLEObjects)
	assertEqual(t, "Sanitization.Office.ReEncodeImages", false, cfg.Sanitization.Office.ReEncodeImages)

	// Sanitization - PDF
	assertEqual(t, "Sanitization.PDF.Enabled", false, cfg.Sanitization.PDF.Enabled)
	assertEqual(t, "Sanitization.PDF.StripXFA", false, cfg.Sanitization.PDF.StripXFA)

	// Logging
	assertEqual(t, "Logging.Format", "text", cfg.Logging.Format)
	assertEqual(t, "Logging.Level", "debug", cfg.Logging.Level)

	// Metrics
	assertEqual(t, "Metrics.PrometheusAddr", ":9191", cfg.Metrics.PrometheusAddr)

	// Enrollment
	assertEqual(t, "Enrollment.Enabled", false, cfg.Enrollment.Enabled)
	assertEqual(t, "Enrollment.TokenFile", "/tmp/token", cfg.Enrollment.TokenFile)
}

func TestDefaultSaneValues(t *testing.T) {
	cfg := Default()

	if cfg.Server.GRPCAddr == "" {
		t.Error("Default grpc_addr is empty")
	}
	if cfg.Server.HTTPAddr == "" {
		t.Error("Default http_addr is empty")
	}
	if cfg.Workers.MaxConcurrent <= 0 {
		t.Errorf("Default max_concurrent should be > 0, got %d", cfg.Workers.MaxConcurrent)
	}
	if cfg.Workers.Timeout <= 0 {
		t.Errorf("Default timeout should be > 0, got %v", cfg.Workers.Timeout)
	}
	if cfg.Limits.MaxFileSize <= 0 {
		t.Errorf("Default max_file_size should be > 0, got %d", cfg.Limits.MaxFileSize)
	}
	if cfg.Limits.MaxDecompressedSize <= 0 {
		t.Errorf("Default max_decompressed_size should be > 0, got %d", cfg.Limits.MaxDecompressedSize)
	}
	if !cfg.Sanitization.Office.Enabled {
		t.Error("Default office sanitization should be enabled")
	}
	if !cfg.Sanitization.PDF.Enabled {
		t.Error("Default PDF sanitization should be enabled")
	}

	// TLS file paths must be populated. When these were empty, main.go
	// handed "" to BootstrapServerCerts, which filepath.Cleaned to ".",
	// and os.ReadFile(".") failed with "is a directory" — sending the
	// container into a restart loop on first boot without a config file.
	if cfg.Server.TLS.CertFile == "" {
		t.Error("Default tls.cert_file must not be empty")
	}
	if cfg.Server.TLS.KeyFile == "" {
		t.Error("Default tls.key_file must not be empty")
	}
	if cfg.Server.TLS.CAFile == "" {
		t.Error("Default tls.ca_file must not be empty")
	}

	// Defaults should pass validation.
	if err := validate(cfg); err != nil {
		t.Errorf("Default config should pass validation, got: %v", err)
	}
}

func TestValidationMissingGRPCAddr(t *testing.T) {
	cfg := Default()
	cfg.Server.GRPCAddr = ""

	path := writeTempConfigFromCfg(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for empty grpc_addr")
	}
	assertContains(t, err.Error(), "grpc_addr")
}

func TestValidationMissingHTTPAddr(t *testing.T) {
	cfg := Default()
	cfg.Server.HTTPAddr = ""

	path := writeTempConfigFromCfg(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for empty http_addr")
	}
	assertContains(t, err.Error(), "http_addr")
}

func TestValidationMaxConcurrentZero(t *testing.T) {
	cfg := Default()
	cfg.Workers.MaxConcurrent = 0

	path := writeTempConfigFromCfg(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for max_concurrent = 0")
	}
	assertContains(t, err.Error(), "max_concurrent")
}

func TestValidationMaxFileSizeZero(t *testing.T) {
	cfg := Default()
	cfg.Limits.MaxFileSize = 0

	path := writeTempConfigFromCfg(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for max_file_size = 0")
	}
	assertContains(t, err.Error(), "max_file_size")
}

func TestInvalidYAMLReturnsError(t *testing.T) {
	path := writeTempConfig(t, `{{{not valid yaml!!!`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	_, err := Load("/does/not/exist/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	assertContains(t, err.Error(), "open config")
}

func TestUnknownFieldReturnsError(t *testing.T) {
	const yamlContent = `
server:
  grpc_addr: ":8443"
  http_addr: ":8080"
  bogus_field: true
`
	path := writeTempConfig(t, yamlContent)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestLoadExampleConfig(t *testing.T) {
	// Load the project's own config.example.yaml to make sure it parses.
	examplePath := filepath.Join(projectRoot(t), "config.example.yaml")
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Skip("config.example.yaml not found, skipping")
	}

	cfg, err := Load(examplePath)
	if err != nil {
		t.Fatalf("Load(config.example.yaml) returned error: %v", err)
	}
	assertEqual(t, "Server.GRPCAddr", ":8443", cfg.Server.GRPCAddr)
	assertEqual(t, "Workers.Timeout", 30*time.Second, cfg.Workers.Timeout)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func writeTempConfigFromCfg(t *testing.T, cfg *Config) string {
	t.Helper()

	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return writeTempConfig(t, string(data))
}

func projectRoot(t *testing.T) string {
	t.Helper()
	// Walk up from the test file's package directory to find go.mod.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root")
		}
		dir = parent
	}
}

func assertEqual[T comparable](t *testing.T, field string, want, got T) {
	t.Helper()
	if want != got {
		t.Errorf("%s: want %v, got %v", field, want, got)
	}
}

func assertContains(t *testing.T, s, substr string) {
	t.Helper()
	if len(s) == 0 || len(substr) == 0 {
		t.Errorf("assertContains: empty string or substr")
		return
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return
		}
	}
	t.Errorf("expected %q to contain %q", s, substr)
}
