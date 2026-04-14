package web

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Sluice/internal/sanitizer"
)

// testLogger returns a silent logger for use in tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// makeTestZIP builds a minimal ZIP archive in memory from the given entries.
func makeTestZIP(entries map[string]string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, _ := w.Create(name)
		_, _ = f.Write([]byte(content))
	}
	_ = w.Close()
	return buf.Bytes()
}

// minimalDOCX returns ZIP entries for a minimal valid DOCX (no threats).
func minimalDOCX() map[string]string {
	return map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`,
		"word/document.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body>
</w:document>`,
	}
}

// createMultipartFile builds a multipart form body containing a single file field.
func createMultipartFile(t *testing.T, fieldname, filename string, data []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile(fieldname, filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(data)
	_ = w.Close()
	return &buf, w.FormDataContentType()
}

// newTestServer creates an httptest.Server backed by a real Dispatcher with the
// OfficeSanitizer registered.
func newTestServer(t *testing.T) (*httptest.Server, *Handler) {
	t.Helper()
	logger := testLogger()
	d := sanitizer.NewDispatcher()
	d.Register(sanitizer.NewOfficeSanitizer(logger))
	d.Register(sanitizer.NewPDFSanitizer(logger))

	h := NewHandler(d, logger, 10*1024*1024) // 10 MB limit
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, h
}

func TestHealthEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)

	resp, err := http.Get(srv.URL + "/api/health")
	if err != nil {
		t.Fatalf("GET /api/health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}

	healthy, ok := body["healthy"]
	if !ok {
		t.Fatal("response missing 'healthy' key")
	}
	if healthy != true {
		t.Errorf("expected healthy=true, got %v", healthy)
	}
}

func TestStatsEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)

	resp, err := http.Get(srv.URL + "/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var stats StatsJSON
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}

	if stats.FilesProcessed != 0 {
		t.Errorf("expected files_processed=0, got %d", stats.FilesProcessed)
	}
	if stats.ThreatsRemoved != 0 {
		t.Errorf("expected threats_removed=0, got %d", stats.ThreatsRemoved)
	}
}

func TestSanitizeEndpoint_NoFile(t *testing.T) {
	srv, _ := newTestServer(t)

	resp, err := http.Post(srv.URL+"/api/sanitize", "multipart/form-data", nil)
	if err != nil {
		t.Fatalf("POST /api/sanitize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}

	if _, ok := body["error"]; !ok {
		t.Error("expected 'error' key in response")
	}
}

func TestSanitizeEndpoint_CleanFile(t *testing.T) {
	srv, _ := newTestServer(t)

	data := makeTestZIP(minimalDOCX())
	body, contentType := createMultipartFile(t, "file", "clean.docx", data)

	resp, err := http.Post(srv.URL+"/api/sanitize", contentType, body)
	if err != nil {
		t.Fatalf("POST /api/sanitize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(respBody))
	}

	var result SanitizeResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}

	if result.Status != "clean" && result.Status != "unsupported" {
		t.Errorf("expected status 'clean' or 'unsupported', got %q", result.Status)
	}

	if result.OriginalSize == 0 {
		t.Error("expected OriginalSize > 0")
	}
}

func TestSanitizeEndpoint_WithThreats(t *testing.T) {
	srv, _ := newTestServer(t)

	entries := minimalDOCX()
	entries["word/vbaProject.bin"] = "fake-vba-macro-data"
	data := makeTestZIP(entries)

	body, contentType := createMultipartFile(t, "file", "malicious.docx", data)

	resp, err := http.Post(srv.URL+"/api/sanitize", contentType, body)
	if err != nil {
		t.Fatalf("POST /api/sanitize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(respBody))
	}

	var result SanitizeResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}

	if result.Status != "sanitized" {
		t.Errorf("expected status 'sanitized', got %q", result.Status)
	}

	if len(result.Threats) == 0 {
		t.Error("expected at least one threat, got none")
	}

	// Verify the VBA macro threat was detected.
	foundMacro := false
	for _, threat := range result.Threats {
		if threat.Type == "macro" {
			foundMacro = true
			break
		}
	}
	if !foundMacro {
		t.Error("expected a 'macro' threat type in the response")
	}

	if result.DownloadID == "" {
		t.Error("expected a non-empty download_id for sanitized file")
	}

	if result.SanitizedSize == 0 {
		t.Error("expected SanitizedSize > 0")
	}
}

func TestStatsAfterSanitize(t *testing.T) {
	srv, _ := newTestServer(t)

	// Sanitize a clean file first.
	cleanData := makeTestZIP(minimalDOCX())
	body, contentType := createMultipartFile(t, "file", "doc.docx", cleanData)
	resp, err := http.Post(srv.URL+"/api/sanitize", contentType, body)
	if err != nil {
		t.Fatalf("POST /api/sanitize (clean): %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for clean sanitize, got %d", resp.StatusCode)
	}

	// Sanitize a file with threats.
	dirtyEntries := minimalDOCX()
	dirtyEntries["word/vbaProject.bin"] = "macro-data"
	dirtyData := makeTestZIP(dirtyEntries)
	body2, contentType2 := createMultipartFile(t, "file", "bad.docx", dirtyData)
	resp2, err := http.Post(srv.URL+"/api/sanitize", contentType2, body2)
	if err != nil {
		t.Fatalf("POST /api/sanitize (dirty): %v", err)
	}
	_ = resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for dirty sanitize, got %d", resp2.StatusCode)
	}

	// Now check stats.
	statsResp, err := http.Get(srv.URL + "/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats: %v", err)
	}
	defer func() { _ = statsResp.Body.Close() }()

	var stats StatsJSON
	if err := json.NewDecoder(statsResp.Body).Decode(&stats); err != nil {
		t.Fatalf("decoding stats JSON: %v", err)
	}

	if stats.FilesProcessed != 2 {
		t.Errorf("expected files_processed=2, got %d", stats.FilesProcessed)
	}

	if stats.ThreatsRemoved < 1 {
		t.Errorf("expected threats_removed >= 1, got %d", stats.ThreatsRemoved)
	}

	if stats.FilesSanitized < 1 {
		t.Errorf("expected files_sanitized >= 1, got %d", stats.FilesSanitized)
	}

	if stats.FilesClean < 1 {
		t.Errorf("expected files_clean >= 1, got %d", stats.FilesClean)
	}
}

func TestStaticFiles(t *testing.T) {
	srv, _ := newTestServer(t)

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}

	bodyStr := string(bodyBytes)
	if !bytes.Contains(bodyBytes, []byte("Sluice")) {
		t.Errorf("expected response body to contain 'Sluice', got:\n%s", bodyStr[:min(len(bodyStr), 200)])
	}
}

func TestDownloadEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)

	// Upload a file with threats to get a download ID.
	entries := minimalDOCX()
	entries["word/vbaProject.bin"] = "vba-macro-payload"
	data := makeTestZIP(entries)
	body, contentType := createMultipartFile(t, "file", "threat.docx", data)

	resp, err := http.Post(srv.URL+"/api/sanitize", contentType, body)
	if err != nil {
		t.Fatalf("POST /api/sanitize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result SanitizeResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decoding sanitize JSON: %v", err)
	}

	if result.DownloadID == "" {
		t.Fatal("expected download_id in sanitize response")
	}

	// Download using the returned ID.
	dlResp, err := http.Get(srv.URL + "/api/download/" + result.DownloadID)
	if err != nil {
		t.Fatalf("GET /api/download: %v", err)
	}
	defer func() { _ = dlResp.Body.Close() }()

	if dlResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", dlResp.StatusCode)
	}

	ct := dlResp.Header.Get("Content-Type")
	if ct != "application/octet-stream" {
		t.Errorf("expected Content-Type application/octet-stream, got %q", ct)
	}

	cd := dlResp.Header.Get("Content-Disposition")
	if cd == "" {
		t.Error("expected Content-Disposition header to be set")
	}

	dlBody, err := io.ReadAll(dlResp.Body)
	if err != nil {
		t.Fatalf("reading download body: %v", err)
	}
	if len(dlBody) == 0 {
		t.Error("expected non-empty download body")
	}

	// The downloaded file should be a valid ZIP (sanitized DOCX).
	_, err = zip.NewReader(bytes.NewReader(dlBody), int64(len(dlBody)))
	if err != nil {
		t.Errorf("downloaded file is not a valid ZIP: %v", err)
	}
}

func TestDownloadEndpoint_NotFound(t *testing.T) {
	srv, _ := newTestServer(t)

	resp, err := http.Get(srv.URL + "/api/download/nonexistent-id")
	if err != nil {
		t.Fatalf("GET /api/download: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}
