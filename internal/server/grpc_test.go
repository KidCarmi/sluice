package server

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Sluice/internal/sanitizer"
)

// makeTestZIP builds a minimal ZIP archive in memory from the given entries.
func makeTestZIP(entries map[string]string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, _ := w.Create(name)
		f.Write([]byte(content))
	}
	w.Close()
	return buf.Bytes()
}

// minimalDOCX returns entries for a minimal valid DOCX (no threats).
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

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// newTestServer creates a dispatcher with the office sanitizer registered,
// starts a Server on a random port, and returns the server together with its
// address. The caller must call srv.Stop() when done.
func newTestServer(t *testing.T, maxFileSize int64) (*Server, string) {
	t.Helper()
	logger := testLogger()

	d := sanitizer.NewDispatcher()
	d.Register(sanitizer.NewOfficeSanitizer(logger))
	d.Register(sanitizer.NewPDFSanitizer(logger))

	srv := NewServer(d, logger, maxFileSize)

	// Use port 0 so the OS assigns a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	// We need to close this listener because ListenAndServe creates its own.
	ln.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(addr)
	}()

	// Give the server a moment to start accepting connections.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return srv, addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server did not start accepting connections on %s", addr)
	return nil, ""
}

// sendRequest dials addr, writes a JSON-line request, reads the JSON-line
// response and returns it decoded.
func sendRequest(t *testing.T, addr string, req SanitizeRequestJSON) SanitizeResponseJSON {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Set a deadline so the test does not hang forever.
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read response line.
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if bytes.Contains(buf.Bytes(), []byte("\n")) {
				break
			}
		}
		if err != nil {
			break
		}
	}

	var resp SanitizeResponseJSON
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &resp); err != nil {
		t.Fatalf("unmarshal response: %v (raw: %q)", err, buf.String())
	}
	return resp
}

func TestServerSanitize(t *testing.T) {
	srv, addr := newTestServer(t, 10*1024*1024)
	defer srv.Stop()

	docxData := makeTestZIP(minimalDOCX())
	req := SanitizeRequestJSON{
		Filename:    "clean.docx",
		ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		RequestID:   "test-clean-001",
		Data:        base64.StdEncoding.EncodeToString(docxData),
	}

	resp := sendRequest(t, addr, req)

	if resp.Status != "clean" {
		t.Errorf("expected status 'clean', got %q", resp.Status)
	}
	if resp.OriginalType != "docx" {
		t.Errorf("expected original_type 'docx', got %q", resp.OriginalType)
	}
	if resp.OriginalSize != int64(len(docxData)) {
		t.Errorf("expected original_size %d, got %d", len(docxData), resp.OriginalSize)
	}
	if len(resp.Threats) != 0 {
		t.Errorf("expected 0 threats, got %d", len(resp.Threats))
	}
	if resp.Data == "" {
		t.Error("expected non-empty sanitized data in response")
	}
	if resp.ErrorMessage != "" {
		t.Errorf("expected no error, got %q", resp.ErrorMessage)
	}

	// Decode the returned data and verify it is a valid ZIP.
	decoded, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		t.Fatalf("decode response data: %v", err)
	}
	if _, err := zip.NewReader(bytes.NewReader(decoded), int64(len(decoded))); err != nil {
		t.Fatalf("response data is not a valid ZIP: %v", err)
	}
}

func TestServerSanitizeWithThreats(t *testing.T) {
	srv, addr := newTestServer(t, 10*1024*1024)
	defer srv.Stop()

	entries := minimalDOCX()
	entries["word/vbaProject.bin"] = "VBA_MACRO_BINARY_DATA"
	docxData := makeTestZIP(entries)

	req := SanitizeRequestJSON{
		Filename:    "macro.docx",
		ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		RequestID:   "test-macro-001",
		Data:        base64.StdEncoding.EncodeToString(docxData),
	}

	resp := sendRequest(t, addr, req)

	if resp.Status != "sanitized" {
		t.Errorf("expected status 'sanitized', got %q", resp.Status)
	}
	if resp.OriginalType != "docx" {
		t.Errorf("expected original_type 'docx', got %q", resp.OriginalType)
	}
	if len(resp.Threats) == 0 {
		t.Fatal("expected at least 1 threat, got 0")
	}

	foundMacro := false
	for _, th := range resp.Threats {
		if th.Type == "macro" {
			foundMacro = true
			if th.Severity != "critical" {
				t.Errorf("expected macro severity 'critical', got %q", th.Severity)
			}
		}
	}
	if !foundMacro {
		t.Error("expected a 'macro' threat but none found")
	}

	if resp.Data == "" {
		t.Error("expected sanitized data in response")
	}

	// Verify that the sanitized archive no longer contains the macro.
	decoded, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		t.Fatalf("decode response data: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(decoded), int64(len(decoded)))
	if err != nil {
		t.Fatalf("read sanitized ZIP: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == "word/vbaProject.bin" {
			t.Error("vbaProject.bin should have been stripped from sanitized output")
		}
	}
}

func TestServerHealth(t *testing.T) {
	// Health endpoint is not yet implemented in the TCP server.
	// This test is a placeholder that will be enabled once the health RPC
	// is added (planned for the gRPC migration).
	t.Skip("health check not yet implemented in JSON-over-TCP server")
}

func TestServerOversizeFile(t *testing.T) {
	maxSize := int64(1024) // 1 KB limit
	srv, addr := newTestServer(t, maxSize)
	defer srv.Stop()

	// Create a file larger than the max.
	bigData := bytes.Repeat([]byte("A"), int(maxSize)+1)
	req := SanitizeRequestJSON{
		Filename:  "big.docx",
		RequestID: "test-oversize-001",
		Data:      base64.StdEncoding.EncodeToString(bigData),
	}

	resp := sendRequest(t, addr, req)

	if resp.Status != "error" {
		t.Errorf("expected status 'error', got %q", resp.Status)
	}
	if resp.ErrorMessage == "" {
		t.Error("expected non-empty error message for oversize file")
	}
	if !strings.Contains(resp.ErrorMessage, "exceeds maximum") {
		t.Errorf("expected error message to mention 'exceeds maximum', got %q", resp.ErrorMessage)
	}
}

func TestServerInvalidJSON(t *testing.T) {
	srv, addr := newTestServer(t, 10*1024*1024)
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send garbage followed by a newline.
	garbage := []byte("this is not valid json at all!!!\n")
	if _, err := conn.Write(garbage); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read the response — server should return a JSON error, not crash.
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if bytes.Contains(buf.Bytes(), []byte("\n")) {
				break
			}
		}
		if err != nil {
			break
		}
	}

	var resp SanitizeResponseJSON
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &resp); err != nil {
		t.Fatalf("expected valid JSON error response, got unmarshal error: %v (raw: %q)", err, buf.String())
	}

	if resp.Status != "error" {
		t.Errorf("expected status 'error', got %q", resp.Status)
	}
	if resp.ErrorMessage == "" {
		t.Error("expected non-empty error message for invalid JSON")
	}
	if !strings.Contains(resp.ErrorMessage, "invalid JSON") {
		t.Errorf("expected error message to mention 'invalid JSON', got %q", resp.ErrorMessage)
	}
}

func TestServerGracefulShutdown(t *testing.T) {
	srv, addr := newTestServer(t, 10*1024*1024)

	// Verify the server is accepting connections.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial before shutdown: %v", err)
	}
	conn.Close()

	// Stop the server.
	if err := srv.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}

	// After stop, new connections should be refused.
	_, err = net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err == nil {
		t.Error("expected connection to be refused after shutdown")
	}
}

func TestServerUnsupportedFileType(t *testing.T) {
	srv, addr := newTestServer(t, 10*1024*1024)
	defer srv.Stop()

	req := SanitizeRequestJSON{
		Filename:  "image.bmp",
		RequestID: "test-unsupported-001",
		Data:      base64.StdEncoding.EncodeToString([]byte("BM\x00\x00\x00")),
	}

	resp := sendRequest(t, addr, req)

	if resp.Status != "unsupported" {
		t.Errorf("expected status 'unsupported', got %q", resp.Status)
	}
	if resp.ErrorMessage == "" {
		t.Error("expected non-empty error message for unsupported type")
	}
}

func TestServerBadBase64(t *testing.T) {
	srv, addr := newTestServer(t, 10*1024*1024)
	defer srv.Stop()

	req := SanitizeRequestJSON{
		Filename:  "test.docx",
		RequestID: "test-badbase64-001",
		Data:      "not!valid!base64!!!",
	}

	resp := sendRequest(t, addr, req)

	if resp.Status != "error" {
		t.Errorf("expected status 'error', got %q", resp.Status)
	}
	if !strings.Contains(resp.ErrorMessage, "base64") {
		t.Errorf("expected error about base64, got %q", resp.ErrorMessage)
	}
}

func TestServerConcurrentRequests(t *testing.T) {
	srv, addr := newTestServer(t, 10*1024*1024)
	defer srv.Stop()

	docxData := makeTestZIP(minimalDOCX())
	encoded := base64.StdEncoding.EncodeToString(docxData)

	const numClients = 5
	errCh := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		go func(id int) {
			req := SanitizeRequestJSON{
				Filename:  "concurrent.docx",
				RequestID: fmt.Sprintf("concurrent-%d", id),
				Data:      encoded,
			}

			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				errCh <- fmt.Errorf("client %d dial: %w", id, err)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))

			data, _ := json.Marshal(req)
			data = append(data, '\n')
			if _, err := conn.Write(data); err != nil {
				errCh <- fmt.Errorf("client %d write: %w", id, err)
				return
			}

			var buf bytes.Buffer
			tmp := make([]byte, 4096)
			for {
				n, readErr := conn.Read(tmp)
				if n > 0 {
					buf.Write(tmp[:n])
					if bytes.Contains(buf.Bytes(), []byte("\n")) {
						break
					}
				}
				if readErr != nil {
					break
				}
			}

			var resp SanitizeResponseJSON
			if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &resp); err != nil {
				errCh <- fmt.Errorf("client %d unmarshal: %w (raw: %q)", id, err, buf.String())
				return
			}
			if resp.Status != "clean" {
				errCh <- fmt.Errorf("client %d: expected status 'clean', got %q", id, resp.Status)
				return
			}
			errCh <- nil
		}(i)
	}

	for i := 0; i < numClients; i++ {
		if err := <-errCh; err != nil {
			t.Error(err)
		}
	}
}
