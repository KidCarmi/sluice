package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Sluice/internal/sanitizer"
)

//go:embed static/*
var staticFS embed.FS

// Stats tracks cumulative sanitization statistics for the dashboard.
type Stats struct {
	FilesProcessed  atomic.Int64
	ThreatsRemoved  atomic.Int64
	FilesSanitized  atomic.Int64
	FilesClean      atomic.Int64
	FilesBlocked    atomic.Int64
	FilesErrored    atomic.Int64
	FilesUnsupported atomic.Int64
}

// StatsJSON is the JSON-serializable snapshot of Stats.
type StatsJSON struct {
	FilesProcessed  int64 `json:"files_processed"`
	ThreatsRemoved  int64 `json:"threats_removed"`
	FilesSanitized  int64 `json:"files_sanitized"`
	FilesClean      int64 `json:"files_clean"`
	FilesBlocked    int64 `json:"files_blocked"`
	FilesErrored    int64 `json:"files_errored"`
	FilesUnsupported int64 `json:"files_unsupported"`
}

func (s *Stats) Snapshot() StatsJSON {
	return StatsJSON{
		FilesProcessed:  s.FilesProcessed.Load(),
		ThreatsRemoved:  s.ThreatsRemoved.Load(),
		FilesSanitized:  s.FilesSanitized.Load(),
		FilesClean:      s.FilesClean.Load(),
		FilesBlocked:    s.FilesBlocked.Load(),
		FilesErrored:    s.FilesErrored.Load(),
		FilesUnsupported: s.FilesUnsupported.Load(),
	}
}

// SanitizeResponseJSON is the JSON response for a sanitization request.
type SanitizeResponseJSON struct {
	Status        string           `json:"status"`
	OriginalType  string           `json:"original_type"`
	OriginalSize  int64            `json:"original_size"`
	SanitizedSize int64            `json:"sanitized_size"`
	Threats       []ThreatJSON     `json:"threats"`
	ErrorMessage  string           `json:"error_message,omitempty"`
	DownloadID    string           `json:"download_id,omitempty"`
	DurationMs    int64            `json:"duration_ms"`
}

// ThreatJSON is the JSON representation of a detected threat.
type ThreatJSON struct {
	Type        string `json:"type"`
	Location    string `json:"location"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// downloadEntry holds a sanitized file available for download.
type downloadEntry struct {
	data      []byte
	filename  string
	createdAt time.Time
}

// Handler serves the web GUI and API endpoints.
type Handler struct {
	dispatcher *sanitizer.Dispatcher
	stats      *Stats
	logger     *slog.Logger
	maxFileSize int64

	mu        sync.Mutex
	downloads map[string]*downloadEntry
}

// NewHandler creates a new web handler.
func NewHandler(dispatcher *sanitizer.Dispatcher, logger *slog.Logger, maxFileSize int64) *Handler {
	h := &Handler{
		dispatcher:  dispatcher,
		stats:       &Stats{},
		logger:      logger,
		maxFileSize: maxFileSize,
		downloads:   make(map[string]*downloadEntry),
	}
	// Clean up expired downloads every minute
	go h.cleanupLoop()
	return h
}

// RegisterRoutes registers all HTTP routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Serve embedded static files from the "static" subdirectory at root
	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /", http.FileServerFS(staticSub))
	mux.HandleFunc("POST /api/sanitize", h.handleSanitize)
	mux.HandleFunc("GET /api/stats", h.handleStats)
	mux.HandleFunc("GET /api/download/{id}", h.handleDownload)
	mux.HandleFunc("GET /api/health", h.handleHealth)
	mux.HandleFunc("GET /api/samples", h.handleSamples)
}

//go:embed samples
var samplesFS embed.FS

func (h *Handler) handleSamples(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		// List available samples
		entries, err := fs.ReadDir(samplesFS, "samples")
		if err != nil {
			h.jsonError(w, "reading samples: "+err.Error(), http.StatusInternalServerError)
			return
		}
		var names []string
		for _, e := range entries {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		h.jsonResponse(w, map[string]interface{}{"samples": names}, http.StatusOK)
		return
	}

	// Serve a specific sample file
	name = filepath.Base(name) // prevent traversal
	data, err := fs.ReadFile(samplesFS, "samples/"+name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	_, _ = w.Write(data) // #nosec G705 -- data is from read-only embedded FS, not user input
}

func (h *Handler) handleSanitize(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Limit request body to max file size + multipart overhead
	r.Body = http.MaxBytesReader(w, r.Body, h.maxFileSize+4096)

	err := r.ParseMultipartForm(h.maxFileSize) // #nosec G120 -- body is already bounded by MaxBytesReader above
	if err != nil {
		h.jsonError(w, "file too large or invalid form data", http.StatusBadRequest)
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, header, err := r.FormFile("file")
	if err != nil {
		h.jsonError(w, "no file provided", http.StatusBadRequest)
		return
	}
	defer func() { _ = file.Close() }()

	// Read file with size limit via io.LimitReader
	data, err := io.ReadAll(io.LimitReader(file, h.maxFileSize+1))
	if err != nil {
		h.jsonError(w, fmt.Sprintf("reading file: %v", err), http.StatusInternalServerError)
		return
	}
	if int64(len(data)) > h.maxFileSize {
		h.jsonError(w, fmt.Sprintf("file exceeds maximum size of %d bytes", h.maxFileSize), http.StatusRequestEntityTooLarge)
		return
	}

	filename := filepath.Base(header.Filename)

	start := time.Now()
	result, err := h.dispatcher.Dispatch(ctx, data, filename)
	duration := time.Since(start)

	if err != nil {
		h.stats.FilesProcessed.Add(1)
		h.stats.FilesErrored.Add(1)
		h.jsonError(w, fmt.Sprintf("sanitization failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Update stats
	h.stats.FilesProcessed.Add(1)
	h.stats.ThreatsRemoved.Add(int64(len(result.Threats)))

	switch result.Status {
	case sanitizer.StatusClean:
		h.stats.FilesClean.Add(1)
	case sanitizer.StatusSanitized:
		h.stats.FilesSanitized.Add(1)
	case sanitizer.StatusBlocked:
		h.stats.FilesBlocked.Add(1)
	case sanitizer.StatusError:
		h.stats.FilesErrored.Add(1)
	case sanitizer.StatusUnsupported:
		h.stats.FilesUnsupported.Add(1)
	}

	resp := SanitizeResponseJSON{
		Status:        statusToString(result.Status),
		OriginalType:  string(result.OriginalType),
		OriginalSize:  result.OriginalSize,
		SanitizedSize: result.SanitizedSize,
		DurationMs:    duration.Milliseconds(),
	}

	if result.Error != nil {
		resp.ErrorMessage = result.Error.Error()
	}

	for _, t := range result.Threats {
		resp.Threats = append(resp.Threats, ThreatJSON{
			Type:        t.Type,
			Location:    t.Location,
			Description: t.Description,
			Severity:    t.Severity,
		})
	}

	// Store sanitized file for download if we have data
	if len(result.SanitizedData) > 0 {
		id := generateSecureID()
		h.mu.Lock()
		h.downloads[id] = &downloadEntry{
			data:      result.SanitizedData,
			filename:  "sanitized_" + filename,
			createdAt: time.Now(),
		}
		h.mu.Unlock()
		resp.DownloadID = id
	}

	h.logger.Info("file sanitized",
		"filename", filename,
		"type", result.OriginalType,
		"status", statusToString(result.Status),
		"threats", len(result.Threats),
		"duration_ms", duration.Milliseconds(),
	)

	h.jsonResponse(w, resp, http.StatusOK)
}

func (h *Handler) handleStats(w http.ResponseWriter, _ *http.Request) {
	h.jsonResponse(w, h.stats.Snapshot(), http.StatusOK)
}

func (h *Handler) handleDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	h.mu.Lock()
	entry, ok := h.downloads[id]
	h.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", entry.filename))
	_, _ = w.Write(entry.data)
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	h.jsonResponse(w, map[string]interface{}{
		"healthy":         true,
		"version":         "0.1.0",
		"supported_types": []string{"pdf", "docx", "xlsx", "pptx", "jpeg", "png", "gif", "svg", "zip"},
	}, http.StatusOK)
}

func (h *Handler) jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *Handler) jsonError(w http.ResponseWriter, message string, status int) {
	h.jsonResponse(w, map[string]string{"error": message}, status)
}

func (h *Handler) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		h.mu.Lock()
		for id, entry := range h.downloads {
			if time.Since(entry.createdAt) > 10*time.Minute {
				delete(h.downloads, id)
			}
		}
		h.mu.Unlock()
	}
}

// GetStats returns the current stats (for use by metrics, gRPC health, etc.)
func (h *Handler) GetStats() StatsJSON {
	return h.stats.Snapshot()
}

// generateSecureID returns a cryptographically random hex string for download IDs.
func generateSecureID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func statusToString(s sanitizer.Status) string {
	switch s {
	case sanitizer.StatusClean:
		return "clean"
	case sanitizer.StatusSanitized:
		return "sanitized"
	case sanitizer.StatusBlocked:
		return "blocked"
	case sanitizer.StatusError:
		return "error"
	case sanitizer.StatusUnsupported:
		return "unsupported"
	default:
		return "unknown"
	}
}
