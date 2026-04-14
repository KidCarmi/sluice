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
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Sluice/internal/sanitizer"
	"github.com/KidCarmi/Sluice/internal/worker"
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
	path      string    // path to temp file on disk
	size      int64     // file size for Content-Length and accounting
	filename  string
	createdAt time.Time
}

const maxDownloads = 100
const maxTotalDownloadBytes = 500 * 1024 * 1024 // 500MB
const downloadTempDir = "/tmp/sluice-downloads"

// requestIDKey is the context key for request ID propagation.
type requestIDKey struct{}

// Handler serves the web GUI and API endpoints.
type Handler struct {
	dispatcher *sanitizer.Dispatcher
	pool       *worker.Pool
	stats      *Stats
	logger     *slog.Logger
	maxFileSize int64

	mu                 sync.Mutex
	downloads          map[string]*downloadEntry
	totalDownloadBytes int64

	// lastError tracks the most recent sanitization error for health checks.
	lastError     atomic.Value // stores string
	lastErrorTime atomic.Value // stores time.Time
	// consecutiveErrors tracks per-type failure streaks.
	errorStreaks sync.Map // map[sanitizer.FileType]*atomic.Int64

	stopCh chan struct{}
}

// NewHandler creates a new web handler.
func NewHandler(dispatcher *sanitizer.Dispatcher, pool *worker.Pool, logger *slog.Logger, maxFileSize int64) *Handler {
	// Clean stale temp files from previous runs, then recreate dir
	_ = os.RemoveAll(downloadTempDir)
	if err := os.MkdirAll(downloadTempDir, 0700); err != nil {
		logger.Error("failed to create download temp dir", "error", err)
	}

	h := &Handler{
		dispatcher:  dispatcher,
		pool:        pool,
		stats:       &Stats{},
		logger:      logger,
		maxFileSize: maxFileSize,
		downloads:   make(map[string]*downloadEntry),
		stopCh:      make(chan struct{}),
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
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// Generate request ID for log correlation
	reqID := generateSecureID()[:12]
	ctx = context.WithValue(ctx, requestIDKey{}, reqID)
	logger := h.logger.With("request_id", reqID)

	// Limit request body to max file size + multipart overhead
	r.Body = http.MaxBytesReader(w, r.Body, h.maxFileSize+4096)

	err := r.ParseMultipartForm(1 << 20) // #nosec G120 -- 1MB in RAM, rest spills to disk; body bounded by MaxBytesReader
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
	jobResult, err := h.pool.Submit(ctx, worker.Job{
		ID:       generateSecureID(),
		Data:     data,
		Filename: filename,
	})
	duration := time.Since(start)

	if err != nil {
		h.stats.FilesProcessed.Add(1)
		h.stats.FilesErrored.Add(1)
		if ctx.Err() != nil {
			h.jsonError(w, "sanitization timed out", http.StatusGatewayTimeout)
		} else {
			h.jsonError(w, fmt.Sprintf("sanitization failed: %v", err), http.StatusServiceUnavailable)
		}
		return
	}

	if jobResult == nil {
		h.stats.FilesProcessed.Add(1)
		h.stats.FilesErrored.Add(1)
		h.jsonError(w, "sanitization produced no result", http.StatusInternalServerError)
		return
	}
	result, ok := jobResult.Result.(*sanitizer.Result)
	if !ok || result == nil {
		h.stats.FilesProcessed.Add(1)
		h.stats.FilesErrored.Add(1)
		h.jsonError(w, "sanitization produced no result", http.StatusInternalServerError)
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

		// Write sanitized data to temp file
		tempPath, writeErr := writeDownloadFile(result.SanitizedData)
		if writeErr != nil {
			logger.Warn("failed to write download file", "error", writeErr)
			// Continue without download — sanitization still succeeded
		} else {
			h.mu.Lock()
			h.downloads[id] = &downloadEntry{
				path:      tempPath,
				size:      int64(len(result.SanitizedData)),
				filename:  "sanitized_" + filename,
				createdAt: time.Now(),
			}
			h.totalDownloadBytes += int64(len(result.SanitizedData))
			// Evict oldest if over count cap
			for len(h.downloads) > maxDownloads {
				h.evictOldest()
			}
			// Evict oldest until under total size cap
			for h.totalDownloadBytes > maxTotalDownloadBytes && len(h.downloads) > 0 {
				h.evictOldest()
			}
			h.mu.Unlock()
			resp.DownloadID = id
		}
	}

	// Track errors for health check and degradation detection
	if result.Status == sanitizer.StatusError {
		errMsg := "unknown error"
		if result.Error != nil {
			errMsg = result.Error.Error()
		}
		h.lastError.Store(errMsg)
		h.lastErrorTime.Store(time.Now())
		h.trackErrorStreak(result.OriginalType, true)
		logger.Warn("sanitization error",
			"filename", filename,
			"type", result.OriginalType,
			"error", errMsg,
			"duration_ms", duration.Milliseconds(),
		)
	} else {
		h.trackErrorStreak(result.OriginalType, false)
		logger.Info("file sanitized",
			"filename", filename,
			"type", result.OriginalType,
			"status", statusToString(result.Status),
			"threats", len(result.Threats),
			"duration_ms", duration.Milliseconds(),
		)
	}

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

	f, err := os.Open(entry.path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", entry.filename))
	http.ServeContent(w, r, entry.filename, entry.createdAt, f)
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	healthy := true
	var lastErr string
	var lastErrAge string

	if v := h.lastError.Load(); v != nil {
		lastErr = v.(string)
	}
	if v := h.lastErrorTime.Load(); v != nil {
		lastErrAge = time.Since(v.(time.Time)).Round(time.Second).String()
	}

	activeWorkers := h.pool.ActiveWorkers()
	queueDepth := h.pool.QueueDepth()

	// Unhealthy if queue is full (backpressure) or recent errors
	if queueDepth >= 50 {
		healthy = false
	}

	resp := map[string]interface{}{
		"healthy":         healthy,
		"version":         "0.1.0",
		"supported_types": []string{"pdf", "docx", "xlsx", "pptx", "jpeg", "png", "gif", "svg", "zip"},
		"active_workers":  activeWorkers,
		"queue_depth":     queueDepth,
		"files_processed": h.stats.FilesProcessed.Load(),
		"threats_removed": h.stats.ThreatsRemoved.Load(),
	}
	if lastErr != "" {
		resp["last_error"] = lastErr
		resp["last_error_age"] = lastErrAge
	}

	status := http.StatusOK
	if !healthy {
		status = http.StatusServiceUnavailable
	}
	h.jsonResponse(w, resp, status)
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
	defer func() {
		if r := recover(); r != nil {
			h.logger.Error("cleanup loop panic recovered", "panic", fmt.Sprintf("%v", r))
		}
	}()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.mu.Lock()
			for id, entry := range h.downloads {
				if time.Since(entry.createdAt) > 10*time.Minute {
					h.totalDownloadBytes -= entry.size
					_ = os.Remove(entry.path)
					delete(h.downloads, id)
				}
			}
			h.mu.Unlock()
		case <-h.stopCh:
			return
		}
	}
}

// Stop signals the handler to stop its background cleanup goroutine.
// It is safe to call multiple times.
func (h *Handler) Stop() {
	select {
	case <-h.stopCh:
		return // already stopped
	default:
		close(h.stopCh)
	}
	// Clean up remaining download temp files
	h.mu.Lock()
	for _, entry := range h.downloads {
		_ = os.Remove(entry.path)
	}
	h.downloads = make(map[string]*downloadEntry)
	h.totalDownloadBytes = 0
	h.mu.Unlock()
}

// GetStats returns the current stats (for use by metrics, gRPC health, etc.)
func (h *Handler) GetStats() StatsJSON {
	return h.stats.Snapshot()
}

// trackErrorStreak tracks consecutive errors per file type and logs a warning
// when a sanitizer starts degrading (5+ consecutive failures).
func (h *Handler) trackErrorStreak(ft sanitizer.FileType, isError bool) {
	val, _ := h.errorStreaks.LoadOrStore(ft, &atomic.Int64{})
	counter := val.(*atomic.Int64)
	if isError {
		streak := counter.Add(1)
		if streak == 5 {
			h.logger.Warn("sanitizer degradation detected",
				"type", ft,
				"consecutive_errors", streak,
			)
		}
	} else {
		counter.Store(0) // reset on success
	}
}

func writeDownloadFile(data []byte) (string, error) {
	f, err := os.CreateTemp(downloadTempDir, "sluice-dl-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Enforce strict permissions
	if err := f.Chmod(0600); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("setting file permissions: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("writing temp file: %w", err)
	}
	return f.Name(), nil
}

// evictOldest removes the oldest download entry and its temp file.
// Must be called with h.mu held.
func (h *Handler) evictOldest() {
	var oldestID string
	var oldestTime time.Time
	for did, de := range h.downloads {
		if oldestID == "" || de.createdAt.Before(oldestTime) {
			oldestID = did
			oldestTime = de.createdAt
		}
	}
	if oldestID != "" {
		entry := h.downloads[oldestID]
		h.totalDownloadBytes -= entry.size
		_ = os.Remove(entry.path)
		delete(h.downloads, oldestID)
	}
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
