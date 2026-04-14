// Package server provides a JSON-over-TCP server that mirrors the planned gRPC
// API shape for the Sluice CDR engine. This will be replaced with proper gRPC
// once protoc code generation is set up.
package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Sluice/internal/sanitizer"
)

// requestTimeout is the maximum time allowed to process a single request.
const requestTimeout = 30 * time.Second

// readOverhead is extra bytes allowed on top of maxFileSize to account for
// JSON framing, base64 expansion, and metadata fields.
const readOverhead = 4096

// statusName maps sanitizer.Status values to the wire-format status strings
// used in JSON responses.
var statusName = map[sanitizer.Status]string{
	sanitizer.StatusClean:       "clean",
	sanitizer.StatusSanitized:   "sanitized",
	sanitizer.StatusBlocked:     "blocked",
	sanitizer.StatusError:       "error",
	sanitizer.StatusUnsupported: "unsupported",
}

// Server handles incoming sanitization requests over TCP with JSON encoding.
type Server struct {
	dispatcher  *sanitizer.Dispatcher
	mu          sync.Mutex // protects listener
	listener    net.Listener
	logger      *slog.Logger
	maxFileSize int64
	connWg      sync.WaitGroup // tracks in-flight connections only
	stopped     atomic.Bool
	acceptDone  chan struct{} // closed when accept loop exits
}

// SanitizeRequestJSON is the JSON request format.
type SanitizeRequestJSON struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	RequestID   string `json:"request_id"`
	Data        string `json:"data"` // base64-encoded file data
}

// SanitizeResponseJSON is the JSON response format.
type SanitizeResponseJSON struct {
	Status        string       `json:"status"` // clean, sanitized, blocked, error, unsupported
	OriginalType  string       `json:"original_type"`
	OriginalSize  int64        `json:"original_size"`
	SanitizedSize int64        `json:"sanitized_size"`
	Threats       []ThreatJSON `json:"threats"`
	Data          string       `json:"data,omitempty"`          // base64-encoded sanitized file
	ErrorMessage  string       `json:"error_message,omitempty"` // human-readable error
}

// ThreatJSON is the JSON representation of a single threat finding.
type ThreatJSON struct {
	Type        string `json:"type"`
	Location    string `json:"location"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// HealthResponseJSON is the JSON response for health checks.
type HealthResponseJSON struct {
	Healthy        bool     `json:"healthy"`
	Version        string   `json:"version"`
	SupportedTypes []string `json:"supported_types"`
}

// NewServer creates a Server ready to accept connections once ListenAndServe
// is called. maxFileSize limits the decoded (pre-base64) payload size in bytes.
func NewServer(dispatcher *sanitizer.Dispatcher, logger *slog.Logger, maxFileSize int64) *Server {
	return &Server{
		dispatcher:  dispatcher,
		logger:      logger,
		maxFileSize: maxFileSize,
		acceptDone:  make(chan struct{}),
	}
}

// ListenAndServe binds to addr (e.g. "127.0.0.1:9000") and begins accepting
// connections. It blocks until the listener is closed or an unrecoverable
// error occurs.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("server listen: %w", err)
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	s.logger.Info("server listening", slog.String("addr", ln.Addr().String()))

	defer close(s.acceptDone)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.stopped.Load() {
				return nil
			}
			s.logger.Error("accept error", slog.String("error", err.Error()))
			continue
		}
		if s.stopped.Load() {
			_ = conn.Close()
			return nil
		}
		s.connWg.Add(1)
		go s.handleConn(conn)
	}
}

// Addr returns the listener's network address, or nil if the server has not
// started listening yet.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Addr()
}

// Stop performs a graceful shutdown: it closes the listener so no new
// connections are accepted, then waits for all in-flight requests to finish.
func (s *Server) Stop() error {
	s.stopped.Store(true)
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	// Wait for the accept loop to exit before waiting on connections.
	// This ensures no new connWg.Add calls race with connWg.Wait.
	<-s.acceptDone
	s.connWg.Wait()
	s.logger.Info("server stopped")
	return err
}

// handleConn reads a single newline-delimited JSON request from conn,
// processes it through the dispatcher, writes the JSON response, and closes
// the connection.
func (s *Server) handleConn(conn net.Conn) {
	defer s.connWg.Done()
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	// Cap reads to prevent memory exhaustion. base64 encoding expands data by
	// ~4/3, so the maximum encoded size is roughly maxFileSize*4/3 plus JSON
	// framing overhead.
	maxRead := s.maxFileSize*2 + readOverhead
	reader := bufio.NewReader(io.LimitReader(conn, maxRead))

	line, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		s.logger.Error("read error",
			slog.String("remote", conn.RemoteAddr().String()),
			slog.String("error", err.Error()),
		)
		s.writeErrorResponse(conn, "read error: "+err.Error())
		return
	}
	if len(line) == 0 {
		s.logger.Warn("empty request", slog.String("remote", conn.RemoteAddr().String()))
		s.writeErrorResponse(conn, "empty request")
		return
	}

	var req SanitizeRequestJSON
	if err := json.Unmarshal(line, &req); err != nil {
		s.logger.Warn("invalid JSON",
			slog.String("remote", conn.RemoteAddr().String()),
			slog.String("error", err.Error()),
		)
		s.writeErrorResponse(conn, "invalid JSON: "+err.Error())
		return
	}

	s.logger.Info("processing request",
		slog.String("request_id", req.RequestID),
		slog.String("filename", req.Filename),
		slog.String("remote", conn.RemoteAddr().String()),
	)

	fileData, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		s.logger.Warn("base64 decode error",
			slog.String("request_id", req.RequestID),
			slog.String("error", err.Error()),
		)
		s.writeErrorResponse(conn, "base64 decode: "+err.Error())
		return
	}

	if int64(len(fileData)) > s.maxFileSize {
		s.logger.Warn("file too large",
			slog.String("request_id", req.RequestID),
			slog.Int64("size", int64(len(fileData))),
			slog.Int64("max", s.maxFileSize),
		)
		s.writeErrorResponse(conn, fmt.Sprintf("file size %d exceeds maximum %d", len(fileData), s.maxFileSize))
		return
	}

	result, err := s.dispatcher.Dispatch(ctx, fileData, req.Filename)
	resp := s.buildResponse(result, err)

	s.writeJSON(conn, resp)
}

// buildResponse converts a sanitizer.Result (and optional error) into the
// JSON response structure.
func (s *Server) buildResponse(result *sanitizer.Result, dispatchErr error) SanitizeResponseJSON {
	if result == nil {
		return SanitizeResponseJSON{
			Status:       "error",
			ErrorMessage: dispatchErr.Error(),
		}
	}

	resp := SanitizeResponseJSON{
		Status:        statusString(result.Status),
		OriginalType:  string(result.OriginalType),
		OriginalSize:  result.OriginalSize,
		SanitizedSize: result.SanitizedSize,
		Threats:       make([]ThreatJSON, 0, len(result.Threats)),
	}

	for _, t := range result.Threats {
		resp.Threats = append(resp.Threats, ThreatJSON{
			Type:        t.Type,
			Location:    t.Location,
			Description: t.Description,
			Severity:    t.Severity,
		})
	}

	if len(result.SanitizedData) > 0 {
		resp.Data = base64.StdEncoding.EncodeToString(result.SanitizedData)
	}

	if result.Error != nil {
		resp.ErrorMessage = result.Error.Error()
	}
	if dispatchErr != nil && resp.ErrorMessage == "" {
		resp.ErrorMessage = dispatchErr.Error()
	}

	return resp
}

// writeErrorResponse sends a minimal error response to the connection.
func (s *Server) writeErrorResponse(conn net.Conn, msg string) {
	resp := SanitizeResponseJSON{
		Status:       "error",
		ErrorMessage: msg,
		Threats:      []ThreatJSON{},
	}
	s.writeJSON(conn, resp)
}

// writeJSON marshals v as a single JSON line and writes it to w.
func (s *Server) writeJSON(w io.Writer, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		s.logger.Error("json marshal error", slog.String("error", err.Error()))
		return
	}
	data = append(data, '\n')
	if _, err := w.Write(data); err != nil {
		s.logger.Error("write error", slog.String("error", err.Error()))
	}
}

// statusString returns the wire-format string for a sanitizer.Status value.
func statusString(st sanitizer.Status) string {
	if name, ok := statusName[st]; ok {
		return name
	}
	return "error"
}
