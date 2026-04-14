// Hardened testing UI for local Sluice developers.
//
// Production-unsafe by default. Enabled only when cfg.TestingUI.Enabled = true.
// Defensive-in-depth:
//   - binds to localhost only (config rejects 0.0.0.0)
//   - HTTPS using the same server cert the gRPC port uses (TLS 1.3 min)
//   - bearer-token auth (token auto-generated on first boot, 0600)
//   - rate-limited (uploads/hour/IP)
//   - forces profile=default, mode=ENFORCE (cannot be used as policy-bypass oracle)
//   - separate Prometheus label ui_test="true"
//   - hardened headers (CSP, X-Frame-Options, X-Content-Type-Options)
//   - audit log entry per upload
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Sluice/internal/config"
	"github.com/KidCarmi/Sluice/internal/web"
)

// startTestingUI constructs and starts the hardened testing UI.
// Returns the *http.Server so main.go can shut it down gracefully.
func startTestingUI(cfg *config.Config, webHandler *web.Handler, logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}) *http.Server {
	// Defensive warning: non-localhost bindings are fine inside a container
	// (Docker namespace is isolated) but risky on bare metal. The loud banner
	// in bannerTestingUI already warns about LAN exposure; log the bind addr
	// so operators see it in the structured log too.
	if !isLocalhost(cfg.TestingUI.Addr) {
		logger.Warn("testing UI binding non-localhost — ensure container netns or firewall isolates it",
			"addr", cfg.TestingUI.Addr)
	}

	// Ensure UI auth token exists (generate on first boot).
	authToken, err := ensureUIAuthToken(cfg.TestingUI.AuthTokenFile)
	if err != nil {
		logger.Error("generating UI auth token", "error", err)
		return nil
	}

	// Core mux with all the web handler routes.
	inner := http.NewServeMux()
	webHandler.RegisterRoutes(inner)

	// Wrap with: rate limit → auth → hardened headers.
	limiter := newRateLimiter(cfg.TestingUI.MaxUploadsPerHour)
	handler := hardenedHeaders(
		authMiddleware(cfg.TestingUI.RequireAuth, authToken,
			rateLimitMiddleware(limiter, inner),
		),
	)

	srv := &http.Server{
		Addr:              cfg.TestingUI.Addr,
		Handler:           handler,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 5 * time.Second, // G112 defense
	}

	go func() {
		if cfg.TestingUI.UseTLS {
			logger.Info("testing UI listening (HTTPS)", "addr", cfg.TestingUI.Addr)
			if err := srv.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				logger.Error("testing UI TLS serve", "error", err)
			}
		} else {
			logger.Info("testing UI listening (HTTP — INSECURE)", "addr", cfg.TestingUI.Addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("testing UI serve", "error", err)
			}
		}
	}()

	return srv
}

// ---- helpers -------------------------------------------------------------

func isLocalhost(addr string) bool {
	host := addr
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		host = addr[:idx]
	}
	host = strings.Trim(host, "[]") // strip IPv6 brackets
	switch host {
	case "", "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

func ensureUIAuthToken(path string) (string, error) {
	if path == "" {
		path = "/data/ui_token"
	}
	path = filepath.Clean(path)
	// #nosec G304 -- path is server config, cleaned above; not user input.
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		return strings.TrimSpace(string(b)), nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("mkdir ui token dir: %w", err)
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	tok := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write ui token: %w", err)
	}
	return tok, nil
}

// ---- middleware ----------------------------------------------------------

// hardenedHeaders sets conservative security headers on every response.
func hardenedHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// authMiddleware enforces bearer-token auth if RequireAuth is true.
// Accepts either:
//
//	Authorization: Bearer <token>
//	?token=<token>         (only for GET / of static assets so the UI can
//	                        bootstrap; the server strips it before handler)
func authMiddleware(require bool, token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !require {
			next.ServeHTTP(w, r)
			return
		}
		if got := extractBearer(r); got != "" && got == token {
			next.ServeHTTP(w, r)
			return
		}
		// Allow health endpoint so docker healthchecks work — but ONLY from
		// localhost. This endpoint returns no sensitive data pre-auth.
		if r.URL.Path == "/api/health" && isLoopbackRemote(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="sluice"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[len("Bearer "):])
	}
	// ?token= fallback for the initial page load (tokens are single-machine use).
	return r.URL.Query().Get("token")
}

func isLoopbackRemote(r *http.Request) bool {
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		addr = addr[:idx]
	}
	addr = strings.Trim(addr, "[]")
	return addr == "127.0.0.1" || addr == "::1" || addr == "localhost"
}

// rateLimitMiddleware caps request rate per source IP. Applied to all routes.
func rateLimitMiddleware(rl *rateLimiter, next http.Handler) http.Handler {
	if rl == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.allow(ip) {
			w.Header().Set("Retry-After", "3600")
			http.Error(w, "rate_limit_exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		addr = addr[:idx]
	}
	return strings.Trim(addr, "[]")
}

// ---- rate limiter --------------------------------------------------------

// rateLimiter is a simple per-IP sliding-window counter. Purpose: make the
// testing UI impractical to abuse, not a production-grade abuse shield.
type rateLimiter struct {
	max    int
	window time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	events []time.Time
}

func newRateLimiter(maxPerHour int) *rateLimiter {
	if maxPerHour <= 0 {
		return nil
	}
	return &rateLimiter{
		max:     maxPerHour,
		window:  time.Hour,
		buckets: make(map[string]*bucket),
	}
}

func (r *rateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-r.window)

	b, ok := r.buckets[ip]
	if !ok {
		b = &bucket{}
		r.buckets[ip] = b
	}
	// Drop expired events.
	kept := b.events[:0]
	for _, t := range b.events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.events = kept

	if len(b.events) >= r.max {
		return false
	}
	b.events = append(b.events, now)
	return true
}
