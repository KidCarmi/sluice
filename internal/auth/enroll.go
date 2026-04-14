package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// defaultTokenTTL is the time a newly-issued enrollment token remains valid
// before it is silently rejected on use.
const defaultTokenTTL = 24 * time.Hour

// tokenEntry is an internal record of a pending (un-consumed) enrollment token.
// Tokens are stored as SHA-256 hashes — plaintext is never persisted in memory
// after GenerateToken returns.
type tokenEntry struct {
	issuedAt time.Time
	ttl      time.Duration
}

// EnrollmentManager handles one-time enrollment tokens for Culvert integration.
// Tokens are stored as SHA-256 hashes at rest with a TTL (default 24h).
// Tokens are single-use: on successful Enroll, the entry is removed.
type EnrollmentManager struct {
	mu     sync.Mutex
	tokens map[string]tokenEntry // sha256-hex -> entry
	caCert []byte                // PEM
	caKey  []byte                // PEM
	ttl    time.Duration
	logger *slog.Logger
}

// NewEnrollmentManager creates a manager. If caCert/caKey are nil, it generates a new CA.
func NewEnrollmentManager(caCert, caKey []byte, logger *slog.Logger) (*EnrollmentManager, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if caCert == nil || caKey == nil {
		var err error
		caCert, caKey, err = GenerateCA()
		if err != nil {
			return nil, fmt.Errorf("generating CA for enrollment manager: %w", err)
		}
		logger.Info("generated new CA for enrollment")
	}

	return &EnrollmentManager{
		tokens: make(map[string]tokenEntry),
		caCert: caCert,
		caKey:  caKey,
		ttl:    defaultTokenTTL,
		logger: logger,
	}, nil
}

// SetTTL overrides the token time-to-live. Must be > 0.
func (m *EnrollmentManager) SetTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	m.mu.Lock()
	m.ttl = ttl
	m.mu.Unlock()
}

// CACert returns the PEM-encoded CA certificate used to sign enrolled clients.
func (m *EnrollmentManager) CACert() []byte {
	return m.caCert
}

// CAKey returns the PEM-encoded CA private key. Handle with care.
func (m *EnrollmentManager) CAKey() []byte {
	return m.caKey
}

// hashToken returns the hex-encoded SHA-256 of a plaintext token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// GenerateToken creates a new one-time enrollment token. Returns the plaintext
// token to the caller (the only time it's visible) and stores only the hash.
func (m *EnrollmentManager) GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random token bytes: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(b)
	h := hashToken(token)

	m.mu.Lock()
	m.tokens[h] = tokenEntry{issuedAt: time.Now(), ttl: m.ttl}
	m.mu.Unlock()

	m.logger.Info("enrollment token generated")
	return token, nil
}

// RevokeAll clears every outstanding token (emergency rotation).
func (m *EnrollmentManager) RevokeAll() {
	m.mu.Lock()
	m.tokens = make(map[string]tokenEntry)
	m.mu.Unlock()
	m.logger.Info("all enrollment tokens revoked")
}

// Enroll consumes a token and returns CA cert + client cert + client key.
// Returns an error if the token is invalid, consumed, or expired.
// Successful enrollment removes the token entry (consume-and-delete).
func (m *EnrollmentManager) Enroll(token string) (caCert, clientCert, clientKey []byte, err error) {
	h := hashToken(token)

	m.mu.Lock()
	entry, exists := m.tokens[h]
	if !exists {
		m.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("enrollment failed: invalid token")
	}
	if time.Since(entry.issuedAt) > entry.ttl {
		delete(m.tokens, h)
		m.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("enrollment failed: token expired")
	}
	delete(m.tokens, h) // consume-and-delete
	m.mu.Unlock()

	clientCert, clientKey, err = GenerateClientCert(m.caCert, m.caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating client certificate during enrollment: %w", err)
	}

	m.logger.Info("enrollment completed successfully")
	return m.caCert, clientCert, clientKey, nil
}

// ValidToken reports whether a plaintext token is known and unconsumed (and unexpired).
func (m *EnrollmentManager) ValidToken(token string) bool {
	h := hashToken(token)
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.tokens[h]
	if !exists {
		return false
	}
	return time.Since(entry.issuedAt) <= entry.ttl
}

// Count returns the number of currently-valid tokens (for telemetry).
func (m *EnrollmentManager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.tokens {
		if time.Since(e.issuedAt) <= e.ttl {
			n++
		}
	}
	return n
}
