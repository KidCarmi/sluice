package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
)

// EnrollmentManager handles one-time enrollment tokens for Culvert integration.
type EnrollmentManager struct {
	mu     sync.Mutex
	tokens map[string]bool // token -> consumed
	caCert []byte          // PEM
	caKey  []byte          // PEM
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
		tokens: make(map[string]bool),
		caCert: caCert,
		caKey:  caKey,
		logger: logger,
	}, nil
}

// GenerateToken creates a new one-time enrollment token.
func (m *EnrollmentManager) GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random token bytes: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(b)

	m.mu.Lock()
	m.tokens[token] = false
	m.mu.Unlock()

	m.logger.Info("enrollment token generated")
	return token, nil
}

// Enroll consumes a token and returns CA cert + client cert + client key.
// Returns error if token is invalid or already consumed.
func (m *EnrollmentManager) Enroll(token string) (caCert, clientCert, clientKey []byte, err error) {
	m.mu.Lock()
	consumed, exists := m.tokens[token]
	if !exists {
		m.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("enrollment failed: invalid token")
	}
	if consumed {
		m.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("enrollment failed: token already consumed")
	}
	m.tokens[token] = true
	m.mu.Unlock()

	clientCert, clientKey, err = GenerateClientCert(m.caCert, m.caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating client certificate during enrollment: %w", err)
	}

	m.logger.Info("enrollment completed successfully")
	return m.caCert, clientCert, clientKey, nil
}

// ValidToken checks if a token is valid and unconsumed.
func (m *EnrollmentManager) ValidToken(token string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	consumed, exists := m.tokens[token]
	return exists && !consumed
}
