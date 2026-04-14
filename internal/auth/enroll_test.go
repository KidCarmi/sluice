package auth

import (
	"log/slog"
	"testing"
)

func newTestManager(t *testing.T) *EnrollmentManager {
	t.Helper()
	mgr, err := NewEnrollmentManager(nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewEnrollmentManager() error: %v", err)
	}
	return mgr
}

func TestGenerateToken(t *testing.T) {
	mgr := newTestManager(t)

	token1, err := mgr.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}
	if token1 == "" {
		t.Fatal("GenerateToken() returned empty token")
	}

	token2, err := mgr.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() second call error: %v", err)
	}
	if token2 == "" {
		t.Fatal("GenerateToken() second call returned empty token")
	}

	if token1 == token2 {
		t.Error("GenerateToken() produced duplicate tokens")
	}
}

func TestEnroll(t *testing.T) {
	mgr := newTestManager(t)

	token, err := mgr.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}

	caCert, clientCert, clientKey, err := mgr.Enroll(token)
	if err != nil {
		t.Fatalf("Enroll() error: %v", err)
	}

	if len(caCert) == 0 {
		t.Error("Enroll() returned empty CA cert")
	}
	if len(clientCert) == 0 {
		t.Error("Enroll() returned empty client cert")
	}
	if len(clientKey) == 0 {
		t.Error("Enroll() returned empty client key")
	}

	// Verify the returned client cert can be used with the returned CA.
	_, _, err = parseCA(caCert, mgr.caKey)
	if err != nil {
		t.Errorf("returned CA cert is not valid: %v", err)
	}
}

func TestEnrollConsumedToken(t *testing.T) {
	mgr := newTestManager(t)

	token, err := mgr.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}

	// First enrollment should succeed.
	_, _, _, err = mgr.Enroll(token)
	if err != nil {
		t.Fatalf("first Enroll() error: %v", err)
	}

	// Second enrollment with the same token should fail.
	_, _, _, err = mgr.Enroll(token)
	if err == nil {
		t.Fatal("second Enroll() with consumed token should return error")
	}
}

func TestEnrollInvalidToken(t *testing.T) {
	mgr := newTestManager(t)

	_, _, _, err := mgr.Enroll("not-a-real-token")
	if err == nil {
		t.Fatal("Enroll() with invalid token should return error")
	}
}

func TestValidToken(t *testing.T) {
	mgr := newTestManager(t)

	token, err := mgr.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}

	// Valid before consumption.
	if !mgr.ValidToken(token) {
		t.Error("ValidToken() = false before consumption, want true")
	}

	// Consume the token.
	_, _, _, err = mgr.Enroll(token)
	if err != nil {
		t.Fatalf("Enroll() error: %v", err)
	}

	// Invalid after consumption.
	if mgr.ValidToken(token) {
		t.Error("ValidToken() = true after consumption, want false")
	}

	// Invalid for unknown token.
	if mgr.ValidToken("nonexistent-token") {
		t.Error("ValidToken() = true for unknown token, want false")
	}
}

func TestNewEnrollmentManagerWithExistingCA(t *testing.T) {
	// Generate a CA to pass in.
	caCert, caKey, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	mgr, err := NewEnrollmentManager(caCert, caKey, slog.Default())
	if err != nil {
		t.Fatalf("NewEnrollmentManager() with existing CA error: %v", err)
	}

	token, err := mgr.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}

	returnedCA, _, _, err := mgr.Enroll(token)
	if err != nil {
		t.Fatalf("Enroll() error: %v", err)
	}

	// The returned CA cert should match the one we provided.
	if string(returnedCA) != string(caCert) {
		t.Error("Enroll() returned different CA cert than the one provided")
	}
}
