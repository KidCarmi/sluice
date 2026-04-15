// Unit tests for the v0.2 additions in enroll.go + mtls.go:
// - GenerateClientCertForCN preserves CommonName
// - CertCommonName + CertFingerprintSHA256 parse PEM correctly
// - BootstrapServerCerts is idempotent
// - EnrollmentManager.RenewClient mints fresh cert, records in ledger
// - EnrollmentManager.Enroll records issued certs when a ledger is wired
// - RevokeAll clears pending enrollment tokens
package auth

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ---- GenerateClientCertForCN ---------------------------------------------

func TestGenerateClientCertForCN_PreservesCommonName(t *testing.T) {
	caCert, caKey, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	certPEM, _, err := GenerateClientCertForCN(caCert, caKey, "custom-node-01")
	if err != nil {
		t.Fatalf("GenerateClientCertForCN: %v", err)
	}
	cn, err := CertCommonName(certPEM)
	if err != nil {
		t.Fatalf("CertCommonName: %v", err)
	}
	if cn != "custom-node-01" {
		t.Errorf("CN not preserved: %q", cn)
	}
}

func TestGenerateClientCert_UsesDefaultCN(t *testing.T) {
	caCert, caKey, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	certPEM, _, err := GenerateClientCert(caCert, caKey)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}
	cn, err := CertCommonName(certPEM)
	if err != nil {
		t.Fatalf("CertCommonName: %v", err)
	}
	if cn != "Sluice Client" {
		t.Errorf("default CN wrong: %q", cn)
	}
}

// ---- Cert inspection helpers ---------------------------------------------

func TestCertCommonName_InvalidPEM(t *testing.T) {
	if _, err := CertCommonName([]byte("not a PEM block")); err == nil {
		t.Error("expected error on garbage input")
	}
}

func TestCertFingerprintSHA256_DeterministicAndPrefixed(t *testing.T) {
	caCert, _, _ := GenerateCA()
	fp1, err := CertFingerprintSHA256(caCert)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	fp2, _ := CertFingerprintSHA256(caCert)
	if fp1 != fp2 {
		t.Error("fingerprint must be deterministic")
	}
	if len(fp1) < 10 || fp1[:7] != "sha256:" {
		t.Errorf("fingerprint must be prefixed sha256:, got %q", fp1)
	}
}

func TestCertFingerprintSHA256_InvalidPEM(t *testing.T) {
	if _, err := CertFingerprintSHA256([]byte("garbage")); err == nil {
		t.Error("expected error on non-PEM input")
	}
}

// ---- BootstrapServerCerts ------------------------------------------------

func TestBootstrap_CreatesAllFilesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.pem")
	keyFile := filepath.Join(dir, "server-key.pem")
	caFile := filepath.Join(dir, "ca.pem")

	caPEM, serverPEM, err := BootstrapServerCerts(certFile, keyFile, caFile, []string{"localhost"})
	if err != nil {
		t.Fatalf("BootstrapServerCerts: %v", err)
	}
	if len(caPEM) == 0 || len(serverPEM) == 0 {
		t.Fatal("empty PEM returned")
	}

	// All three files must exist on disk with mode 0600.
	for _, p := range []string{certFile, keyFile, caFile} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v; want 0600", p, info.Mode().Perm())
		}
	}
	// CA key should also exist alongside.
	if _, err := os.Stat(caKeyPath(caFile)); err != nil {
		t.Errorf("CA key not written: %v", err)
	}
}

func TestBootstrap_Idempotent(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.pem")
	keyFile := filepath.Join(dir, "server-key.pem")
	caFile := filepath.Join(dir, "ca.pem")

	ca1, srv1, err := BootstrapServerCerts(certFile, keyFile, caFile, []string{"localhost"})
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	ca2, srv2, err := BootstrapServerCerts(certFile, keyFile, caFile, []string{"localhost"})
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	// Both calls must return byte-identical material — no regeneration on
	// repeat calls.
	if string(ca1) != string(ca2) {
		t.Error("CA regenerated on idempotent call")
	}
	if string(srv1) != string(srv2) {
		t.Error("server cert regenerated on idempotent call")
	}
}

func TestBootstrap_ReusesExistingCA_MintsFreshServerCert(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.pem")
	keyFile := filepath.Join(dir, "server-key.pem")
	caFile := filepath.Join(dir, "ca.pem")

	// First call: mints CA + server.
	caFirst, srvFirst, err := BootstrapServerCerts(certFile, keyFile, caFile, []string{"localhost"})
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	// Delete the server cert to simulate `sluice cert server-rotate`.
	if err := os.Remove(certFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	// Second call: CA present → reused; server cert missing → minted fresh.
	caSecond, srvSecond, err := BootstrapServerCerts(certFile, keyFile, caFile, []string{"localhost"})
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if string(caFirst) != string(caSecond) {
		t.Error("CA must be reused; got a fresh one")
	}
	if string(srvFirst) == string(srvSecond) {
		t.Error("server cert should be fresh after deletion; got the same bytes back")
	}
}

func TestLoadCAKey(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.pem")
	keyFile := filepath.Join(dir, "server-key.pem")
	caFile := filepath.Join(dir, "ca.pem")

	if _, _, err := BootstrapServerCerts(certFile, keyFile, caFile, []string{"localhost"}); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	keyPEM, err := LoadCAKey(caFile)
	if err != nil {
		t.Fatalf("LoadCAKey: %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("CA key not valid PEM")
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
		t.Errorf("CA key not parseable: %v", err)
	}
}

// ---- EnrollmentManager.RenewClient ---------------------------------------

func TestRenewClient_MintsFreshCert_RecordsInLedger(t *testing.T) {
	m, err := NewEnrollmentManager(nil, nil, silentLogger())
	if err != nil {
		t.Fatalf("NewEnrollmentManager: %v", err)
	}
	ledger, _ := NewClientLedger(filepath.Join(t.TempDir(), "clients.json"))
	m.SetLedger(ledger)

	cert, key, notAfter, err := m.RenewClient("culvert-us-east-01")
	if err != nil {
		t.Fatalf("RenewClient: %v", err)
	}
	if len(cert) == 0 || len(key) == 0 {
		t.Fatal("empty cert/key returned")
	}
	if time.Until(notAfter) < 360*24*time.Hour {
		t.Errorf("notAfter too soon: %v", notAfter)
	}
	// Record must show up in ledger with the correct CN.
	fp, _ := CertFingerprintSHA256(cert)
	rec, ok := ledger.Get(fp)
	if !ok {
		t.Fatal("ledger did not record the renewed cert")
	}
	if rec.CommonName != "culvert-us-east-01" {
		t.Errorf("ledger CN wrong: %q", rec.CommonName)
	}
}

func TestRenewClient_EmptyCN_Rejected(t *testing.T) {
	m, _ := NewEnrollmentManager(nil, nil, silentLogger())
	_, _, _, err := m.RenewClient("")
	if err == nil {
		t.Fatal("expected error for empty CN")
	}
}

func TestRenewClient_NoLedger_StillSucceeds(t *testing.T) {
	// Ledger is optional — missing it just skips the record step.
	m, _ := NewEnrollmentManager(nil, nil, silentLogger())
	cert, key, _, err := m.RenewClient("whatever")
	if err != nil {
		t.Fatalf("RenewClient without ledger: %v", err)
	}
	if len(cert) == 0 || len(key) == 0 {
		t.Fatal("empty cert/key")
	}
}

// ---- EnrollmentManager.Enroll with ledger --------------------------------

func TestEnroll_RecordsIssuedCertInLedger(t *testing.T) {
	m, _ := NewEnrollmentManager(nil, nil, silentLogger())
	ledger, _ := NewClientLedger(filepath.Join(t.TempDir(), "clients.json"))
	m.SetLedger(ledger)

	token, _ := m.GenerateToken()
	_, cert, _, err := m.Enroll(token)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	fp, _ := CertFingerprintSHA256(cert)
	if _, ok := ledger.Get(fp); !ok {
		t.Error("enrollment did not record cert in ledger")
	}
}

// ---- EnrollmentManager.RevokeAll (tokens) --------------------------------

func TestEnrollmentManager_RevokeAll_ClearsPendingTokens(t *testing.T) {
	m, _ := NewEnrollmentManager(nil, nil, silentLogger())
	_, _ = m.GenerateToken()
	_, _ = m.GenerateToken()
	_, _ = m.GenerateToken()
	if m.Count() != 3 {
		t.Fatalf("setup: expected 3 tokens, got %d", m.Count())
	}

	m.RevokeAll()

	if m.Count() != 0 {
		t.Errorf("RevokeAll should clear all tokens, got %d", m.Count())
	}
}

// ---- TTL semantics ------------------------------------------------------

func TestEnroll_ExpiredToken_Rejected(t *testing.T) {
	m, _ := NewEnrollmentManager(nil, nil, silentLogger())
	m.SetTTL(10 * time.Millisecond)

	token, _ := m.GenerateToken()
	time.Sleep(25 * time.Millisecond)

	_, _, _, err := m.Enroll(token)
	if err == nil {
		t.Fatal("expected expired-token error")
	}
}

func TestValidToken_ExpiredReturnsFalse(t *testing.T) {
	m, _ := NewEnrollmentManager(nil, nil, silentLogger())
	m.SetTTL(10 * time.Millisecond)

	token, _ := m.GenerateToken()
	if !m.ValidToken(token) {
		t.Error("fresh token must be valid")
	}
	time.Sleep(25 * time.Millisecond)
	if m.ValidToken(token) {
		t.Error("expired token must be invalid")
	}
}

func TestEnrollmentManager_CACertCAKey_Accessors(t *testing.T) {
	m, err := NewEnrollmentManager(nil, nil, silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.CACert()) == 0 {
		t.Error("CACert() empty")
	}
	if len(m.CAKey()) == 0 {
		t.Error("CAKey() empty")
	}
	if m.Ledger() != nil {
		t.Error("Ledger() must be nil before SetLedger")
	}
	l, _ := NewClientLedger(filepath.Join(t.TempDir(), "c.json"))
	m.SetLedger(l)
	if m.Ledger() != l {
		t.Error("Ledger() must return the wired ledger")
	}
}

func TestSetTTL_RejectsNonPositive(t *testing.T) {
	m, _ := NewEnrollmentManager(nil, nil, silentLogger())
	m.SetTTL(-1 * time.Hour) // should silently ignore
	// Generate + immediately validate — if TTL had been set to -1h every
	// token would appear expired.
	token, _ := m.GenerateToken()
	if !m.ValidToken(token) {
		t.Error("SetTTL(<=0) must be a no-op, not corrupt existing TTL")
	}
}
