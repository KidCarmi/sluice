// Tests for the public sluiceauth façade.
//
// These exercise the three functions through the exported symbols (not via
// internal/auth) so that renaming or removing a public function — even if
// the internal implementation is unchanged — triggers a test failure.
// This keeps the public API genuinely stable across minor releases.
package sluiceauth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Sluice/internal/auth"
	"github.com/KidCarmi/Sluice/pkg/sluiceauth"
)

// issueTestCert mints a CA-signed client cert so we have real PEM bytes to
// parse. Matches what a Culvert client would receive from EnrollResponse.
func issueTestCert(t *testing.T, cn string) []byte {
	t.Helper()
	caCert, caKey, err := auth.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	cert, _, err := auth.GenerateClientCertForCN(caCert, caKey, cn)
	if err != nil {
		t.Fatalf("GenerateClientCertForCN: %v", err)
	}
	return cert
}

func TestNotAfter_ReturnsApproximatelyOneYear(t *testing.T) {
	cert := issueTestCert(t, "culvert-east-01")
	expiry, err := sluiceauth.NotAfter(cert)
	if err != nil {
		t.Fatalf("NotAfter: %v", err)
	}
	// Client certs are minted with 1-year validity. Allow slop for boundary
	// conditions — we only care that "days remaining" falls in the expected
	// ballpark, not exact equality.
	days := int(time.Until(expiry) / (24 * time.Hour))
	if days < 364 || days > 366 {
		t.Errorf("days until expiry = %d; want ~365", days)
	}
}

func TestNotAfter_InvalidPEM_Errors(t *testing.T) {
	// Whatever bytes Culvert feeds in, garbage input must produce an error
	// rather than a panic or a zero-value Time.
	if _, err := sluiceauth.NotAfter([]byte("not a PEM-encoded cert")); err == nil {
		t.Error("expected error on non-PEM input")
	}
}

func TestFingerprint_Format(t *testing.T) {
	cert := issueTestCert(t, "culvert-east-01")
	fp, err := sluiceauth.Fingerprint(cert)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	// Format contract: "sha256:" + 64 lowercase hex characters. Culvert's
	// TOFU pin check is a string-equality comparison against exactly this
	// format, so drift here would silently break all pinned clients.
	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("fingerprint missing sha256: prefix: %q", fp)
	}
	const want = 7 + 64 // "sha256:" + hex
	if len(fp) != want {
		t.Errorf("fingerprint length = %d; want %d", len(fp), want)
	}
	// Lowercase-only — a Culvert pinned with "sha256:ABC..." would miss a
	// server advertising "sha256:abc..." from Health.
	if fp != strings.ToLower(fp) {
		t.Errorf("fingerprint must be lowercase: %q", fp)
	}
}

func TestFingerprint_DeterministicAcrossCalls(t *testing.T) {
	cert := issueTestCert(t, "stable-cn")
	fp1, err := sluiceauth.Fingerprint(cert)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := sluiceauth.Fingerprint(cert)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Error("Fingerprint must be deterministic for identical input")
	}
}

func TestFingerprint_DifferentCerts_DifferentFingerprints(t *testing.T) {
	a := issueTestCert(t, "a")
	b := issueTestCert(t, "b")
	fpA, _ := sluiceauth.Fingerprint(a)
	fpB, _ := sluiceauth.Fingerprint(b)
	if fpA == fpB {
		t.Error("two distinct certs produced identical fingerprints — crypto broken or test fixture reused")
	}
}

func TestFingerprint_InvalidPEM_Errors(t *testing.T) {
	if _, err := sluiceauth.Fingerprint([]byte("garbage")); err == nil {
		t.Error("expected error on non-PEM input")
	}
}

func TestCommonName_RoundTripsThroughGeneration(t *testing.T) {
	// Issue a cert with a specific CN, parse it back, confirm match.
	// This is exactly what Culvert does when it wants to display
	// "enrolled as <cn>" in the GUI.
	cn := "culvert-west-02"
	cert := issueTestCert(t, cn)
	got, err := sluiceauth.CommonName(cert)
	if err != nil {
		t.Fatalf("CommonName: %v", err)
	}
	if got != cn {
		t.Errorf("CommonName = %q; want %q", got, cn)
	}
}

func TestCommonName_InvalidPEM_Errors(t *testing.T) {
	if _, err := sluiceauth.CommonName([]byte("not a cert")); err == nil {
		t.Error("expected error on non-PEM input")
	}
}
