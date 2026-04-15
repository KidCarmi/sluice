// Package sluiceauth is a thin public façade over Sluice's cert-inspection
// helpers, intended for use by gRPC clients that consume an EnrollResponse
// or RenewCertResponse bundle and need to introspect the returned cert
// without pulling in Sluice's internal server code.
//
// The canonical implementation lives in internal/auth. This package
// re-exports only the three functions a proto client genuinely needs:
//
//	NotAfter     — the cert's expiry timestamp (for days-remaining banners)
//	Fingerprint  — SHA-256 fingerprint as "sha256:" + hex (for TOFU pinning)
//	CommonName   — the Subject CN (for node identification)
//
// Everything else — CA generation, client-cert signing, the client ledger,
// the enrollment manager, the fingerprint tracker — stays internal. It's
// server-only state and not part of any client's compat surface.
//
// This package uses ONLY Go stdlib. Safe to import from any CDR client.
//
// Backward compatibility: the three exported functions ship with v0.2.1
// and won't break across the v0.x train. If we need a wider API we'll
// add new functions here; we won't change the signature of these three.
package sluiceauth

import (
	"time"

	"github.com/KidCarmi/Sluice/internal/auth"
)

// NotAfter parses a PEM-encoded x509 certificate and returns its NotAfter
// timestamp. Use it on the client_cert field of EnrollResponse or
// RenewCertResponse to render "cert expires in N days" banners.
//
//	exp, err := sluiceauth.NotAfter(resp.ClientCert)
//	if err == nil {
//	    daysLeft := time.Until(exp) / (24 * time.Hour)
//	}
func NotAfter(certPEM []byte) (time.Time, error) {
	return auth.CertNotAfter(certPEM)
}

// Fingerprint returns the SHA-256 fingerprint of a PEM-encoded certificate
// as a lowercase hex string prefixed with "sha256:". Format matches what
// Sluice emits via `sluice fingerprint` and HealthResponse.server_fingerprint,
// so string equality is the correct comparison for TOFU pinning.
//
//	fp, err := sluiceauth.Fingerprint(resp.CaCert)
//	if fp != operatorProvidedFingerprint {
//	    // TOFU mismatch — refuse to enroll
//	}
func Fingerprint(certPEM []byte) (string, error) {
	return auth.CertFingerprintSHA256(certPEM)
}

// CommonName returns the Subject Common Name from a PEM-encoded certificate.
// Useful for dashboards that want to display "enrolled as <name>" where
// <name> is the CN Culvert's client supplied when it renewed (or the
// default "Sluice Client" from initial Enroll).
func CommonName(certPEM []byte) (string, error) {
	return auth.CertCommonName(certPEM)
}
