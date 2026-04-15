package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// sha256FingerprintDER returns the hex-encoded SHA-256 of a DER certificate.
func sha256FingerprintDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// GenerateCA creates a new self-signed CA certificate and private key.
// Returns PEM-encoded cert and key.
func GenerateCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Sluice CDR"},
			CommonName:   "Sluice CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling CA key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// GenerateClientCert creates a client certificate signed by the given CA with
// a generic "Sluice Client" common name.
func GenerateClientCert(caCertPEM, caKeyPEM []byte) (certPEM, keyPEM []byte, err error) {
	return GenerateClientCertForCN(caCertPEM, caKeyPEM, "Sluice Client")
}

// GenerateClientCertForCN creates a client certificate with a specific Common
// Name. Used by RenewClient so the renewed cert keeps the same identity as
// the presented cert.
func GenerateClientCertForCN(caCertPEM, caKeyPEM []byte, commonName string) (certPEM, keyPEM []byte, err error) {
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA material: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating client key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Sluice CDR"},
			CommonName:   commonName,
		},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("creating client certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling client key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// GenerateServerCert creates a server certificate signed by the given CA.
// Returns PEM-encoded cert and key.
func GenerateServerCert(caCertPEM, caKeyPEM []byte, hosts []string) (certPEM, keyPEM []byte, err error) {
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA material: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating server key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Sluice CDR"},
			CommonName:   "Sluice Server",
		},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("creating server certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling server key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// LoadTLSConfig creates a tls.Config for a gRPC server requiring mTLS.
// All clients MUST present a valid client cert (RequireAndVerifyClientCert).
func LoadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	return loadTLSConfig(certFile, keyFile, caFile, tls.RequireAndVerifyClientCert)
}

// LoadTLSConfigOptionalClient returns a tls.Config that verifies client certs
// when presented but does not require them. Used for gRPC servers that must
// accept both authenticated (Sanitize, Health) and unauthenticated (Enroll)
// RPCs on the same port — the per-RPC interceptor enforces auth.
func LoadTLSConfigOptionalClient(certFile, keyFile, caFile string) (*tls.Config, error) {
	return loadTLSConfig(certFile, keyFile, caFile, tls.VerifyClientCertIfGiven)
}

func loadTLSConfig(certFile, keyFile, caFile string, clientAuth tls.ClientAuthType) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading server key pair: %w", err)
	}

	caPEM, err := os.ReadFile(filepath.Clean(caFile)) // #nosec G304 -- path is from server config, not user input
	if err != nil {
		return nil, fmt.Errorf("reading CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parsing CA certificate: no valid PEM blocks found")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// BootstrapServerCerts ensures a CA and server certificate exist at the given
// paths. If any file is missing, it generates a new CA (or reuses an existing
// one), issues a fresh server cert for the provided hosts, and writes all
// three files with mode 0600. Idempotent: if everything already exists, it
// returns (caCert, serverCert) unchanged.
//
// Returns the PEM-encoded CA cert and the PEM-encoded server cert for any
// caller that needs to log fingerprints or derive the enrollment manager.
func BootstrapServerCerts(certFile, keyFile, caFile string, hosts []string) (caCertPEM, serverCertPEM []byte, err error) {
	certFile = filepath.Clean(certFile)
	keyFile = filepath.Clean(keyFile)
	caFile = filepath.Clean(caFile)

	// Ensure parent directories exist.
	for _, p := range []string{certFile, keyFile, caFile} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, nil, fmt.Errorf("creating cert directory %s: %w", filepath.Dir(p), err)
		}
	}

	// If all three files exist already, load and return.
	if fileExists(certFile) && fileExists(keyFile) && fileExists(caFile) {
		caCertPEM, err = os.ReadFile(caFile) // #nosec G304 -- admin-provided path
		if err != nil {
			return nil, nil, fmt.Errorf("reading existing CA: %w", err)
		}
		serverCertPEM, err = os.ReadFile(certFile) // #nosec G304
		if err != nil {
			return nil, nil, fmt.Errorf("reading existing server cert: %w", err)
		}
		return caCertPEM, serverCertPEM, nil
	}

	// Re-use CA if present, else mint a new one.
	var caKeyPEM []byte
	if fileExists(caFile) {
		caCertPEM, err = os.ReadFile(caFile) // #nosec G304
		if err != nil {
			return nil, nil, fmt.Errorf("reading CA cert: %w", err)
		}
		caKeyPath := caKeyPath(caFile)
		caKeyPEM, err = os.ReadFile(caKeyPath) // #nosec G304
		if err != nil {
			return nil, nil, fmt.Errorf("reading CA key %s: %w", caKeyPath, err)
		}
	} else {
		caCertPEM, caKeyPEM, err = GenerateCA()
		if err != nil {
			return nil, nil, fmt.Errorf("generating CA: %w", err)
		}
		if err := os.WriteFile(caFile, caCertPEM, 0o600); err != nil {
			return nil, nil, fmt.Errorf("writing CA cert: %w", err)
		}
		if err := os.WriteFile(caKeyPath(caFile), caKeyPEM, 0o600); err != nil {
			return nil, nil, fmt.Errorf("writing CA key: %w", err)
		}
	}

	// Generate server cert.
	serverCertPEM, serverKeyPEM, err := GenerateServerCert(caCertPEM, caKeyPEM, hosts)
	if err != nil {
		return nil, nil, fmt.Errorf("generating server cert: %w", err)
	}
	// #nosec G703 -- certFile/keyFile are already filepath.Clean'd above and
	// come from admin-provided server config (not user input).
	if err := os.WriteFile(certFile, serverCertPEM, 0o600); err != nil {
		return nil, nil, fmt.Errorf("writing server cert: %w", err)
	}
	// #nosec G703 -- keyFile is already filepath.Clean'd above.
	if err := os.WriteFile(keyFile, serverKeyPEM, 0o600); err != nil {
		return nil, nil, fmt.Errorf("writing server key: %w", err)
	}

	return caCertPEM, serverCertPEM, nil
}

// LoadCAKey reads the CA private key sibling of the CA cert file.
func LoadCAKey(caFile string) ([]byte, error) {
	return os.ReadFile(caKeyPath(filepath.Clean(caFile))) // #nosec G304 -- admin-provided path
}

func caKeyPath(caFile string) string {
	dir := filepath.Dir(caFile)
	base := filepath.Base(caFile)
	// Strip common cert extensions and append -key.pem.
	for _, ext := range []string{".pem", ".crt", ".cert"} {
		if len(base) > len(ext) && base[len(base)-len(ext):] == ext {
			base = base[:len(base)-len(ext)]
			break
		}
	}
	return filepath.Join(dir, base+"-key.pem")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// CertFingerprintSHA256 returns the SHA-256 fingerprint of a PEM-encoded
// certificate as a lowercase hex string prefixed with "sha256:". This is what
// the operator pastes into Culvert's admin UI for TOFU verification.
func CertFingerprintSHA256(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("decoding certificate: no PEM block found")
	}
	sum := sha256FingerprintDER(block.Bytes)
	return "sha256:" + sum, nil
}

// parseCA decodes PEM-encoded CA cert and key into their x509/ecdsa types.
func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("decoding CA certificate PEM: no valid block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("decoding CA key PEM: no valid block found")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA key: %w", err)
	}

	return cert, key, nil
}

// randomSerial generates a random 128-bit serial number for certificates.
func randomSerial() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialLimit)
}

// CertNotAfter decodes a PEM cert and returns its NotAfter timestamp.
// Exported because the CLI's `sluice cert expiry` needs to compute
// days-remaining without re-implementing x509 parsing.
func CertNotAfter(certPEM []byte) (time.Time, error) {
	notAfter, _, err := certValidityWindow(certPEM)
	return notAfter, err
}

// certValidityWindow decodes a PEM cert and returns its (NotAfter, NotBefore).
// Helper for RenewClient so callers don't re-parse the cert.
func certValidityWindow(certPEM []byte) (notAfter, notBefore time.Time, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("decoding certificate: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert.NotAfter, cert.NotBefore, nil
}

// CertCommonName extracts the Subject Common Name from a PEM cert.
func CertCommonName(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("decoding certificate: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing certificate: %w", err)
	}
	return cert.Subject.CommonName, nil
}

// recordIssuedCert extracts metadata from a freshly-issued PEM cert and
// appends a record to the ledger. Called from Enroll + RenewClient paths.
func recordIssuedCert(ledger *ClientLedger, certPEM []byte) error {
	fingerprint, err := CertFingerprintSHA256(certPEM)
	if err != nil {
		return fmt.Errorf("computing fingerprint: %w", err)
	}
	cn, err := CertCommonName(certPEM)
	if err != nil {
		return fmt.Errorf("reading common name: %w", err)
	}
	notAfter, notBefore, err := certValidityWindow(certPEM)
	if err != nil {
		return fmt.Errorf("reading validity window: %w", err)
	}
	return ledger.Add(ClientRecord{
		Fingerprint:  fingerprint,
		CommonName:   cn,
		IssuedAtUnix: notBefore.Unix(),
		NotAfterUnix: notAfter.Unix(),
	})
}
