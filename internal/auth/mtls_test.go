package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	if len(certPEM) == 0 {
		t.Fatal("GenerateCA() returned empty cert PEM")
	}
	if len(keyPEM) == 0 {
		t.Fatal("GenerateCA() returned empty key PEM")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	if !cert.IsCA {
		t.Error("CA certificate IsCA = false, want true")
	}
	if !cert.BasicConstraintsValid {
		t.Error("CA certificate BasicConstraintsValid = false, want true")
	}
	if cert.Subject.CommonName != "Sluice CA" {
		t.Errorf("CA CommonName = %q, want %q", cert.Subject.CommonName, "Sluice CA")
	}

	// Verify the cert is self-signed.
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("CA certificate is not self-signed: %v", err)
	}
}

func TestGenerateClientCert(t *testing.T) {
	caCertPEM, caKeyPEM, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	clientCertPEM, clientKeyPEM, err := GenerateClientCert(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("GenerateClientCert() error: %v", err)
	}

	if len(clientCertPEM) == 0 {
		t.Fatal("GenerateClientCert() returned empty cert PEM")
	}
	if len(clientKeyPEM) == 0 {
		t.Fatal("GenerateClientCert() returned empty key PEM")
	}

	block, _ := pem.Decode(clientCertPEM)
	if block == nil {
		t.Fatal("failed to decode client cert PEM")
	}
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse client certificate: %v", err)
	}

	if clientCert.IsCA {
		t.Error("client certificate IsCA = true, want false")
	}
	if clientCert.Subject.CommonName != "Sluice Client" {
		t.Errorf("client CommonName = %q, want %q", clientCert.Subject.CommonName, "Sluice Client")
	}

	// Verify the client cert is signed by our CA.
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := clientCert.Verify(opts); err != nil {
		t.Errorf("client certificate not valid against CA: %v", err)
	}
}

func TestGenerateServerCert(t *testing.T) {
	caCertPEM, caKeyPEM, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	hosts := []string{"localhost", "sluice.example.com", "127.0.0.1"}
	serverCertPEM, serverKeyPEM, err := GenerateServerCert(caCertPEM, caKeyPEM, hosts)
	if err != nil {
		t.Fatalf("GenerateServerCert() error: %v", err)
	}

	if len(serverCertPEM) == 0 {
		t.Fatal("GenerateServerCert() returned empty cert PEM")
	}
	if len(serverKeyPEM) == 0 {
		t.Fatal("GenerateServerCert() returned empty key PEM")
	}

	block, _ := pem.Decode(serverCertPEM)
	if block == nil {
		t.Fatal("failed to decode server cert PEM")
	}
	serverCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse server certificate: %v", err)
	}

	// Check DNS SANs.
	wantDNS := map[string]bool{"localhost": false, "sluice.example.com": false}
	for _, name := range serverCert.DNSNames {
		if _, ok := wantDNS[name]; ok {
			wantDNS[name] = true
		}
	}
	for name, found := range wantDNS {
		if !found {
			t.Errorf("server cert missing DNS SAN %q", name)
		}
	}

	// Check IP SANs.
	foundIP := false
	for _, ip := range serverCert.IPAddresses {
		if ip.String() == "127.0.0.1" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Error("server cert missing IP SAN 127.0.0.1")
	}

	// Verify the server cert is signed by our CA.
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := serverCert.Verify(opts); err != nil {
		t.Errorf("server certificate not valid against CA for localhost: %v", err)
	}
}

func TestLoadTLSConfig(t *testing.T) {
	caCertPEM, caKeyPEM, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	serverCertPEM, serverKeyPEM, err := GenerateServerCert(caCertPEM, caKeyPEM, []string{"localhost"})
	if err != nil {
		t.Fatalf("GenerateServerCert() error: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	caFile := filepath.Join(dir, "ca.crt")

	if err := os.WriteFile(certFile, serverCertPEM, 0600); err != nil {
		t.Fatalf("writing cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, serverKeyPEM, 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	if err := os.WriteFile(caFile, caCertPEM, 0600); err != nil {
		t.Fatalf("writing CA file: %v", err)
	}

	cfg, err := LoadTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("LoadTLSConfig() error: %v", err)
	}

	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs is nil, want non-nil cert pool")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1", len(cfg.Certificates))
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want TLS 1.3 (%d)", cfg.MinVersion, tls.VersionTLS13)
	}
}

func TestLoadTLSConfig_MissingFile(t *testing.T) {
	_, err := LoadTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem", "/nonexistent/ca.pem")
	if err == nil {
		t.Fatal("LoadTLSConfig() with missing files should return error")
	}
}
