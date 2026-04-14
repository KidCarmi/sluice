// Thin wrappers around internal/auth used by the CLI subcommands.
// Keeping these here avoids having cli.go hard-depend on the auth package
// directly and makes unit-testing the CLI layer easier.
package main

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/KidCarmi/Sluice/internal/auth"
	"github.com/KidCarmi/Sluice/internal/config"
)

func authBootstrap(cfg *config.Config) (caCertPEM, serverCertPEM []byte, err error) {
	return auth.BootstrapServerCerts(
		cfg.Server.TLS.CertFile,
		cfg.Server.TLS.KeyFile,
		cfg.Server.TLS.CAFile,
		[]string{"localhost", "127.0.0.1", "::1"},
	)
}

func authFingerprint(certPEM []byte) (string, error) {
	return auth.CertFingerprintSHA256(certPEM)
}

// authMintToken generates a new token. It's a thin wrapper so the CLI can
// work without a running daemon. The token itself is written to the token
// file by the caller; we don't persist it here.
//
// NOTE: This path does not register the token in any running daemon's
// in-memory map. Operators using `sluice token` while the daemon is running
// should restart the daemon so it picks up the new token; or more cleanly,
// the daemon reads the token file on startup (first-boot token path).
func authMintToken(cfg *config.Config) (string, error) {
	_ = cfg
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
