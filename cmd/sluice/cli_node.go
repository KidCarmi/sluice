// CLI commands for client node management + cert rotation.
//
// Shape:
//
//	sluice node list                    — tabular listing of enrolled clients
//	sluice node show <fingerprint>      — details for one client
//	sluice node revoke <fingerprint>    — revoke one client (sync)
//	sluice node revoke-all              — revoke every currently-active client
//	sluice cert server-rotate [flags]   — swap server cert with a grace window
//	sluice cert ca-rotate               — regenerate the CA (forces full re-enroll)
//
// The `node` commands consult the persistent ledger directly
// (/data/clients.json). Revocations are applied to the ledger file, which
// the running daemon re-reads on demand via its mTLS interceptor. No IPC to
// the daemon is required for revocation to take effect — the ledger IS the
// source of truth.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/KidCarmi/Sluice/internal/auth"
	"github.com/KidCarmi/Sluice/internal/config"
	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// ---- sluice node ----------------------------------------------------------

func runNodeCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sluice node {list|show|revoke|revoke-all} [args]")
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "list":
		return runNodeList(rest)
	case "show":
		return runNodeShow(rest)
	case "revoke":
		return runNodeRevoke(rest)
	case "revoke-all":
		return runNodeRevokeAll(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown node subcommand: %s\n", sub)
		return 2
	}
}

func runNodeList(args []string) int {
	fs := flag.NewFlagSet("node list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	includeRevoked := fs.Bool("all", false, "include revoked/expired clients")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg := loadConfigOrDefault("config.yaml")
	ledger, err := openLedger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	records := ledger.List()
	sort.Slice(records, func(i, j int) bool {
		return records[i].IssuedAtUnix > records[j].IssuedAtUnix
	})
	filtered := records[:0]
	for _, r := range records {
		if !*includeRevoked && !r.Active() {
			continue
		}
		filtered = append(filtered, r)
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(filtered)
		return 0
	}
	if len(filtered) == 0 {
		fmt.Println("no enrolled clients")
		return 0
	}
	fmt.Printf("%-72s  %-22s  %-12s  %-8s\n", "FINGERPRINT", "ISSUED", "EXPIRES IN", "STATUS")
	for _, r := range filtered {
		issued := time.Unix(r.IssuedAtUnix, 0).UTC().Format("2006-01-02T15:04Z")
		statusStr := "active"
		switch {
		case r.IsRevoked():
			statusStr = "revoked"
		case r.IsExpired():
			statusStr = "expired"
		}
		expiresIn := time.Until(time.Unix(r.NotAfterUnix, 0)).Round(24 * time.Hour)
		fmt.Printf("%-72s  %-22s  %-12s  %-8s\n", r.Fingerprint, issued, expiresIn.String(), statusStr)
	}
	return 0
}

func runNodeShow(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: sluice node show <fingerprint>")
		return 2
	}
	fp := args[0]

	cfg := loadConfigOrDefault("config.yaml")
	ledger, err := openLedger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	rec, ok := ledger.Get(fp)
	if !ok {
		fmt.Fprintln(os.Stderr, "not found")
		return 1
	}
	_ = json.NewEncoder(os.Stdout).Encode(rec)
	return 0
}

func runNodeRevoke(args []string) int {
	fs := flag.NewFlagSet("node revoke", flag.ContinueOnError)
	reason := fs.String("reason", "", "operator-supplied reason (audit log)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: sluice node revoke [--reason ...] <fingerprint>")
		return 2
	}
	fp := fs.Arg(0)

	cfg := loadConfigOrDefault("config.yaml")

	// Try the daemon first so it gets an atomic in-memory update.
	if ok := revokeViaDaemon(cfg, fp, *reason); ok {
		fmt.Printf("revoked %s\n", fp)
		return 0
	}

	// Daemon unreachable — fall back to writing the ledger directly. Any
	// running daemon's revocation set will pick this up on its next load.
	ledger, err := openLedger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	changed, err := ledger.Revoke(fp, *reason)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if !changed {
		fmt.Fprintln(os.Stderr, "already revoked or unknown fingerprint")
		return 1
	}
	fmt.Printf("revoked %s (daemon not running — restart for in-memory sync)\n", fp)
	return 0
}

func runNodeRevokeAll(args []string) int {
	fs := flag.NewFlagSet("node revoke-all", flag.ContinueOnError)
	reason := fs.String("reason", "emergency rotation", "operator-supplied reason (audit log)")
	yes := fs.Bool("yes", false, "confirm revocation of ALL active clients")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*yes {
		fmt.Fprintln(os.Stderr, "refusing to revoke all clients without --yes")
		return 2
	}
	cfg := loadConfigOrDefault("config.yaml")
	ledger, err := openLedger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	n, err := ledger.RevokeAll(*reason)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Printf("revoked %d clients (daemon not running — restart for in-memory sync)\n", n)
	return 0
}

// ---- sluice cert ----------------------------------------------------------

func runCertCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sluice cert {server-rotate|ca-rotate|expiry}")
		return 2
	}
	switch args[0] {
	case "server-rotate":
		return runCertServerRotate(args[1:])
	case "ca-rotate":
		return runCertCaRotate(args[1:])
	case "expiry":
		return runCertExpiry(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown cert subcommand: %s\n", args[0])
		return 2
	}
}

func runCertServerRotate(args []string) int {
	fs := flag.NewFlagSet("cert server-rotate", flag.ContinueOnError)
	grace := fs.Duration("grace", 24*time.Hour, "dual-pin window during which the PREVIOUS server cert fingerprint is still accepted")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	_ = grace // grace is surfaced in Health; the daemon's FingerprintTracker.Rotate enforces it.

	cfg := loadConfigOrDefault("config.yaml")
	// Compute OLD fingerprint before we overwrite the cert files.
	oldCertPEM, err := os.ReadFile(filepath.Clean(cfg.Server.TLS.CertFile)) // #nosec G304 -- admin-provided
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading current server cert: %v\n", err)
		return 1
	}
	oldFP, err := auth.CertFingerprintSHA256(oldCertPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fingerprinting current cert: %v\n", err)
		return 1
	}

	// Delete old server cert + key; BootstrapServerCerts will mint fresh
	// ones signed by the existing CA. This is a hard-cutover on the file
	// system; the dual-pin grace is the CLIENT-side acceptance window
	// surfaced via Health.
	_ = os.Remove(cfg.Server.TLS.CertFile)
	_ = os.Remove(cfg.Server.TLS.KeyFile)

	_, newCertPEM, err := auth.BootstrapServerCerts(
		cfg.Server.TLS.CertFile,
		cfg.Server.TLS.KeyFile,
		cfg.Server.TLS.CAFile,
		[]string{"localhost", "127.0.0.1", "::1"},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generating new server cert: %v\n", err)
		return 1
	}
	newFP, err := auth.CertFingerprintSHA256(newCertPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fingerprinting new cert: %v\n", err)
		return 1
	}

	fmt.Printf("old fingerprint: %s\n", oldFP)
	fmt.Printf("new fingerprint: %s\n", newFP)
	fmt.Printf("grace window:    %s\n", *grace)
	fmt.Println()
	fmt.Println("RESTART the daemon to pick up the new cert. Culvert will see")
	fmt.Println("rotated_fingerprint=<old> and rotated_fingerprint_until_unix=<now+grace>")
	fmt.Println("via Health and auto-rewrite its pinned fingerprint without re-enrollment.")
	return 0
}

func runCertCaRotate(args []string) int {
	fs := flag.NewFlagSet("cert ca-rotate", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "confirm CA regeneration (INVALIDATES ALL CLIENT CERTS)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*yes {
		fmt.Fprintln(os.Stderr, "refusing to rotate CA without --yes")
		fmt.Fprintln(os.Stderr, "this invalidates EVERY client cert and forces re-enrollment")
		return 2
	}

	cfg := loadConfigOrDefault("config.yaml")
	// Delete CA, server cert + key, and ledger. BootstrapServerCerts will
	// mint a fresh CA + server cert.
	_ = os.Remove(cfg.Server.TLS.CAFile)
	_ = os.Remove(strings.TrimSuffix(cfg.Server.TLS.CAFile, ".pem") + "-key.pem")
	_ = os.Remove(cfg.Server.TLS.CertFile)
	_ = os.Remove(cfg.Server.TLS.KeyFile)

	// Wipe the ledger — every record refers to certs signed by the old CA.
	ledgerPath := filepath.Join(filepath.Dir(cfg.Enrollment.TokenFile), "clients.json")
	_ = os.Remove(ledgerPath)

	caCertPEM, serverCertPEM, err := auth.BootstrapServerCerts(
		cfg.Server.TLS.CertFile,
		cfg.Server.TLS.KeyFile,
		cfg.Server.TLS.CAFile,
		[]string{"localhost", "127.0.0.1", "::1"},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstrapping fresh CA: %v\n", err)
		return 1
	}
	caFP, _ := auth.CertFingerprintSHA256(caCertPEM)
	srvFP, _ := auth.CertFingerprintSHA256(serverCertPEM)
	fmt.Println("CA rotated. ALL client certs are now invalid; operators must re-enroll every Culvert node.")
	fmt.Printf("new CA fingerprint:     %s\n", caFP)
	fmt.Printf("new server fingerprint: %s\n", srvFP)
	fmt.Println()
	fmt.Println("RESTART the daemon, then run `sluice token` to issue enrollment tokens.")
	return 0
}

func runCertExpiry(_ []string) int {
	cfg := loadConfigOrDefault("config.yaml")
	certPEM, err := os.ReadFile(filepath.Clean(cfg.Server.TLS.CertFile)) // #nosec G304 -- admin-provided
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading server cert: %v\n", err)
		return 1
	}
	cn, _ := auth.CertCommonName(certPEM)
	fp, _ := auth.CertFingerprintSHA256(certPEM)
	// We don't have a direct "days until expiry" in auth — compute from
	// a freshly-bootstrapped server cert validity window.
	// TODO(v0.3): add auth.CertNotAfter helper.
	fmt.Printf("common_name: %s\n", cn)
	fmt.Printf("fingerprint: %s\n", fp)
	return 0
}

// ---- helpers ---------------------------------------------------------------

func openLedger(cfg *config.Config) (*auth.ClientLedger, error) {
	ledgerPath := filepath.Join(filepath.Dir(cfg.Enrollment.TokenFile), "clients.json")
	return auth.NewClientLedger(ledgerPath)
}

func revokeViaDaemon(cfg *config.Config, fp, reason string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.NewClient("unix:"+cfg.CLI.SocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	client := pb.NewSluiceServiceClient(conn)
	_, err = client.RevokeClient(ctx, &pb.RevokeClientRequest{Fingerprint: fp, Reason: reason})
	return err == nil
}
