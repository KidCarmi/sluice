// Client cert ledger — persists metadata about issued client certs so we can
// revoke them by fingerprint. Plain JSON on disk; the volume of records is
// bounded by the number of Culvert nodes an operator enrolls (typically <100)
// so this is fine without a real database.
//
// File layout (/data/clients.json):
//
//	{
//	  "version": 1,
//	  "clients": [
//	    { "fingerprint": "sha256:...", "name": "", "common_name": "Sluice Client",
//	      "issued_at_unix": 1713110400, "not_after_unix": 1744646400,
//	      "revoked_at_unix": 0, "revoke_reason": "" }
//	  ]
//	}
//
// name is empty in v0.2 — we don't collect a label at Enroll time. Culvert
// stores its own label locally and uses fingerprint as the correlation key.
package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const clientsLedgerVersion = 1

// ClientRecord is one row in the ledger.
type ClientRecord struct {
	Fingerprint   string `json:"fingerprint"`      // "sha256:" + hex, unique key
	Name          string `json:"name,omitempty"`   // reserved for future use
	CommonName    string `json:"common_name"`      // x509 CN at issue time
	IssuedAtUnix  int64  `json:"issued_at_unix"`   // cert NotBefore
	NotAfterUnix  int64  `json:"not_after_unix"`   // cert NotAfter
	RevokedAtUnix int64  `json:"revoked_at_unix"`  // 0 if not revoked
	RevokeReason  string `json:"revoke_reason,omitempty"`
}

// IsRevoked reports whether this record has been revoked.
func (r ClientRecord) IsRevoked() bool { return r.RevokedAtUnix > 0 }

// IsExpired reports whether the cert is past its NotAfter.
func (r ClientRecord) IsExpired() bool {
	return r.NotAfterUnix > 0 && time.Now().Unix() >= r.NotAfterUnix
}

// Active reports whether this cert is currently valid for auth: unrevoked
// and unexpired.
func (r ClientRecord) Active() bool {
	return !r.IsRevoked() && !r.IsExpired()
}

// ClientLedger is the persisted set of issued + revoked client certs. Access
// is serialized via a mutex; all mutating operations fsync to disk before
// returning so the in-memory set never diverges from /data/clients.json.
type ClientLedger struct {
	mu   sync.RWMutex
	path string

	// records is keyed by fingerprint for O(1) revocation checks. This is the
	// hot path — every mTLS RPC hits it in the interceptor.
	records map[string]ClientRecord
}

// NewClientLedger loads (or creates) the ledger at path. If the file doesn't
// exist, an empty ledger is returned and persisted on first write.
func NewClientLedger(path string) (*ClientLedger, error) {
	path = filepath.Clean(path)
	l := &ClientLedger{
		path:    path,
		records: make(map[string]ClientRecord),
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("clients ledger: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := l.load(); err != nil {
		return nil, err
	}
	return l, nil
}

// Add records a newly-issued cert. Called from Enroll + RenewCert paths.
// Fingerprint collisions overwrite (matches renewal semantics).
func (l *ClientLedger) Add(r ClientRecord) error {
	if r.Fingerprint == "" {
		return fmt.Errorf("clients ledger: empty fingerprint")
	}
	l.mu.Lock()
	l.records[r.Fingerprint] = r
	l.mu.Unlock()
	return l.save()
}

// Revoke marks a fingerprint as revoked. Returns true if the fingerprint was
// previously active (i.e. a meaningful revocation), false if unknown or
// already-revoked (idempotent behaviour the proto documents).
func (l *ClientLedger) Revoke(fingerprint, reason string) (bool, error) {
	l.mu.Lock()
	rec, ok := l.records[fingerprint]
	if !ok || rec.IsRevoked() {
		l.mu.Unlock()
		return false, nil
	}
	rec.RevokedAtUnix = time.Now().Unix()
	rec.RevokeReason = reason
	l.records[fingerprint] = rec
	l.mu.Unlock()
	return true, l.save()
}

// IsRevoked is the hot-path check called from the mTLS interceptor on every
// RPC. Read-lock only; ledger writes are rare.
func (l *ClientLedger) IsRevoked(fingerprint string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	rec, ok := l.records[fingerprint]
	if !ok {
		// Unknown certs are NOT treated as revoked here. The cert might still
		// be validly signed by our CA (e.g. after an operator restored a
		// backup). The interceptor still verifies the chain; this check only
		// vetoes KNOWN-revoked fingerprints.
		return false
	}
	return rec.IsRevoked()
}

// Get returns a copy of the record for fingerprint, or ok=false if unknown.
func (l *ClientLedger) Get(fingerprint string) (ClientRecord, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	r, ok := l.records[fingerprint]
	return r, ok
}

// List returns a snapshot of all records (copies, safe to mutate).
func (l *ClientLedger) List() []ClientRecord {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]ClientRecord, 0, len(l.records))
	for _, r := range l.records {
		out = append(out, r)
	}
	return out
}

// ActiveCount returns the number of non-revoked, non-expired records.
func (l *ClientLedger) ActiveCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	n := 0
	for _, r := range l.records {
		if r.Active() {
			n++
		}
	}
	return n
}

// RevokeAll is the CA-rotation nuke: marks every record as revoked.
// Returns the count of newly-revoked (not already-revoked) entries.
func (l *ClientLedger) RevokeAll(reason string) (int, error) {
	now := time.Now().Unix()
	l.mu.Lock()
	changed := 0
	for fp, rec := range l.records {
		if rec.IsRevoked() {
			continue
		}
		rec.RevokedAtUnix = now
		rec.RevokeReason = reason
		l.records[fp] = rec
		changed++
	}
	l.mu.Unlock()
	if changed == 0 {
		return 0, nil
	}
	return changed, l.save()
}

// ---- persistence helpers ---------------------------------------------------

type ledgerFile struct {
	Version int            `json:"version"`
	Clients []ClientRecord `json:"clients"`
}

func (l *ClientLedger) load() error {
	// #nosec G304 -- l.path is set by admin config at NewClientLedger time.
	data, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("clients ledger: read %s: %w", l.path, err)
	}
	var f ledgerFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("clients ledger: parse %s: %w", l.path, err)
	}
	if f.Version != clientsLedgerVersion {
		return fmt.Errorf("clients ledger: unsupported version %d (want %d)", f.Version, clientsLedgerVersion)
	}
	for _, r := range f.Clients {
		l.records[r.Fingerprint] = r
	}
	return nil
}

// save atomically writes the ledger: write-to-temp, fsync, rename.
// The rename is atomic on POSIX, so an interrupted save never corrupts the
// on-disk file.
func (l *ClientLedger) save() error {
	l.mu.RLock()
	snapshot := ledgerFile{
		Version: clientsLedgerVersion,
		Clients: make([]ClientRecord, 0, len(l.records)),
	}
	for _, r := range l.records {
		snapshot.Clients = append(snapshot.Clients, r)
	}
	l.mu.RUnlock()

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("clients ledger: marshal: %w", err)
	}

	tmp := l.path + ".tmp"
	// #nosec G304 -- tmp path derived from admin-provided path.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("clients ledger: open temp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("clients ledger: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("clients ledger: fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("clients ledger: close: %w", err)
	}
	if err := os.Rename(tmp, l.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("clients ledger: rename: %w", err)
	}
	return nil
}
