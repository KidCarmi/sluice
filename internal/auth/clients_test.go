// Unit tests for the client cert ledger.
//
// Focus: correctness of the persistence layer + revocation semantics.
// These are fast (<100ms total) because they hit local tempdir only.
package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestLedger(t *testing.T) (*ClientLedger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clients.json")
	l, err := NewClientLedger(path)
	if err != nil {
		t.Fatalf("NewClientLedger: %v", err)
	}
	return l, path
}

func testRecord(fp string) ClientRecord {
	now := time.Now()
	return ClientRecord{
		Fingerprint:  fp,
		CommonName:   "Test Client",
		IssuedAtUnix: now.Unix(),
		NotAfterUnix: now.Add(365 * 24 * time.Hour).Unix(),
	}
}

// ---- Add / Get / List / ActiveCount --------------------------------------

func TestLedger_AddAndGet(t *testing.T) {
	l, _ := newTestLedger(t)
	r := testRecord("sha256:aaa")
	if err := l.Add(r); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, ok := l.Get("sha256:aaa")
	if !ok {
		t.Fatal("record not found after Add")
	}
	if got.CommonName != "Test Client" {
		t.Errorf("CommonName mismatch: %q", got.CommonName)
	}
}

func TestLedger_AddRejectsEmptyFingerprint(t *testing.T) {
	l, _ := newTestLedger(t)
	if err := l.Add(ClientRecord{}); err == nil {
		t.Fatal("expected error on empty fingerprint")
	}
}

func TestLedger_AddOverwritesSameFingerprint(t *testing.T) {
	// Renewal reuses fingerprint → each new Add should replace the record
	// rather than duplicating. (This is documented behaviour.)
	l, _ := newTestLedger(t)
	_ = l.Add(testRecord("sha256:x"))

	second := testRecord("sha256:x")
	second.CommonName = "Renamed"
	_ = l.Add(second)

	if len(l.List()) != 1 {
		t.Errorf("expected 1 record, got %d", len(l.List()))
	}
	if got, _ := l.Get("sha256:x"); got.CommonName != "Renamed" {
		t.Errorf("overwrite did not take effect: %q", got.CommonName)
	}
}

func TestLedger_GetMissing(t *testing.T) {
	l, _ := newTestLedger(t)
	if _, ok := l.Get("sha256:nope"); ok {
		t.Error("missing fingerprint must return ok=false")
	}
}

func TestLedger_List_ReturnsSnapshotCopy(t *testing.T) {
	// List must return a defensive copy — callers shouldn't be able to
	// mutate the ledger's internal state by mutating the returned slice.
	l, _ := newTestLedger(t)
	_ = l.Add(testRecord("sha256:a"))
	_ = l.Add(testRecord("sha256:b"))

	snap := l.List()
	if len(snap) != 2 {
		t.Fatalf("expected 2 records, got %d", len(snap))
	}
	snap[0].CommonName = "mutated-externally"
	// Re-read from ledger — should still show original values.
	for _, r := range l.List() {
		if r.CommonName == "mutated-externally" {
			t.Error("List() returned a reference; mutation leaked into ledger")
		}
	}
}

func TestLedger_ActiveCount(t *testing.T) {
	l, _ := newTestLedger(t)
	_ = l.Add(testRecord("sha256:a"))
	_ = l.Add(testRecord("sha256:b"))
	_ = l.Add(testRecord("sha256:c"))

	if l.ActiveCount() != 3 {
		t.Errorf("expected 3 active, got %d", l.ActiveCount())
	}

	_, _ = l.Revoke("sha256:b", "")
	if l.ActiveCount() != 2 {
		t.Errorf("expected 2 active after revoke, got %d", l.ActiveCount())
	}

	// An expired record should also not count as active.
	expired := testRecord("sha256:d")
	expired.NotAfterUnix = time.Now().Add(-time.Hour).Unix()
	_ = l.Add(expired)
	if l.ActiveCount() != 2 {
		t.Errorf("expired record should not be counted; got %d active", l.ActiveCount())
	}
}

// ---- Revoke semantics -----------------------------------------------------

func TestLedger_Revoke_ChangesFlag(t *testing.T) {
	l, _ := newTestLedger(t)
	_ = l.Add(testRecord("sha256:a"))

	changed, err := l.Revoke("sha256:a", "compromised")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !changed {
		t.Error("first revocation should return changed=true")
	}
	if !l.IsRevoked("sha256:a") {
		t.Error("IsRevoked must reflect revocation")
	}
	rec, _ := l.Get("sha256:a")
	if rec.RevokeReason != "compromised" {
		t.Errorf("reason not persisted: %q", rec.RevokeReason)
	}
}

func TestLedger_Revoke_Idempotent(t *testing.T) {
	l, _ := newTestLedger(t)
	_ = l.Add(testRecord("sha256:a"))
	_, _ = l.Revoke("sha256:a", "first")

	changed, err := l.Revoke("sha256:a", "second")
	if err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if changed {
		t.Error("repeat revoke must return changed=false")
	}
}

func TestLedger_Revoke_UnknownFingerprint(t *testing.T) {
	l, _ := newTestLedger(t)
	changed, err := l.Revoke("sha256:nope", "")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if changed {
		t.Error("revoking unknown fingerprint must return changed=false")
	}
}

func TestLedger_IsRevoked_UnknownReturnsFalse(t *testing.T) {
	// The interceptor's contract depends on this: unknown fingerprints are
	// NOT treated as revoked; the CA verification chain rejects unknown
	// certs at the TLS layer.
	l, _ := newTestLedger(t)
	if l.IsRevoked("sha256:unknown") {
		t.Error("IsRevoked on unknown fingerprint must be false")
	}
}

// ---- RevokeAll ------------------------------------------------------------

func TestLedger_RevokeAll(t *testing.T) {
	l, _ := newTestLedger(t)
	_ = l.Add(testRecord("sha256:a"))
	_ = l.Add(testRecord("sha256:b"))
	_ = l.Add(testRecord("sha256:c"))
	_, _ = l.Revoke("sha256:b", "earlier")

	n, err := l.RevokeAll("emergency")
	if err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	// Only the 2 previously-active records should be newly-revoked.
	if n != 2 {
		t.Errorf("expected 2 newly-revoked, got %d", n)
	}
	if l.ActiveCount() != 0 {
		t.Errorf("active count must be 0 after RevokeAll, got %d", l.ActiveCount())
	}
}

func TestLedger_RevokeAll_EmptyLedger_NoError(t *testing.T) {
	l, _ := newTestLedger(t)
	n, err := l.RevokeAll("nothing to do")
	if err != nil {
		t.Fatalf("RevokeAll on empty: %v", err)
	}
	if n != 0 {
		t.Errorf("empty ledger RevokeAll should return 0, got %d", n)
	}
}

// ---- Persistence ---------------------------------------------------------

func TestLedger_PersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	l1, _ := NewClientLedger(path)
	_ = l1.Add(testRecord("sha256:x"))
	_, _ = l1.Revoke("sha256:x", "test")

	l2, err := NewClientLedger(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	r, ok := l2.Get("sha256:x")
	if !ok {
		t.Fatal("record not persisted")
	}
	if !r.IsRevoked() {
		t.Error("revocation not persisted")
	}
	if r.RevokeReason != "test" {
		t.Errorf("reason not persisted: %q", r.RevokeReason)
	}
}

func TestLedger_PersistsAtomically(t *testing.T) {
	// Writing N records should result in ONE valid JSON file, never a
	// partial write. The atomic rename makes this true by construction;
	// this test simply checks the resulting file parses cleanly.
	path := filepath.Join(t.TempDir(), "clients.json")
	l, _ := NewClientLedger(path)
	for i := 0; i < 20; i++ {
		_ = l.Add(testRecord("sha256:" + string(rune('a'+i))))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var f ledgerFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("file is not valid JSON: %v", err)
	}
	if f.Version != clientsLedgerVersion {
		t.Errorf("version mismatch: %d", f.Version)
	}
	if len(f.Clients) != 20 {
		t.Errorf("expected 20 clients on disk, got %d", len(f.Clients))
	}
}

func TestLedger_MissingFile_LoadsEmpty(t *testing.T) {
	// NewClientLedger on a path that doesn't exist should succeed with an
	// empty ledger (not create the file until the first write).
	path := filepath.Join(t.TempDir(), "nonexistent", "clients.json")
	l, err := NewClientLedger(path)
	if err != nil {
		t.Fatalf("NewClientLedger: %v", err)
	}
	if l.ActiveCount() != 0 {
		t.Errorf("empty ledger should have 0 active, got %d", l.ActiveCount())
	}
}

func TestLedger_CorruptJSON_Errors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if _, err := NewClientLedger(path); err == nil {
		t.Error("expected error on corrupt ledger file")
	}
}

func TestLedger_WrongVersion_Errors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(path, []byte(`{"version":999,"clients":[]}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := NewClientLedger(path); err == nil {
		t.Error("expected error on unsupported version")
	}
}

// ---- Record helpers -------------------------------------------------------

func TestRecord_ActiveExpiredRevoked(t *testing.T) {
	now := time.Now()
	valid := ClientRecord{IssuedAtUnix: now.Unix(), NotAfterUnix: now.Add(time.Hour).Unix()}
	if !valid.Active() {
		t.Error("fresh record must be Active")
	}
	if valid.IsRevoked() {
		t.Error("fresh record must not be Revoked")
	}
	if valid.IsExpired() {
		t.Error("fresh record must not be Expired")
	}

	expired := ClientRecord{IssuedAtUnix: now.Add(-2 * time.Hour).Unix(), NotAfterUnix: now.Add(-time.Hour).Unix()}
	if !expired.IsExpired() {
		t.Error("expired record must be Expired")
	}
	if expired.Active() {
		t.Error("expired record must not be Active")
	}

	revoked := ClientRecord{
		IssuedAtUnix:  now.Unix(),
		NotAfterUnix:  now.Add(time.Hour).Unix(),
		RevokedAtUnix: now.Unix(),
	}
	if !revoked.IsRevoked() {
		t.Error("revoked record must be Revoked")
	}
	if revoked.Active() {
		t.Error("revoked record must not be Active")
	}
}
