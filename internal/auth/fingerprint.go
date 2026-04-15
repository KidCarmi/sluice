// FingerprintTracker keeps the current server cert fingerprint plus an
// optional "rotated-out" fingerprint that clients should continue to accept
// during a migration grace window. This lets an operator swap the server
// cert without forcing every Culvert node to re-enroll.
//
// The tracker is in-memory only. On daemon restart the rotated fingerprint
// (if any) is lost — operators should complete rotations before restarting,
// or bake a grace window long enough to outlast a restart. In practice the
// default 24h grace and typical restart times make this a non-issue.
package auth

import (
	"sync"
	"time"
)

// FingerprintTracker is concurrency-safe.
type FingerprintTracker struct {
	mu          sync.RWMutex
	current     string
	previous    string
	previousTTL time.Time // zero = no rotation active
}

// NewFingerprintTracker creates a tracker with a single current fingerprint.
func NewFingerprintTracker(current string) *FingerprintTracker {
	return &FingerprintTracker{current: current}
}

// Current returns the current server cert fingerprint.
func (t *FingerprintTracker) Current() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.current
}

// Snapshot returns the current fingerprint, the rotated-out previous
// fingerprint (or empty string), and the unix timestamp at which the
// previous fingerprint stops being acceptable (0 = no active rotation).
//
// Callers handling Health responses should use Snapshot; callers handling
// TLS verification should use Accepts.
func (t *FingerprintTracker) Snapshot() (current, previous string, previousUntilUnix int64) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.previousTTL.IsZero() || time.Now().After(t.previousTTL) {
		return t.current, "", 0
	}
	return t.current, t.previous, t.previousTTL.Unix()
}

// Accepts reports whether fp (sha256:... hex) matches EITHER the current
// fingerprint OR the rotated-out previous fingerprint during its grace
// window. Used by any code path that needs to verify a pinned fingerprint
// (nothing on the server uses this today, but the helper is here for
// symmetry with what Culvert's client implements).
func (t *FingerprintTracker) Accepts(fp string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if fp == t.current {
		return true
	}
	if t.previous != "" && fp == t.previous && !t.previousTTL.IsZero() && time.Now().Before(t.previousTTL) {
		return true
	}
	return false
}

// Rotate records a new current fingerprint and keeps the old one acceptable
// for `grace`. Passing grace <= 0 drops the previous fingerprint immediately
// (hard cutover — forces re-enrollment).
func (t *FingerprintTracker) Rotate(newCurrent string, grace time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	oldCurrent := t.current
	t.current = newCurrent
	if grace > 0 && oldCurrent != "" && oldCurrent != newCurrent {
		t.previous = oldCurrent
		t.previousTTL = time.Now().Add(grace)
	} else {
		t.previous = ""
		t.previousTTL = time.Time{}
	}
}
