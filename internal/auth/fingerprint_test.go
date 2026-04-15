// Unit tests for the server-cert dual-pin tracker.
package auth

import (
	"testing"
	"time"
)

func TestFingerprintTracker_InitialState(t *testing.T) {
	tr := NewFingerprintTracker("sha256:current")
	if got := tr.Current(); got != "sha256:current" {
		t.Errorf("Current()=%q; want sha256:current", got)
	}
	cur, prev, until := tr.Snapshot()
	if cur != "sha256:current" {
		t.Errorf("snapshot current=%q", cur)
	}
	if prev != "" {
		t.Errorf("snapshot previous=%q; want empty", prev)
	}
	if until != 0 {
		t.Errorf("snapshot until=%d; want 0", until)
	}
}

func TestFingerprintTracker_RotateWithinGrace(t *testing.T) {
	tr := NewFingerprintTracker("sha256:old")
	tr.Rotate("sha256:new", 1*time.Hour)

	cur, prev, until := tr.Snapshot()
	if cur != "sha256:new" {
		t.Errorf("current not updated: %q", cur)
	}
	if prev != "sha256:old" {
		t.Errorf("previous not populated: %q", prev)
	}
	if until <= time.Now().Unix() {
		t.Errorf("until must be in the future: %d", until)
	}

	// Both fingerprints should be accepted during the grace window.
	if !tr.Accepts("sha256:old") {
		t.Error("old FP must be accepted during grace")
	}
	if !tr.Accepts("sha256:new") {
		t.Error("new FP must always be accepted")
	}
	if tr.Accepts("sha256:other") {
		t.Error("unrelated FP must not be accepted")
	}
}

func TestFingerprintTracker_RotateWithZeroGrace_HardCutover(t *testing.T) {
	// Grace of zero means the previous FP is dropped immediately — operators
	// use this when they want to force re-enrollment.
	tr := NewFingerprintTracker("sha256:old")
	tr.Rotate("sha256:new", 0)

	if tr.Accepts("sha256:old") {
		t.Error("old FP must NOT be accepted after zero-grace rotation")
	}
	if !tr.Accepts("sha256:new") {
		t.Error("new FP must be accepted")
	}
	_, prev, until := tr.Snapshot()
	if prev != "" || until != 0 {
		t.Errorf("snapshot should be clear after hard cutover: prev=%q until=%d", prev, until)
	}
}

func TestFingerprintTracker_RotateExpires(t *testing.T) {
	tr := NewFingerprintTracker("sha256:old")
	tr.Rotate("sha256:new", 10*time.Millisecond)

	// Within the window — old still accepted.
	if !tr.Accepts("sha256:old") {
		t.Error("old FP must be accepted before TTL expires")
	}

	time.Sleep(25 * time.Millisecond)

	if tr.Accepts("sha256:old") {
		t.Error("old FP must be rejected after TTL expires")
	}
	if !tr.Accepts("sha256:new") {
		t.Error("new FP must still be accepted after old expires")
	}

	// Snapshot should clear the previous FP once expired.
	_, prev, until := tr.Snapshot()
	if prev != "" {
		t.Errorf("snapshot previous should clear after expiry: %q", prev)
	}
	if until != 0 {
		t.Errorf("snapshot until should clear after expiry: %d", until)
	}
}

func TestFingerprintTracker_DoubleRotate_KeepsLatestOldOnly(t *testing.T) {
	// Rotate A → B → C in quick succession. The tracker only remembers ONE
	// previous fingerprint — B. A is forgotten. (Documented behaviour; if
	// Culvert needs multi-generation acceptance it should do it client-side.)
	tr := NewFingerprintTracker("sha256:A")
	tr.Rotate("sha256:B", 1*time.Hour)
	tr.Rotate("sha256:C", 1*time.Hour)

	if !tr.Accepts("sha256:C") {
		t.Error("C (current) must be accepted")
	}
	if !tr.Accepts("sha256:B") {
		t.Error("B (previous) must be accepted")
	}
	if tr.Accepts("sha256:A") {
		t.Error("A (before previous) must NOT be accepted — tracker only remembers one")
	}
}

func TestFingerprintTracker_RotateSameFingerprint_Noop(t *testing.T) {
	// Rotating to the same fingerprint shouldn't advertise a dual-pin — it's
	// a no-op rotation.
	tr := NewFingerprintTracker("sha256:same")
	tr.Rotate("sha256:same", 1*time.Hour)

	_, prev, until := tr.Snapshot()
	if prev != "" || until != 0 {
		t.Errorf("rotating to same FP must not create a dual-pin; prev=%q until=%d", prev, until)
	}
}
