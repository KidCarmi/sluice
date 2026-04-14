package sanitizer

import (
	"context"
	"fmt"
	"sync"
)

// Status describes the outcome of a sanitization pass.
type Status int

const (
	// StatusClean means the document contained no threats.
	StatusClean Status = iota
	// StatusSanitized means threats were found and neutralized.
	StatusSanitized
	// StatusBlocked means the document was rejected outright.
	StatusBlocked
	// StatusError means sanitization failed due to an internal error.
	StatusError
	// StatusUnsupported means the file type is not handled by any registered sanitizer.
	StatusUnsupported
)

// Threat records a single dangerous element found inside a document.
type Threat struct {
	Type        string // "macro", "ole_object", "javascript", "external_ref", "activex"
	Location    string // Where in the document the threat was found.
	Description string // Human-readable explanation.
	Severity    string // "low", "medium", "high", "critical"
}

// Result is returned by a Sanitizer after processing a document.
type Result struct {
	Status        Status
	OriginalType  FileType
	OriginalSize  int64
	SanitizedSize int64
	Threats       []Threat
	SanitizedData []byte
	Error         error
}

// Sanitizer is the interface every format-specific sanitizer must implement.
type Sanitizer interface {
	// Sanitize processes data and returns a sanitized copy together with
	// metadata about any threats that were found and removed.
	Sanitize(ctx context.Context, data []byte, filename string) (*Result, error)

	// SupportedTypes returns the set of FileType values this sanitizer
	// handles.
	SupportedTypes() []FileType
}

// Dispatcher routes incoming documents to the appropriate format-specific
// Sanitizer based on the detected file type.
type Dispatcher struct {
	mu         sync.RWMutex
	sanitizers map[FileType]Sanitizer
}

// NewDispatcher creates a ready-to-use Dispatcher.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		sanitizers: make(map[FileType]Sanitizer),
	}
}

// Register adds a Sanitizer for each of its supported file types. If a type
// was already registered the new sanitizer silently replaces the old one.
func (d *Dispatcher) Register(s Sanitizer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, ft := range s.SupportedTypes() {
		d.sanitizers[ft] = s
	}
}

// Dispatch detects the file type of data, finds the matching Sanitizer and
// delegates to it. If no sanitizer is registered for the detected type a
// Result with StatusUnsupported is returned.
func (d *Dispatcher) Dispatch(ctx context.Context, data []byte, filename string) (*Result, error) {
	ft := DetectType(data, filename)

	d.mu.RLock()
	s, ok := d.sanitizers[ft]
	d.mu.RUnlock()

	if !ok {
		return &Result{
			Status:       StatusUnsupported,
			OriginalType: ft,
			OriginalSize: int64(len(data)),
		}, fmt.Errorf("dispatch: unsupported file type %q", ft)
	}

	return s.Sanitize(ctx, data, filename)
}
