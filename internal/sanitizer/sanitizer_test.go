package sanitizer

import (
	"context"
	"testing"
)

// mockSanitizer is a trivial Sanitizer used to verify Dispatcher routing.
type mockSanitizer struct {
	types  []FileType
	called bool
}

func (m *mockSanitizer) Sanitize(_ context.Context, data []byte, _ string) (*Result, error) {
	m.called = true
	return &Result{
		Status:        StatusClean,
		OriginalType:  m.types[0],
		OriginalSize:  int64(len(data)),
		SanitizedSize: int64(len(data)),
		SanitizedData: data,
	}, nil
}

func (m *mockSanitizer) SupportedTypes() []FileType {
	return m.types
}

func TestDispatcher_Unsupported(t *testing.T) {
	d := NewDispatcher()
	res, err := d.Dispatch(context.Background(), []byte("random bytes"), "file.xyz")
	if err == nil {
		t.Fatal("expected error for unsupported type, got nil")
	}
	if res.Status != StatusUnsupported {
		t.Errorf("expected StatusUnsupported (%d), got %d", StatusUnsupported, res.Status)
	}
}

func TestDispatcher_RegisterAndDispatch_PDF(t *testing.T) {
	d := NewDispatcher()
	mock := &mockSanitizer{types: []FileType{FileTypePDF}}
	d.Register(mock)

	pdfData := []byte("%PDF-1.4 fake body")
	res, err := d.Dispatch(context.Background(), pdfData, "test.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.called {
		t.Error("mock sanitizer was not called")
	}
	if res.Status != StatusClean {
		t.Errorf("expected StatusClean, got %d", res.Status)
	}
	if res.OriginalType != FileTypePDF {
		t.Errorf("expected OriginalType %q, got %q", FileTypePDF, res.OriginalType)
	}
	if res.OriginalSize != int64(len(pdfData)) {
		t.Errorf("expected OriginalSize %d, got %d", len(pdfData), res.OriginalSize)
	}
}

func TestDispatcher_RegisterMultipleTypes(t *testing.T) {
	d := NewDispatcher()
	mock := &mockSanitizer{types: []FileType{FileTypeDOCX, FileTypeXLSX}}
	d.Register(mock)

	// Dispatch a DOCX-like file by extension (header is not a known magic
	// sequence, so extension fallback kicks in).
	res, err := d.Dispatch(context.Background(), []byte("dummy"), "report.docx")
	if err != nil {
		t.Fatalf("unexpected error for DOCX: %v", err)
	}
	if res.Status != StatusClean {
		t.Errorf("expected StatusClean for DOCX, got %d", res.Status)
	}
	if !mock.called {
		t.Error("mock sanitizer was not called for DOCX")
	}

	// Reset and test XLSX.
	mock.called = false
	res, err = d.Dispatch(context.Background(), []byte("dummy"), "sheet.xlsx")
	if err != nil {
		t.Fatalf("unexpected error for XLSX: %v", err)
	}
	if res.Status != StatusClean {
		t.Errorf("expected StatusClean for XLSX, got %d", res.Status)
	}
	if !mock.called {
		t.Error("mock sanitizer was not called for XLSX")
	}
}

func TestDispatcher_ContextCancellation(t *testing.T) {
	d := NewDispatcher()

	ctxSan := &contextCheckSanitizer{}
	d.Register(ctxSan)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	res, err := d.Dispatch(ctx, []byte("%PDF-1.0"), "test.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Error == nil {
		t.Error("expected Result.Error to reflect context cancellation")
	}
}

// contextCheckSanitizer verifies that the context is forwarded.
type contextCheckSanitizer struct{}

func (c *contextCheckSanitizer) Sanitize(ctx context.Context, data []byte, _ string) (*Result, error) {
	return &Result{
		Status:       StatusError,
		OriginalType: FileTypePDF,
		OriginalSize: int64(len(data)),
		Error:        ctx.Err(),
	}, nil
}

func (c *contextCheckSanitizer) SupportedTypes() []FileType {
	return []FileType{FileTypePDF}
}
