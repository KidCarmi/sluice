package sanitizer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// makeTestPDF builds a minimal valid PDF with the given extra content
// injected into the catalog dictionary.
func makeTestPDF(extraContent string) []byte {
	return []byte(fmt.Sprintf(`%%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R %s >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
trailer
<< /Size 4 /Root 1 0 R >>
startxref
0
%%%%EOF`, extraContent))
}

func newTestSanitizer() *PDFSanitizer {
	return NewPDFSanitizer(slog.Default())
}

func TestPDFSanitizer_CleanPDF(t *testing.T) {
	s := newTestSanitizer()
	data := makeTestPDF("")
	res, err := s.Sanitize(context.Background(), data, "clean.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusClean {
		t.Errorf("expected StatusClean, got %d", res.Status)
	}
	if len(res.Threats) != 0 {
		t.Errorf("expected 0 threats, got %d", len(res.Threats))
	}
	if res.OriginalSize != int64(len(data)) {
		t.Errorf("OriginalSize = %d, want %d", res.OriginalSize, len(data))
	}
}

func TestPDFSanitizer_StripJavaScript(t *testing.T) {
	s := newTestSanitizer()
	data := makeTestPDF("/JS (alert('xss'))")
	res, err := s.Sanitize(context.Background(), data, "js.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", res.Status)
	}
	found := false
	for _, th := range res.Threats {
		if th.Type == "javascript" {
			found = true
			if th.Severity != "critical" {
				t.Errorf("expected severity critical, got %s", th.Severity)
			}
		}
	}
	if !found {
		t.Error("expected a javascript threat to be recorded")
	}
	// Verify the dangerous pattern is gone from the output.
	if strings.Contains(string(res.SanitizedData), "/JS") {
		t.Error("sanitized data still contains /JS")
	}
}

func TestPDFSanitizer_StripJavaScriptAction(t *testing.T) {
	s := newTestSanitizer()
	data := makeTestPDF("/S /JavaScript")
	res, err := s.Sanitize(context.Background(), data, "jsaction.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", res.Status)
	}
	if strings.Contains(string(res.SanitizedData), "/JavaScript") {
		t.Error("sanitized data still contains /JavaScript")
	}
}

func TestPDFSanitizer_StripLaunch(t *testing.T) {
	s := newTestSanitizer()
	data := makeTestPDF("/S /Launch")
	res, err := s.Sanitize(context.Background(), data, "launch.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", res.Status)
	}
	if strings.Contains(string(res.SanitizedData), "/Launch") {
		t.Error("sanitized data still contains /Launch")
	}
}

func TestPDFSanitizer_StripEmbeddedFile(t *testing.T) {
	s := newTestSanitizer()
	data := makeTestPDF("/Type /EmbeddedFile")
	res, err := s.Sanitize(context.Background(), data, "embedded.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", res.Status)
	}
	if strings.Contains(string(res.SanitizedData), "/EmbeddedFile") {
		t.Error("sanitized data still contains /EmbeddedFile")
	}
}

func TestPDFSanitizer_StripSubmitForm(t *testing.T) {
	s := newTestSanitizer()
	data := makeTestPDF("/S /SubmitForm")
	res, err := s.Sanitize(context.Background(), data, "submit.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", res.Status)
	}
	if strings.Contains(string(res.SanitizedData), "/SubmitForm") {
		t.Error("sanitized data still contains /SubmitForm")
	}
}

func TestPDFSanitizer_StripXFA(t *testing.T) {
	s := newTestSanitizer()
	data := makeTestPDF("/XFA 5 0 R")
	res, err := s.Sanitize(context.Background(), data, "xfa.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", res.Status)
	}
	if strings.Contains(string(res.SanitizedData), "/XFA") {
		t.Error("sanitized data still contains /XFA")
	}
}

func TestPDFSanitizer_StripAutoAction(t *testing.T) {
	s := newTestSanitizer()
	data := makeTestPDF("/AA << /O << /S /JavaScript /JS (evil()) >> >>")
	res, err := s.Sanitize(context.Background(), data, "aa.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", res.Status)
	}
	// /AA should be neutralized.
	foundAA := false
	for _, th := range res.Threats {
		if th.Type == "auto_action" {
			foundAA = true
			break
		}
	}
	if !foundAA {
		t.Error("expected an auto_action threat to be recorded")
	}
}

func TestPDFSanitizer_MultipleThreats(t *testing.T) {
	s := newTestSanitizer()
	data := makeTestPDF("/JS (evil()) /Launch /XFA 5 0 R")
	res, err := s.Sanitize(context.Background(), data, "multi.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", res.Status)
	}

	types := make(map[string]bool)
	for _, th := range res.Threats {
		types[th.Type] = true
	}
	for _, expected := range []string{"javascript", "launch_action", "xfa"} {
		if !types[expected] {
			t.Errorf("expected threat type %q to be recorded", expected)
		}
	}
}

func TestPDFSanitizer_InvalidPDF(t *testing.T) {
	s := newTestSanitizer()
	data := []byte("this is not a PDF at all")
	res, err := s.Sanitize(context.Background(), data, "bad.pdf")
	if err == nil {
		t.Fatal("expected error for invalid PDF")
	}
	if res.Status != StatusError {
		t.Errorf("expected StatusError, got %d", res.Status)
	}
}

func TestPDFSanitizer_EmptyFile(t *testing.T) {
	s := newTestSanitizer()
	res, err := s.Sanitize(context.Background(), []byte{}, "empty.pdf")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
	if res.Status != StatusError {
		t.Errorf("expected StatusError, got %d", res.Status)
	}
}

func TestPDFSanitizer_PreservesStructure(t *testing.T) {
	s := newTestSanitizer()
	data := makeTestPDF("/JS (bad) /Launch")
	res, err := s.Sanitize(context.Background(), data, "preserve.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusSanitized {
		t.Fatalf("expected StatusSanitized, got %d", res.Status)
	}
	if int64(len(res.SanitizedData)) != res.OriginalSize {
		t.Errorf("sanitized length %d != original length %d; structure not preserved",
			len(res.SanitizedData), res.OriginalSize)
	}
}

func TestPDFSanitizer_SupportedTypes(t *testing.T) {
	s := newTestSanitizer()
	types := s.SupportedTypes()
	if len(types) != 1 || types[0] != FileTypePDF {
		t.Errorf("expected [pdf], got %v", types)
	}
}

func TestPDFSanitizer_ContextCancellation(t *testing.T) {
	s := newTestSanitizer()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	data := makeTestPDF("/JS (evil())")
	_, err := s.Sanitize(ctx, data, "cancelled.pdf")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func FuzzPDFSanitizer(f *testing.F) {
	f.Add(makeTestPDF(""))
	f.Add(makeTestPDF("/JS (alert('xss'))"))
	f.Add(makeTestPDF("/Launch"))
	f.Add([]byte("not a pdf"))
	f.Add([]byte{})

	s := NewPDFSanitizer(slog.Default())

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic regardless of input.
		_, _ = s.Sanitize(context.Background(), data, "fuzz.pdf")
	})
}
