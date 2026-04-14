package sanitizer

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
)

// makeTestZIPArchive builds a ZIP archive from name→data pairs.
func makeTestZIPArchive(entries map[string][]byte) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range entries {
		f, _ := w.Create(name)
		_, _ = f.Write(data)
	}
	_ = w.Close()
	return buf.Bytes()
}

// makeDocxWithMacro returns a minimal OOXML (DOCX) archive that contains a
// VBA macro binary — enough for the OfficeSanitizer to detect and strip it.
func makeDocxWithMacro() []byte {
	entries := map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>`),
		"_rels/.rels":         []byte(`<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`),
		"word/document.xml":   []byte(`<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Test</w:t></w:r></w:p></w:body></w:document>`),
		"word/vbaProject.bin": []byte("FAKE_VBA_MACRO_DATA"),
	}
	return makeTestZIPArchive(entries)
}

// makePDFWithJS returns a minimal PDF that contains a /JavaScript action.
func makePDFWithJS() []byte {
	return []byte(`%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj
4 0 obj<</Type/Action/S/JavaScript/JS(alert('test'))>>endobj
xref
0 5
trailer<</Size 5/Root 1 0 R>>startxref 0
%%EOF`)
}

// newTestDispatcher creates a Dispatcher with real sanitizers registered,
// including the ArchiveSanitizer itself for nested ZIP tests.
func newTestDispatcher() *Dispatcher {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := NewDispatcher()
	d.Register(NewOfficeSanitizer(logger))
	d.Register(NewPDFSanitizer(logger))
	d.Register(NewImageSanitizer(logger))
	d.Register(NewArchiveSanitizer(d, logger))
	return d
}

func newTestArchiveSanitizer() *ArchiveSanitizer {
	d := newTestDispatcher()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewArchiveSanitizer(d, logger)
}

func TestArchiveSanitizer_SupportedTypes(t *testing.T) {
	s := newTestArchiveSanitizer()
	types := s.SupportedTypes()
	if len(types) != 1 || types[0] != FileTypeZIP {
		t.Errorf("expected [zip], got %v", types)
	}
}

func TestArchiveSanitizer_CleanZIP(t *testing.T) {
	s := newTestArchiveSanitizer()
	data := makeTestZIPArchive(map[string][]byte{
		"hello.txt": []byte("Hello, world!"),
	})

	result, err := s.Sanitize(context.Background(), data, "clean.zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Errorf("expected StatusClean, got %d", result.Status)
	}
	if len(result.Threats) != 0 {
		t.Errorf("expected 0 threats, got %d", len(result.Threats))
	}
}

func TestArchiveSanitizer_SanitizeContainedDoc(t *testing.T) {
	docx := makeDocxWithMacro()
	data := makeTestZIPArchive(map[string][]byte{
		"documents/macro.docx": docx,
	})

	s := newTestArchiveSanitizer()
	result, err := s.Sanitize(context.Background(), data, "archive.zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	// There should be at least one macro threat with location prefixed by
	// the archive entry path.
	foundMacro := false
	for _, th := range result.Threats {
		if th.Type == "macro" {
			foundMacro = true
			if !bytes.Contains([]byte(th.Location), []byte("documents/macro.docx/")) {
				t.Errorf("expected threat location to be prefixed with archive path, got %q", th.Location)
			}
		}
	}
	if !foundMacro {
		t.Error("expected at least one macro threat")
	}
}

func TestArchiveSanitizer_SanitizeContainedPDF(t *testing.T) {
	pdfData := makePDFWithJS()
	data := makeTestZIPArchive(map[string][]byte{
		"report.pdf": pdfData,
	})

	s := newTestArchiveSanitizer()
	result, err := s.Sanitize(context.Background(), data, "archive.zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	foundJS := false
	for _, th := range result.Threats {
		if th.Type == "javascript" {
			foundJS = true
		}
	}
	if !foundJS {
		t.Error("expected at least one javascript threat from contained PDF")
	}
}

func TestArchiveSanitizer_MixedContent(t *testing.T) {
	docx := makeDocxWithMacro()
	data := makeTestZIPArchive(map[string][]byte{
		"clean.txt":  []byte("just a text file"),
		"macro.docm": docx,
	})

	s := newTestArchiveSanitizer()
	result, err := s.Sanitize(context.Background(), data, "mixed.zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	// Only the DOCX should produce threats.
	if len(result.Threats) == 0 {
		t.Fatal("expected at least one threat from macro.docm")
	}

	for _, th := range result.Threats {
		if !bytes.Contains([]byte(th.Location), []byte("macro.docm/")) {
			t.Errorf("expected all threats to come from macro.docm, got location %q", th.Location)
		}
	}
}

func TestArchiveSanitizer_PathTraversal(t *testing.T) {
	data := makeTestZIPArchive(map[string][]byte{
		"../../etc/passwd": []byte("root:x:0:0"),
	})

	s := newTestArchiveSanitizer()
	result, err := s.Sanitize(context.Background(), data, "traversal.zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	found := false
	for _, th := range result.Threats {
		if th.Type == "path_traversal" {
			found = true
			if th.Severity != "critical" {
				t.Errorf("expected severity critical, got %q", th.Severity)
			}
		}
	}
	if !found {
		t.Error("expected path_traversal threat")
	}
}

func TestArchiveSanitizer_EmptyZIP(t *testing.T) {
	// A valid ZIP with zero entries.
	data := makeTestZIPArchive(map[string][]byte{})

	s := newTestArchiveSanitizer()
	result, err := s.Sanitize(context.Background(), data, "empty.zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Errorf("expected StatusClean, got %d", result.Status)
	}
}

func TestArchiveSanitizer_InvalidZIP(t *testing.T) {
	s := newTestArchiveSanitizer()
	result, err := s.Sanitize(context.Background(), []byte("this is not a zip file at all"), "bad.zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusError {
		t.Errorf("expected StatusError, got %d", result.Status)
	}
	if result.Error == nil {
		t.Error("expected Result.Error to be set")
	}
}

func TestArchiveSanitizer_EmptyInput(t *testing.T) {
	s := newTestArchiveSanitizer()
	result, err := s.Sanitize(context.Background(), []byte{}, "empty.zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusError {
		t.Errorf("expected StatusError, got %d", result.Status)
	}
	if result.Error == nil {
		t.Error("expected Result.Error to be set")
	}
}

func TestArchiveSanitizer_ContextCancellation(t *testing.T) {
	s := newTestArchiveSanitizer()
	data := makeTestZIPArchive(map[string][]byte{
		"hello.txt": []byte("Hello"),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	result, err := s.Sanitize(ctx, data, "cancel.zip")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if result != nil {
		t.Errorf("expected nil result for context cancellation, got %+v", result)
	}
}

func TestArchiveSanitizer_NestedZIP(t *testing.T) {
	// Inner ZIP contains a DOCX with a macro.
	docx := makeDocxWithMacro()
	innerZIP := makeTestZIPArchive(map[string][]byte{
		"inner_macro.docx": docx,
	})
	outerZIP := makeTestZIPArchive(map[string][]byte{
		"nested.zip": innerZIP,
	})

	s := newTestArchiveSanitizer()
	result, err := s.Sanitize(context.Background(), outerZIP, "outer.zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	// Should have macro threat from the nested DOCX.
	foundMacro := false
	for _, th := range result.Threats {
		if th.Type == "macro" {
			foundMacro = true
		}
	}
	if !foundMacro {
		t.Error("expected macro threat from nested ZIP containing DOCX")
	}
}

func TestArchiveSanitizer_MaxDepth(t *testing.T) {
	// Build a ZIP nested 4 levels deep (exceeds maxArchiveDepth of 3).
	// Level 4: innermost content.
	innermost := makeTestZIPArchive(map[string][]byte{
		"deep.txt": []byte("deep content"),
	})
	// Level 3:
	level3 := makeTestZIPArchive(map[string][]byte{
		"level3.zip": innermost,
	})
	// Level 2:
	level2 := makeTestZIPArchive(map[string][]byte{
		"level2.zip": level3,
	})
	// Level 1:
	level1 := makeTestZIPArchive(map[string][]byte{
		"level1.zip": level2,
	})

	s := newTestArchiveSanitizer()
	result, err := s.Sanitize(context.Background(), level1, "deep.zip")

	// The result should be blocked because nesting is too deep.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusBlocked {
		t.Errorf("expected StatusBlocked, got %d", result.Status)
	}

	foundZipBomb := false
	for _, th := range result.Threats {
		if th.Type == "zip_bomb" {
			foundZipBomb = true
		}
	}
	if !foundZipBomb {
		t.Error("expected zip_bomb threat for excessive nesting")
	}
}

func FuzzArchiveSanitizer(f *testing.F) {
	// Seed with a valid ZIP and some edge cases.
	f.Add(makeTestZIPArchive(map[string][]byte{"test.txt": []byte("hello")}))
	f.Add([]byte{})
	f.Add([]byte("not a zip"))
	f.Add([]byte{0x50, 0x4B, 0x03, 0x04}) // ZIP magic only

	s := newTestArchiveSanitizer()

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic regardless of input.
		_, _ = s.Sanitize(context.Background(), data, "fuzz.zip")
	})
}
