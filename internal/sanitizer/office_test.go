package sanitizer

import (
	"archive/zip"
	"bytes"
	"context"
	"log/slog"
	"testing"
)

// makeTestZIP builds a minimal ZIP archive in memory from the given entries.
func makeTestZIP(entries map[string]string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, _ := w.Create(name)
		f.Write([]byte(content))
	}
	w.Close()
	return buf.Bytes()
}

// minimalDOCX returns the entries for a minimal valid DOCX (no threats).
func minimalDOCX() map[string]string {
	return map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`,
		"word/document.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body>
</w:document>`,
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestOfficeSanitizer_CleanDocx(t *testing.T) {
	s := NewOfficeSanitizer(testLogger())
	data := makeTestZIP(minimalDOCX())

	result, err := s.Sanitize(context.Background(), data, "test.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusClean {
		t.Errorf("expected StatusClean, got %d", result.Status)
	}
	if len(result.Threats) != 0 {
		t.Errorf("expected 0 threats, got %d", len(result.Threats))
	}
	if result.OriginalSize != int64(len(data)) {
		t.Errorf("expected OriginalSize %d, got %d", len(data), result.OriginalSize)
	}
	// Clean result should return original data unchanged.
	if !bytes.Equal(result.SanitizedData, data) {
		t.Error("expected SanitizedData to equal original data for clean file")
	}
}

func TestOfficeSanitizer_StripMacro(t *testing.T) {
	entries := minimalDOCX()
	entries["word/vbaProject.bin"] = "VBA_BINARY_DATA"

	s := NewOfficeSanitizer(testLogger())
	data := makeTestZIP(entries)

	result, err := s.Sanitize(context.Background(), data, "macro.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}
	if len(result.Threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(result.Threats))
	}

	th := result.Threats[0]
	if th.Type != "macro" {
		t.Errorf("expected threat type 'macro', got %q", th.Type)
	}
	if th.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", th.Severity)
	}
	if th.Location != "word/vbaProject.bin" {
		t.Errorf("expected location 'word/vbaProject.bin', got %q", th.Location)
	}

	// Verify the rebuilt archive does not contain the macro.
	assertZIPMissing(t, result.SanitizedData, "word/vbaProject.bin")
}

func TestOfficeSanitizer_StripOLE(t *testing.T) {
	entries := minimalDOCX()
	entries["word/embeddings/oleObject1.bin"] = "OLE_DATA"

	s := NewOfficeSanitizer(testLogger())
	data := makeTestZIP(entries)

	result, err := s.Sanitize(context.Background(), data, "ole.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}
	if len(result.Threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(result.Threats))
	}
	if result.Threats[0].Type != "ole_object" {
		t.Errorf("expected threat type 'ole_object', got %q", result.Threats[0].Type)
	}
	if result.Threats[0].Severity != "high" {
		t.Errorf("expected severity 'high', got %q", result.Threats[0].Severity)
	}
	assertZIPMissing(t, result.SanitizedData, "word/embeddings/oleObject1.bin")
}

func TestOfficeSanitizer_StripActiveX(t *testing.T) {
	entries := minimalDOCX()
	entries["word/activeX/activeX1.xml"] = "<activex/>"

	s := NewOfficeSanitizer(testLogger())
	data := makeTestZIP(entries)

	result, err := s.Sanitize(context.Background(), data, "activex.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}
	if len(result.Threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(result.Threats))
	}
	if result.Threats[0].Type != "activex" {
		t.Errorf("expected threat type 'activex', got %q", result.Threats[0].Type)
	}
	if result.Threats[0].Severity != "high" {
		t.Errorf("expected severity 'high', got %q", result.Threats[0].Severity)
	}
	assertZIPMissing(t, result.SanitizedData, "word/activeX/activeX1.xml")
}

func TestOfficeSanitizer_StripConnections(t *testing.T) {
	entries := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0"?><Types/>`,
		"xl/workbook.xml":     `<workbook/>`,
		"xl/connections.xml":  `<connections><connection name="evil"/></connections>`,
	}

	s := NewOfficeSanitizer(testLogger())
	data := makeTestZIP(entries)

	result, err := s.Sanitize(context.Background(), data, "conn.xlsx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}
	if len(result.Threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(result.Threats))
	}
	if result.Threats[0].Type != "external_ref" {
		t.Errorf("expected threat type 'external_ref', got %q", result.Threats[0].Type)
	}
	assertZIPMissing(t, result.SanitizedData, "xl/connections.xml")
}

func TestOfficeSanitizer_StripExternalRels(t *testing.T) {
	entries := minimalDOCX()
	entries["word/_rels/document.xml.rels"] = `<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
    Target="https://evil.example.com/payload" TargetMode="External"/>
</Relationships>`

	s := NewOfficeSanitizer(testLogger())
	data := makeTestZIP(entries)

	result, err := s.Sanitize(context.Background(), data, "extref.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	found := false
	for _, th := range result.Threats {
		if th.Type == "external_ref" {
			found = true
		}
	}
	if !found {
		t.Error("expected at least one external_ref threat")
	}
	assertZIPMissing(t, result.SanitizedData, "word/_rels/document.xml.rels")
}

func TestOfficeSanitizer_KeepInternalRels(t *testing.T) {
	entries := minimalDOCX()
	// This .rels file has no TargetMode="External", so it should be kept.
	entries["word/_rels/document.xml.rels"] = `<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
    Target="worksheets/sheet1.xml"/>
</Relationships>`

	s := NewOfficeSanitizer(testLogger())
	data := makeTestZIP(entries)

	result, err := s.Sanitize(context.Background(), data, "internal.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusClean {
		t.Errorf("expected StatusClean (internal rels are safe), got %d", result.Status)
	}
}

func TestOfficeSanitizer_MultipleThreats(t *testing.T) {
	entries := minimalDOCX()
	entries["word/vbaProject.bin"] = "MACRO"
	entries["word/embeddings/oleObject1.bin"] = "OLE"
	entries["word/activeX/activeX1.xml"] = "<ax/>"

	s := NewOfficeSanitizer(testLogger())
	data := makeTestZIP(entries)

	result, err := s.Sanitize(context.Background(), data, "multi.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}
	if len(result.Threats) != 3 {
		t.Fatalf("expected 3 threats, got %d: %+v", len(result.Threats), result.Threats)
	}

	types := map[string]bool{}
	for _, th := range result.Threats {
		types[th.Type] = true
	}
	for _, expected := range []string{"macro", "ole_object", "activex"} {
		if !types[expected] {
			t.Errorf("expected threat type %q not found", expected)
		}
	}

	assertZIPMissing(t, result.SanitizedData, "word/vbaProject.bin")
	assertZIPMissing(t, result.SanitizedData, "word/embeddings/oleObject1.bin")
	assertZIPMissing(t, result.SanitizedData, "word/activeX/activeX1.xml")
}

func TestOfficeSanitizer_EmptyFile(t *testing.T) {
	s := NewOfficeSanitizer(testLogger())

	result, err := s.Sanitize(context.Background(), []byte{}, "empty.docx")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
	if result.Status != StatusError {
		t.Errorf("expected StatusError, got %d", result.Status)
	}
	if result.Error == nil {
		t.Error("expected Result.Error to be set")
	}
}

func TestOfficeSanitizer_ContextCancellation(t *testing.T) {
	s := NewOfficeSanitizer(testLogger())
	data := makeTestZIP(minimalDOCX())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	result, err := s.Sanitize(ctx, data, "cancel.docx")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if result.Status != StatusError {
		t.Errorf("expected StatusError, got %d", result.Status)
	}
}

func TestOfficeSanitizer_PathTraversal(t *testing.T) {
	entries := map[string]string{
		"[Content_Types].xml": `<Types/>`,
		"../../../etc/passwd": "root:x:0:0",
	}
	s := NewOfficeSanitizer(testLogger())
	data := makeTestZIP(entries)

	result, err := s.Sanitize(context.Background(), data, "traversal.docx")
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
		}
	}
	if !found {
		t.Error("expected path_traversal threat")
	}
	assertZIPMissing(t, result.SanitizedData, "../../../etc/passwd")
}

func TestOfficeSanitizer_SupportedTypes(t *testing.T) {
	s := NewOfficeSanitizer(testLogger())
	types := s.SupportedTypes()

	expected := map[FileType]bool{
		FileTypeDOCX: true,
		FileTypeXLSX: true,
		FileTypePPTX: true,
	}
	if len(types) != len(expected) {
		t.Fatalf("expected %d supported types, got %d", len(expected), len(types))
	}
	for _, ft := range types {
		if !expected[ft] {
			t.Errorf("unexpected supported type: %s", ft)
		}
	}
}

func TestOfficeSanitizer_VBASourceFile(t *testing.T) {
	entries := minimalDOCX()
	entries["word/vbaData/module1.vba"] = "Sub AutoOpen()\nEnd Sub"

	s := NewOfficeSanitizer(testLogger())
	data := makeTestZIP(entries)

	result, err := s.Sanitize(context.Background(), data, "vba.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}
	if len(result.Threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(result.Threats))
	}
	if result.Threats[0].Type != "macro" {
		t.Errorf("expected threat type 'macro', got %q", result.Threats[0].Type)
	}
	assertZIPMissing(t, result.SanitizedData, "word/vbaData/module1.vba")
}

func FuzzOfficeSanitizer(f *testing.F) {
	// Seed the fuzzer with a valid DOCX ZIP and some edge cases.
	f.Add(makeTestZIP(minimalDOCX()))
	f.Add([]byte{})
	f.Add([]byte("not a zip"))
	f.Add([]byte{0x50, 0x4B, 0x03, 0x04}) // ZIP magic only

	s := NewOfficeSanitizer(testLogger())

	f.Fuzz(func(t *testing.T, data []byte) {
		// The sanitizer must never panic regardless of input.
		_, _ = s.Sanitize(context.Background(), data, "fuzz.docx")
	})
}

// assertZIPMissing verifies that the given entry name does not appear in the
// ZIP archive contained in data.
func assertZIPMissing(t *testing.T, data []byte, name string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("failed to read sanitized ZIP: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			t.Errorf("entry %q should have been stripped but is still present", name)
		}
	}
}
