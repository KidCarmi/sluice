package sanitizer

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

// assertPDFStructure verifies a sanitized PDF is structurally valid.
func assertPDFStructure(t *testing.T, data []byte, originalSize int64) {
	t.Helper()

	if !bytes.HasPrefix(data, []byte("%PDF")) {
		t.Error("PDF: missing %PDF header")
	}
	if !bytes.Contains(data, []byte("%%EOF")) {
		t.Error("PDF: missing EOF trailer")
	}
	if !bytes.Contains(data, []byte("startxref")) {
		t.Error("PDF: missing startxref pointer")
	}
	if len(data) != int(originalSize) {
		t.Errorf("PDF: sanitized length %d != original length %d; same-length replacement not preserved", len(data), originalSize)
	}
	if bytes.Contains(data, []byte("/JavaScript")) {
		t.Error("PDF: sanitized output still contains /JavaScript")
	}
	if bytes.Contains(data, []byte("/JS")) {
		t.Error("PDF: sanitized output still contains /JS")
	}
}

// assertOfficeStructure verifies a sanitized OOXML file is structurally valid.
func assertOfficeStructure(t *testing.T, data []byte) {
	t.Helper()

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Office: cannot open as ZIP: %v", err)
	}

	hasContentTypes := false
	hasRels := false
	hasOOXMLPrefix := false
	hasVBAProject := false

	for _, f := range zr.File {
		if f.Name == "[Content_Types].xml" {
			hasContentTypes = true
		}
		if f.Name == "_rels/.rels" {
			hasRels = true
			// Verify .rels parses as valid XML.
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("Office: cannot open _rels/.rels: %v", err)
			}
			relsData, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				t.Fatalf("Office: cannot read _rels/.rels: %v", err)
			}
			var dummy struct {
				XMLName xml.Name
			}
			if err := xml.Unmarshal(relsData, &dummy); err != nil {
				t.Errorf("Office: _rels/.rels is not valid XML: %v", err)
			}
		}
		if strings.HasPrefix(f.Name, "word/") || strings.HasPrefix(f.Name, "xl/") || strings.HasPrefix(f.Name, "ppt/") {
			hasOOXMLPrefix = true
		}
		if strings.ToLower(f.Name) == "word/vbaproject.bin" || strings.HasSuffix(strings.ToLower(f.Name), "/vbaproject.bin") {
			hasVBAProject = true
		}

		// Verify every entry can be opened and read without error.
		rc, err := f.Open()
		if err != nil {
			t.Errorf("Office: cannot open entry %q: %v", f.Name, err)
			continue
		}
		if _, err := io.ReadAll(rc); err != nil {
			t.Errorf("Office: cannot read entry %q: %v", f.Name, err)
		}
		_ = rc.Close()
	}

	if !hasContentTypes {
		t.Error("Office: missing [Content_Types].xml entry")
	}
	if !hasRels {
		t.Error("Office: missing _rels/.rels entry")
	}
	if !hasOOXMLPrefix {
		t.Error("Office: no entry with word/, xl/, or ppt/ prefix found")
	}
	if hasVBAProject {
		t.Error("Office: vbaProject.bin should have been stripped but is still present")
	}
}

// assertJPEGStructure verifies a sanitized JPEG is structurally valid.
func assertJPEGStructure(t *testing.T, data []byte, origWidth, origHeight int) {
	t.Helper()

	if !bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}) {
		t.Error("JPEG: missing SOI marker (FF D8 FF)")
	}
	if !bytes.HasSuffix(data, []byte{0xFF, 0xD9}) {
		t.Error("JPEG: missing EOI marker (FF D9)")
	}

	cfg, err := jpeg.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("JPEG: jpeg.DecodeConfig failed: %v", err)
	}
	if cfg.Width != origWidth {
		t.Errorf("JPEG: width %d != expected %d", cfg.Width, origWidth)
	}
	if cfg.Height != origHeight {
		t.Errorf("JPEG: height %d != expected %d", cfg.Height, origHeight)
	}
}

// assertPNGStructure verifies a sanitized PNG is structurally valid.
func assertPNGStructure(t *testing.T, data []byte, origWidth, origHeight int) {
	t.Helper()

	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if !bytes.HasPrefix(data, pngSig) {
		t.Error("PNG: missing PNG signature")
	}

	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("PNG: png.DecodeConfig failed: %v", err)
	}
	if cfg.Width != origWidth {
		t.Errorf("PNG: width %d != expected %d", cfg.Width, origWidth)
	}
	if cfg.Height != origHeight {
		t.Errorf("PNG: height %d != expected %d", cfg.Height, origHeight)
	}
}

// assertGIFStructure verifies a sanitized GIF is structurally valid.
func assertGIFStructure(t *testing.T, data []byte) {
	t.Helper()

	if !bytes.HasPrefix(data, []byte("GIF")) {
		t.Error("GIF: missing GIF signature")
	}

	g, err := gif.DecodeAll(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("GIF: gif.DecodeAll failed: %v", err)
	}
	if g.Config.Width == 0 || g.Config.Height == 0 {
		t.Error("GIF: image dimensions are zero")
	}
}

// assertSVGStructure verifies a sanitized SVG is structurally valid and safe.
func assertSVGStructure(t *testing.T, data []byte) {
	t.Helper()

	var root struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(data, &root); err != nil {
		t.Fatalf("SVG: xml.Unmarshal failed: %v", err)
	}
	if root.XMLName.Local != "svg" {
		t.Errorf("SVG: root element is %q, expected \"svg\"", root.XMLName.Local)
	}

	lower := strings.ToLower(string(data))
	if strings.Contains(lower, "<script") {
		t.Error("SVG: sanitized output still contains <script> element")
	}
	if strings.Contains(lower, "onclick") {
		t.Error("SVG: sanitized output still contains onclick event handler")
	}
	if strings.Contains(lower, "javascript:") {
		t.Error("SVG: sanitized output still contains javascript: URI")
	}
}

// assertZIPStructure verifies a sanitized ZIP is structurally valid.
func assertZIPStructure(t *testing.T, data []byte, maxEntries int) {
	t.Helper()

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("ZIP: cannot open as ZIP: %v", err)
	}

	if len(zr.File) > maxEntries {
		t.Errorf("ZIP: entry count %d exceeds max %d", len(zr.File), maxEntries)
	}

	for _, f := range zr.File {
		if strings.Contains(f.Name, "..") {
			t.Errorf("ZIP: entry name %q contains path traversal sequence", f.Name)
		}
		if strings.HasPrefix(f.Name, "/") {
			t.Errorf("ZIP: entry name %q starts with /", f.Name)
		}

		rc, err := f.Open()
		if err != nil {
			t.Errorf("ZIP: cannot open entry %q: %v", f.Name, err)
			continue
		}
		if _, err := io.ReadAll(rc); err != nil {
			t.Errorf("ZIP: cannot read entry %q: %v", f.Name, err)
		}
		_ = rc.Close()
	}
}

// ---------------------------------------------------------------------------
// Integration test helpers
// ---------------------------------------------------------------------------

// integrationLogger creates a discard logger for integration tests.
func integrationLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// makeIntegrationDispatcher creates a Dispatcher with all sanitizers
// registered, suitable for full-pipeline integration tests.
func makeIntegrationDispatcher() *Dispatcher {
	logger := integrationLogger()
	d := NewDispatcher()
	d.Register(NewPDFSanitizer(logger))
	d.Register(NewOfficeSanitizer(logger))
	d.Register(NewImageSanitizer(logger))
	d.Register(NewSVGSanitizer(logger))
	d.Register(NewArchiveSanitizer(d, logger))
	return d
}

// makeIntegrationDOCX creates a minimal valid DOCX with optional extra
// entries merged in. The base always includes [Content_Types].xml,
// _rels/.rels, and word/document.xml.
func makeIntegrationDOCX(extras map[string]string) []byte {
	entries := map[string]string{
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
  <w:body><w:p><w:r><w:t>Integration test document</w:t></w:r></w:p></w:body>
</w:document>`,
	}
	for k, v := range extras {
		entries[k] = v
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, _ := w.Create(name)
		_, _ = f.Write([]byte(content))
	}
	_ = w.Close()
	return buf.Bytes()
}

// makeIntegrationXLSX creates a minimal valid XLSX.
func makeIntegrationXLSX() []byte {
	entries := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`,
		"xl/workbook.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets>
</workbook>`,
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, _ := w.Create(name)
		_, _ = f.Write([]byte(content))
	}
	_ = w.Close()
	return buf.Bytes()
}

// makeIntegrationZIPArchive builds a ZIP from name to byte-slice entries.
func makeIntegrationZIPArchive(entries map[string][]byte) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range entries {
		f, _ := w.Create(name)
		_, _ = f.Write(data)
	}
	_ = w.Close()
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// PDF integration tests
// ---------------------------------------------------------------------------

func TestIntegration_PDFSanitized(t *testing.T) {
	s := NewPDFSanitizer(integrationLogger())

	// Create a PDF with /JavaScript, /Launch, and /OpenAction threats.
	data := makeTestPDF("/JavaScript /Launch /OpenAction")

	result, err := s.Sanitize(context.Background(), data, "threats.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Fatalf("expected StatusSanitized, got %d", result.Status)
	}

	assertPDFStructure(t, result.SanitizedData, result.OriginalSize)
}

func TestIntegration_PDFClean(t *testing.T) {
	s := NewPDFSanitizer(integrationLogger())

	data := makeTestPDF("")

	result, err := s.Sanitize(context.Background(), data, "clean.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Fatalf("expected StatusClean, got %d", result.Status)
	}

	// For clean PDFs, assertPDFStructure still applies (just no threats to check).
	if !bytes.HasPrefix(result.SanitizedData, []byte("%PDF")) {
		t.Error("clean PDF: missing %PDF header")
	}
	if !bytes.Contains(result.SanitizedData, []byte("%%EOF")) {
		t.Error("clean PDF: missing EOF trailer")
	}
	if !bytes.Contains(result.SanitizedData, []byte("startxref")) {
		t.Error("clean PDF: missing startxref pointer")
	}
	if len(result.SanitizedData) != int(result.OriginalSize) {
		t.Errorf("clean PDF: length mismatch %d != %d", len(result.SanitizedData), result.OriginalSize)
	}
}

// ---------------------------------------------------------------------------
// Office (DOCX) integration tests
// ---------------------------------------------------------------------------

func TestIntegration_DocxSanitized(t *testing.T) {
	s := NewOfficeSanitizer(integrationLogger())

	data := makeIntegrationDOCX(map[string]string{
		"word/vbaProject.bin":              "FAKE_VBA_BINARY",
		"word/embeddings/oleObject1.bin":   "OLE_EMBEDDED_DATA",
	})

	result, err := s.Sanitize(context.Background(), data, "macro.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Fatalf("expected StatusSanitized, got %d", result.Status)
	}

	assertOfficeStructure(t, result.SanitizedData)
}

func TestIntegration_DocxClean(t *testing.T) {
	s := NewOfficeSanitizer(integrationLogger())

	data := makeIntegrationDOCX(nil)

	result, err := s.Sanitize(context.Background(), data, "clean.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Fatalf("expected StatusClean, got %d", result.Status)
	}

	assertOfficeStructure(t, result.SanitizedData)
}

func TestIntegration_XlsxClean(t *testing.T) {
	s := NewOfficeSanitizer(integrationLogger())

	data := makeIntegrationXLSX()

	result, err := s.Sanitize(context.Background(), data, "clean.xlsx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Fatalf("expected StatusClean, got %d", result.Status)
	}

	assertOfficeStructure(t, result.SanitizedData)
}

// ---------------------------------------------------------------------------
// Image integration tests
// ---------------------------------------------------------------------------

func TestIntegration_JPEGSanitized(t *testing.T) {
	s := NewImageSanitizer(integrationLogger())

	base := makeTestJPEG()
	// Inject EXIF metadata to trigger sanitization.
	exifPayload := append([]byte("Exif\x00\x00"), []byte("II*\x00dummy exif integration data")...)
	data := injectJPEGMarker(base, 0xE1, exifPayload)

	result, err := s.Sanitize(context.Background(), data, "exif.jpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Fatalf("expected StatusSanitized, got %d", result.Status)
	}

	// The original test image is 10x10.
	assertJPEGStructure(t, result.SanitizedData, 10, 10)
}

func TestIntegration_PNGClean(t *testing.T) {
	s := NewImageSanitizer(integrationLogger())

	data := makeTestPNG()

	result, err := s.Sanitize(context.Background(), data, "clean.png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Fatalf("expected StatusClean, got %d", result.Status)
	}

	// The original test image is 10x10.
	assertPNGStructure(t, result.SanitizedData, 10, 10)
}

func TestIntegration_GIFClean(t *testing.T) {
	s := NewImageSanitizer(integrationLogger())

	data := makeTestGIF()

	result, err := s.Sanitize(context.Background(), data, "clean.gif")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Fatalf("expected StatusClean, got %d", result.Status)
	}

	assertGIFStructure(t, result.SanitizedData)
}

// ---------------------------------------------------------------------------
// SVG integration tests
// ---------------------------------------------------------------------------

func TestIntegration_SVGSanitized(t *testing.T) {
	s := NewSVGSanitizer(integrationLogger())

	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <circle cx="50" cy="50" r="40" fill="red" onclick="alert('xss')"/>
  <script>document.cookie</script>
  <a href="javascript:alert(1)"><text>Click</text></a>
</svg>`)

	result, err := s.Sanitize(context.Background(), svg, "threats.svg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Fatalf("expected StatusSanitized, got %d", result.Status)
	}

	assertSVGStructure(t, result.SanitizedData)
}

func TestIntegration_SVGClean(t *testing.T) {
	s := NewSVGSanitizer(integrationLogger())

	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <rect x="0" y="0" width="100" height="100" fill="blue"/>
  <circle cx="50" cy="50" r="25" fill="yellow"/>
</svg>`)

	result, err := s.Sanitize(context.Background(), svg, "clean.svg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Fatalf("expected StatusClean, got %d", result.Status)
	}

	assertSVGStructure(t, result.SanitizedData)
}

// ---------------------------------------------------------------------------
// ZIP / Archive integration tests
// ---------------------------------------------------------------------------

func TestIntegration_ZIPSanitized(t *testing.T) {
	logger := integrationLogger()
	d := makeIntegrationDispatcher()
	s := NewArchiveSanitizer(d, logger)

	// Create a DOCX with a macro, then wrap it in a ZIP.
	docxWithMacro := makeIntegrationDOCX(map[string]string{
		"word/vbaProject.bin": "MACRO_DATA_FOR_ZIP_TEST",
	})
	data := makeIntegrationZIPArchive(map[string][]byte{
		"documents/report.docx": docxWithMacro,
		"readme.txt":            []byte("just a readme"),
	})

	result, err := s.Sanitize(context.Background(), data, "archive.zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Fatalf("expected StatusSanitized, got %d", result.Status)
	}

	assertZIPStructure(t, result.SanitizedData, 10)

	// Extract the inner DOCX and verify its structure.
	zr, err := zip.NewReader(bytes.NewReader(result.SanitizedData), int64(len(result.SanitizedData)))
	if err != nil {
		t.Fatalf("cannot reopen sanitized ZIP: %v", err)
	}

	for _, f := range zr.File {
		if f.Name == "documents/report.docx" {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("cannot open inner DOCX: %v", err)
			}
			innerData, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				t.Fatalf("cannot read inner DOCX: %v", err)
			}
			assertOfficeStructure(t, innerData)
			return
		}
	}
	t.Fatal("inner DOCX entry 'documents/report.docx' not found in sanitized ZIP")
}

func TestIntegration_ZIPClean(t *testing.T) {
	logger := integrationLogger()
	d := makeIntegrationDispatcher()
	s := NewArchiveSanitizer(d, logger)

	data := makeIntegrationZIPArchive(map[string][]byte{
		"file1.txt": []byte("Hello from file1"),
		"file2.txt": []byte("Hello from file2"),
		"file3.txt": []byte("Hello from file3"),
	})

	result, err := s.Sanitize(context.Background(), data, "clean.zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Fatalf("expected StatusClean, got %d", result.Status)
	}

	assertZIPStructure(t, result.SanitizedData, 10)
}

// ---------------------------------------------------------------------------
// Full pipeline integration test
// ---------------------------------------------------------------------------

func TestIntegration_FullPipeline(t *testing.T) {
	d := makeIntegrationDispatcher()
	ctx := context.Background()

	t.Run("PDF", func(t *testing.T) {
		data := makeTestPDF("/JavaScript /Launch")
		result, err := d.Dispatch(ctx, data, "pipeline.pdf")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != StatusSanitized {
			t.Fatalf("expected StatusSanitized, got %d", result.Status)
		}
		assertPDFStructure(t, result.SanitizedData, result.OriginalSize)
	})

	t.Run("DOCX", func(t *testing.T) {
		data := makeIntegrationDOCX(map[string]string{
			"word/vbaProject.bin": "MACRO",
		})
		result, err := d.Dispatch(ctx, data, "pipeline.docx")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != StatusSanitized {
			t.Fatalf("expected StatusSanitized, got %d", result.Status)
		}
		assertOfficeStructure(t, result.SanitizedData)
	})

	t.Run("XLSX", func(t *testing.T) {
		data := makeIntegrationXLSX()
		result, err := d.Dispatch(ctx, data, "pipeline.xlsx")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != StatusClean {
			t.Fatalf("expected StatusClean, got %d", result.Status)
		}
		assertOfficeStructure(t, result.SanitizedData)
	})

	t.Run("JPEG", func(t *testing.T) {
		base := makeTestJPEG()
		exifPayload := append([]byte("Exif\x00\x00"), []byte("II*\x00pipeline exif data")...)
		data := injectJPEGMarker(base, 0xE1, exifPayload)
		result, err := d.Dispatch(ctx, data, "pipeline.jpg")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != StatusSanitized {
			t.Fatalf("expected StatusSanitized, got %d", result.Status)
		}
		assertJPEGStructure(t, result.SanitizedData, 10, 10)
	})

	t.Run("PNG", func(t *testing.T) {
		data := makeTestPNG()
		result, err := d.Dispatch(ctx, data, "pipeline.png")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != StatusClean {
			t.Fatalf("expected StatusClean, got %d", result.Status)
		}
		assertPNGStructure(t, result.SanitizedData, 10, 10)
	})

	t.Run("GIF", func(t *testing.T) {
		data := makeTestGIF()
		result, err := d.Dispatch(ctx, data, "pipeline.gif")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != StatusClean {
			t.Fatalf("expected StatusClean, got %d", result.Status)
		}
		assertGIFStructure(t, result.SanitizedData)
	})

	t.Run("SVG", func(t *testing.T) {
		svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="50" height="50">
  <script>evil()</script>
  <circle cx="25" cy="25" r="20" fill="green"/>
</svg>`)
		result, err := d.Dispatch(ctx, svg, "pipeline.svg")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != StatusSanitized {
			t.Fatalf("expected StatusSanitized, got %d", result.Status)
		}
		assertSVGStructure(t, result.SanitizedData)
	})

	t.Run("ZIP", func(t *testing.T) {
		docx := makeIntegrationDOCX(map[string]string{
			"word/vbaProject.bin": "ZIP_PIPELINE_MACRO",
		})
		data := makeIntegrationZIPArchive(map[string][]byte{
			"inner.docx": docx,
			"notes.txt":  []byte("clean text"),
		})
		result, err := d.Dispatch(ctx, data, "pipeline.zip")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != StatusSanitized {
			t.Fatalf("expected StatusSanitized, got %d", result.Status)
		}
		assertZIPStructure(t, result.SanitizedData, 10)
	})
}
