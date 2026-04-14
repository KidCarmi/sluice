package sanitizer

import (
	"archive/zip"
	"bytes"
	"testing"
)

// buildMinimalZIP creates a minimal ZIP archive in memory that contains a
// single file at path entryName. This is sufficient to trigger the OOXML
// detection logic.
func buildMinimalZIP(t *testing.T, entryName string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(entryName)
	if err != nil {
		t.Fatalf("zip create entry: %v", err)
	}
	if _, err := w.Write([]byte("placeholder")); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestDetectType_PDF_MagicBytes(t *testing.T) {
	header := []byte("%PDF-1.7 some trailing data")
	ft := DetectType(header, "invoice.bin")
	if ft != FileTypePDF {
		t.Errorf("expected %q, got %q", FileTypePDF, ft)
	}
}

func TestDetectType_DOCX_MagicBytes(t *testing.T) {
	data := buildMinimalZIP(t, "word/document.xml")
	ft := DetectType(data, "report.bin")
	if ft != FileTypeDOCX {
		t.Errorf("expected %q, got %q", FileTypeDOCX, ft)
	}
}

func TestDetectType_XLSX_MagicBytes(t *testing.T) {
	data := buildMinimalZIP(t, "xl/workbook.xml")
	ft := DetectType(data, "report.bin")
	if ft != FileTypeXLSX {
		t.Errorf("expected %q, got %q", FileTypeXLSX, ft)
	}
}

func TestDetectType_PPTX_MagicBytes(t *testing.T) {
	data := buildMinimalZIP(t, "ppt/presentation.xml")
	ft := DetectType(data, "deck.bin")
	if ft != FileTypePPTX {
		t.Errorf("expected %q, got %q", FileTypePPTX, ft)
	}
}

func TestDetectType_Unknown(t *testing.T) {
	header := []byte{0x00, 0x01, 0x02, 0x03}
	ft := DetectType(header, "mystery.xyz")
	if ft != FileTypeUnknown {
		t.Errorf("expected %q, got %q", FileTypeUnknown, ft)
	}
}

func TestDetectType_ExtensionFallback(t *testing.T) {
	tests := []struct {
		filename string
		want     FileType
	}{
		{"report.pdf", FileTypePDF},
		{"report.PDF", FileTypePDF},
		{"doc.docx", FileTypeDOCX},
		{"sheet.xlsx", FileTypeXLSX},
		{"slides.pptx", FileTypePPTX},
		{"archive.tar.gz", FileTypeUnknown},
	}

	// Use a header that does not match any known magic bytes so that the
	// detector falls through to the extension check.
	header := []byte("not-a-magic-header")

	for _, tc := range tests {
		t.Run(tc.filename, func(t *testing.T) {
			got := DetectType(header, tc.filename)
			if got != tc.want {
				t.Errorf("DetectType(%q) = %q; want %q", tc.filename, got, tc.want)
			}
		})
	}
}

func TestDetectType_ZIPWithoutOOXML(t *testing.T) {
	// A valid ZIP that does not contain any OOXML marker directories should
	// be detected as a plain ZIP archive.
	data := buildMinimalZIP(t, "README.txt")
	ft := DetectType(data, "archive.zip")
	if ft != FileTypeZIP {
		t.Errorf("expected %q for plain ZIP, got %q", FileTypeZIP, ft)
	}
}

func TestIsSupportedType(t *testing.T) {
	supported := []FileType{FileTypePDF, FileTypeDOCX, FileTypeXLSX, FileTypePPTX}
	for _, ft := range supported {
		if !IsSupportedType(ft) {
			t.Errorf("IsSupportedType(%q) = false; want true", ft)
		}
	}
	if IsSupportedType(FileTypeUnknown) {
		t.Error("IsSupportedType(FileTypeUnknown) = true; want false")
	}
	if IsSupportedType(FileType("bmp")) {
		t.Error("IsSupportedType(\"bmp\") = true; want false")
	}
}
