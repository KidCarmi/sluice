package sanitizer

import (
	"archive/zip"
	"bytes"
	"io"
	"path/filepath"
	"strings"
)

// FileType represents a recognized document type.
type FileType string

const (
	FileTypePDF     FileType = "pdf"
	FileTypeDOCX    FileType = "docx"
	FileTypeXLSX    FileType = "xlsx"
	FileTypePPTX    FileType = "pptx"
	FileTypeUnknown FileType = "unknown"
)

// maxZIPSize is the maximum number of bytes we are willing to read when
// inspecting a ZIP archive for OOXML markers. 50 MB.
const maxZIPSize = 50 * 1024 * 1024

// magicPDF is the magic-byte prefix for PDF files.
var magicPDF = []byte("%PDF")

// magicZIP is the local-file-header signature for ZIP (PK\x03\x04).
var magicZIP = []byte{0x50, 0x4B, 0x03, 0x04}

// DetectType identifies the file type by inspecting magic bytes first and
// falling back to the file extension when the magic bytes are inconclusive.
// Never trust Content-Type or extension alone.
func DetectType(header []byte, filename string) FileType {
	if ft := detectByMagic(header); ft != FileTypeUnknown {
		return ft
	}
	return detectByExtension(filename)
}

// detectByMagic inspects the raw bytes of a file and returns the detected
// FileType, or FileTypeUnknown if the bytes do not match any known signature.
func detectByMagic(data []byte) FileType {
	if bytes.HasPrefix(data, magicPDF) {
		return FileTypePDF
	}
	if bytes.HasPrefix(data, magicZIP) {
		return detectOOXML(data)
	}
	return FileTypeUnknown
}

// detectOOXML opens data as a ZIP archive and inspects its entries to
// distinguish between DOCX, XLSX and PPTX files. All three are ZIP-based
// Office Open XML formats.
func detectOOXML(data []byte) FileType {
	// Cap the amount of data we feed to the ZIP reader.
	size := int64(len(data))
	if size > maxZIPSize {
		size = maxZIPSize
	}
	r := io.LimitReader(bytes.NewReader(data), size)

	// Read the (potentially limited) data into a buffer so we can create a
	// ReaderAt required by zip.NewReader.
	buf, err := io.ReadAll(r)
	if err != nil {
		return FileTypeUnknown
	}

	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return FileTypeUnknown
	}

	for _, f := range zr.File {
		name := f.Name
		if strings.HasPrefix(name, "word/") {
			return FileTypeDOCX
		}
		if strings.HasPrefix(name, "xl/") {
			return FileTypeXLSX
		}
		if strings.HasPrefix(name, "ppt/") {
			return FileTypePPTX
		}
	}

	return FileTypeUnknown
}

// detectByExtension maps common file extensions to their FileType. This is
// used as a fallback when magic bytes are inconclusive.
func detectByExtension(filename string) FileType {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(filename), "."))
	switch ext {
	case "pdf":
		return FileTypePDF
	case "docx":
		return FileTypeDOCX
	case "xlsx":
		return FileTypeXLSX
	case "pptx":
		return FileTypePPTX
	default:
		return FileTypeUnknown
	}
}

// IsSupportedType returns true when ft is one of the document types the CDR
// engine knows how to sanitize.
func IsSupportedType(ft FileType) bool {
	switch ft {
	case FileTypePDF, FileTypeDOCX, FileTypeXLSX, FileTypePPTX:
		return true
	default:
		return false
	}
}
