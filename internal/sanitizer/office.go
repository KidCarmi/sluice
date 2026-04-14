package sanitizer

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
)

// maxEntrySize is the maximum decompressed size allowed for a single ZIP entry
// (50 MB). This prevents zip-bomb attacks.
const maxEntrySize = 50 * 1024 * 1024

// OfficeSanitizer strips dangerous content from Office Open XML files (docx,
// xlsx, pptx). These formats are ZIP archives containing XML parts; the
// sanitizer walks every entry, drops known-dangerous ones, and rebuilds a
// clean archive.
type OfficeSanitizer struct {
	logger *slog.Logger
}

// NewOfficeSanitizer returns a ready-to-use OfficeSanitizer.
func NewOfficeSanitizer(logger *slog.Logger) *OfficeSanitizer {
	return &OfficeSanitizer{logger: logger}
}

// SupportedTypes returns the Office Open XML file types handled by this
// sanitizer.
func (s *OfficeSanitizer) SupportedTypes() []FileType {
	return []FileType{FileTypeDOCX, FileTypeXLSX, FileTypePPTX}
}

// Sanitize processes an Office Open XML document, stripping macros, OLE
// objects, ActiveX controls, external data connections, and external
// references. The returned Result describes what was found and removed.
func (s *OfficeSanitizer) Sanitize(ctx context.Context, data []byte, filename string) (*Result, error) {
	ft := DetectType(data, filename)

	result := &Result{
		OriginalType: ft,
		OriginalSize: int64(len(data)),
	}

	// Check context before starting.
	select {
	case <-ctx.Done():
		result.Status = StatusError
		result.Error = fmt.Errorf("office sanitize: %w", ctx.Err())
		return result, result.Error
	default:
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		result.Status = StatusError
		result.Error = fmt.Errorf("office sanitize: invalid zip: %w", err)
		return result, result.Error
	}

	var (
		buf     bytes.Buffer
		zw      = zip.NewWriter(&buf)
		threats []Threat
	)

	for _, entry := range zr.File {
		// Check context between entries.
		select {
		case <-ctx.Done():
			result.Status = StatusError
			result.Error = fmt.Errorf("office sanitize: %w", ctx.Err())
			return result, result.Error
		default:
		}

		name := entry.Name

		// Reject path traversal.
		if strings.Contains(name, "..") {
			threats = append(threats, Threat{
				Type:        "path_traversal",
				Location:    filepath.Base(name),
				Description: "ZIP entry contains path traversal sequence",
				Severity:    "critical",
			})
			s.logger.Warn("stripping path traversal entry",
				slog.String("entry", filepath.Base(name)),
				slog.String("file", filepath.Base(filename)),
			)
			continue
		}

		baseName := filepath.Base(name)

		// Check for dangerous entry types.
		if threat, dangerous := classifyEntry(name, baseName); dangerous {
			threats = append(threats, threat)
			s.logger.Info("stripping dangerous entry",
				slog.String("entry", filepath.Base(name)),
				slog.String("threat", threat.Type),
				slog.String("severity", threat.Severity),
				slog.String("file", filepath.Base(filename)),
			)
			continue
		}

		// Read the entry content.
		content, err := readZIPEntry(entry)
		if err != nil {
			result.Status = StatusError
			result.Error = fmt.Errorf("office sanitize: reading entry %q: %w", filepath.Base(name), err)
			return result, result.Error
		}

		// Check .rels files for external references.
		if strings.HasSuffix(strings.ToLower(name), ".rels") && containsExternalRef(content) {
			threats = append(threats, Threat{
				Type:        "external_ref",
				Location:    name,
				Description: fmt.Sprintf("relationship file %q contains external references", filepath.Base(name)),
				Severity:    "medium",
			})
			s.logger.Info("stripping rels with external references",
				slog.String("entry", filepath.Base(name)),
				slog.String("file", filepath.Base(filename)),
			)
			continue
		}

		// Copy clean entry to rebuilt archive.
		fw, err := zw.Create(name)
		if err != nil {
			result.Status = StatusError
			result.Error = fmt.Errorf("office sanitize: creating entry %q: %w", filepath.Base(name), err)
			return result, result.Error
		}
		if _, err := fw.Write(content); err != nil {
			result.Status = StatusError
			result.Error = fmt.Errorf("office sanitize: writing entry %q: %w", filepath.Base(name), err)
			return result, result.Error
		}
	}

	if err := zw.Close(); err != nil {
		result.Status = StatusError
		result.Error = fmt.Errorf("office sanitize: finalizing zip: %w", err)
		return result, result.Error
	}

	result.Threats = threats

	if len(threats) == 0 {
		result.Status = StatusClean
		result.SanitizedData = data
		result.SanitizedSize = int64(len(data))
	} else {
		result.Status = StatusSanitized
		result.SanitizedData = buf.Bytes()
		result.SanitizedSize = int64(len(result.SanitizedData))
	}

	return result, nil
}

// classifyEntry decides whether a ZIP entry is dangerous based on its name.
// It returns the corresponding Threat and true if the entry should be
// stripped, or an empty Threat and false if the entry is safe.
func classifyEntry(fullPath, baseName string) (Threat, bool) {
	lower := strings.ToLower(baseName)

	// VBA macro binary.
	if lower == "vbaproject.bin" {
		return Threat{
			Type:        "macro",
			Location:    fullPath,
			Description: "VBA macro code (vbaProject.bin)",
			Severity:    "critical",
		}, true
	}

	// VBA source files.
	if strings.HasSuffix(lower, ".vba") {
		return Threat{
			Type:        "macro",
			Location:    fullPath,
			Description: fmt.Sprintf("VBA source file (%s)", baseName),
			Severity:    "critical",
		}, true
	}

	// OLE embedded objects: oleObject*.bin
	if strings.HasPrefix(lower, "oleobject") && strings.HasSuffix(lower, ".bin") {
		return Threat{
			Type:        "ole_object",
			Location:    fullPath,
			Description: fmt.Sprintf("OLE embedded object (%s)", baseName),
			Severity:    "high",
		}, true
	}

	// ActiveX controls: activeX*.xml and activeX*.bin
	if strings.HasPrefix(lower, "activex") &&
		(strings.HasSuffix(lower, ".xml") || strings.HasSuffix(lower, ".bin")) {
		return Threat{
			Type:        "activex",
			Location:    fullPath,
			Description: fmt.Sprintf("ActiveX control (%s)", baseName),
			Severity:    "high",
		}, true
	}

	// External data connections.
	if lower == "connections.xml" {
		return Threat{
			Type:        "external_ref",
			Location:    fullPath,
			Description: "external data connections file",
			Severity:    "medium",
		}, true
	}

	return Threat{}, false
}

// readZIPEntry reads the full content of a ZIP entry, capping decompressed
// data at maxEntrySize to prevent zip-bomb attacks.
func readZIPEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = rc.Close() }()

	lr := io.LimitReader(rc, maxEntrySize+1)
	content, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if int64(len(content)) > maxEntrySize {
		return nil, fmt.Errorf("entry exceeds maximum decompressed size (%d bytes)", maxEntrySize)
	}
	return content, nil
}

// containsExternalRef checks whether a .rels XML file contains relationships
// with TargetMode="External" pointing to remote URLs (http://, https://,
// ftp://). Internal relative references are left alone.
func containsExternalRef(data []byte) bool {
	s := string(data)

	// Only flag entries that are explicitly marked as external.
	if !strings.Contains(s, `TargetMode="External"`) {
		return false
	}

	// Look for URL targets.
	for _, prefix := range []string{`Target="http://`, `Target="https://`, `Target="ftp://`} {
		if strings.Contains(s, prefix) {
			return true
		}
	}

	return false
}
