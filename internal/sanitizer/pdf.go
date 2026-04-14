package sanitizer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
)

// maxPDFSize is the maximum number of bytes we are willing to process
// for a PDF file. 50 MB.
const maxPDFSize = 50 * 1024 * 1024

// pdfMagic is the magic-byte prefix every valid PDF starts with.
var pdfMagic = []byte("%PDF")

// dangerousPattern describes a single pattern that should be neutralized
// inside a PDF document.
type dangerousPattern struct {
	old        []byte
	new        []byte
	threatType string
	severity   string
	desc       string
}

// pdfPatterns lists all dangerous byte sequences and their safe replacements.
// Each replacement is the same length as the original to preserve cross-reference
// table offsets.
var pdfPatterns = []dangerousPattern{
	// JavaScript — critical
	{
		old:        []byte("/JavaScript"),
		new:        []byte("/XXXXXXXXXX"),
		threatType: "javascript",
		severity:   "critical",
		desc:       "JavaScript action type neutralized",
	},
	{
		old:        []byte("/JS"),
		new:        []byte("/XX"),
		threatType: "javascript",
		severity:   "critical",
		desc:       "JavaScript reference neutralized",
	},

	// Launch actions — critical
	{
		old:        []byte("/Launch"),
		new:        []byte("/XXXXXX"),
		threatType: "launch_action",
		severity:   "critical",
		desc:       "Launch action neutralized",
	},

	// Embedded files — high
	{
		old:        []byte("/EmbeddedFile"),
		new:        []byte("/XXXXXXXXXXXX"),
		threatType: "embedded_file",
		severity:   "high",
		desc:       "Embedded file reference neutralized",
	},

	// Form submit — high
	{
		old:        []byte("/SubmitForm"),
		new:        []byte("/XXXXXXXXXX"),
		threatType: "form_submit",
		severity:   "high",
		desc:       "Form submit action neutralized",
	},

	// OpenAction — high (checked before /AA so longer patterns match first)
	{
		old:        []byte("/OpenAction"),
		new:        []byte("/XXXXXXXXXX"),
		threatType: "auto_action",
		severity:   "high",
		desc:       "Auto-open action neutralized",
	},

	// XFA forms — high
	{
		old:        []byte("/XFA"),
		new:        []byte("/XXX"),
		threatType: "xfa",
		severity:   "high",
		desc:       "XFA form reference neutralized",
	},

	// RichMedia (Flash) — high
	{
		old:        []byte("/RichMedia"),
		new:        []byte("/XXXXXXXXX"),
		threatType: "rich_media",
		severity:   "high",
		desc:       "RichMedia content (Flash) neutralized",
	},

	// GoToR (remote file reference) — high
	{
		old:        []byte("/GoToR"),
		new:        []byte("/XXXXX"),
		threatType: "remote_goto",
		severity:   "high",
		desc:       "Remote file reference neutralized",
	},

	// GoToE (embedded file goto) — high
	{
		old:        []byte("/GoToE"),
		new:        []byte("/XXXXX"),
		threatType: "embedded_goto",
		severity:   "high",
		desc:       "Embedded file goto neutralized",
	},

	// Movie — medium
	{
		old:        []byte("/Movie"),
		new:        []byte("/XXXXX"),
		threatType: "movie_action",
		severity:   "medium",
		desc:       "Movie action neutralized",
	},

	// Sound — medium
	{
		old:        []byte("/Sound"),
		new:        []byte("/XXXXX"),
		threatType: "sound_action",
		severity:   "medium",
		desc:       "Sound action neutralized",
	},

	// ImportData — high
	{
		old:        []byte("/ImportData"),
		new:        []byte("/XXXXXXXXXX"),
		threatType: "import_data",
		severity:   "high",
		desc:       "Data import action neutralized",
	},

	// Rendition — medium
	{
		old:        []byte("/Rendition"),
		new:        []byte("/XXXXXXXXX"),
		threatType: "rendition",
		severity:   "medium",
		desc:       "Rendition action neutralized",
	},
}

// PDFSanitizer strips dangerous elements from PDF documents.
type PDFSanitizer struct {
	logger *slog.Logger
}

// NewPDFSanitizer creates a PDFSanitizer with the given structured logger.
func NewPDFSanitizer(logger *slog.Logger) *PDFSanitizer {
	return &PDFSanitizer{logger: logger}
}

// SupportedTypes returns the file types this sanitizer handles.
func (s *PDFSanitizer) SupportedTypes() []FileType {
	return []FileType{FileTypePDF}
}

// Sanitize processes a PDF document, neutralizing any dangerous patterns and
// returning a result that describes what was found and changed.
//
// NOTE: This sanitizer uses byte-pattern replacement, not structural PDF parsing.
// This means patterns inside strings or comments may also be neutralized, which
// could affect content but errs on the side of security. A structural parser
// (e.g., pdfcpu) would be more precise but adds a dependency.
func (s *PDFSanitizer) Sanitize(ctx context.Context, data []byte, filename string) (*Result, error) {
	// Bound the input via LimitReader so callers cannot pass unbounded data.
	lr := io.LimitReader(bytes.NewReader(data), maxPDFSize)
	bounded, err := io.ReadAll(lr)
	if err != nil {
		return &Result{
			Status:       StatusError,
			OriginalType: FileTypePDF,
			OriginalSize: int64(len(data)),
			Error:        fmt.Errorf("pdf: reading input: %w", err),
		}, nil
	}

	// Check for cancellation before doing any work.
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("pdf: %w", ctx.Err())
	default:
	}

	// Validate magic bytes.
	if len(bounded) < len(pdfMagic) || !bytes.HasPrefix(bounded, pdfMagic) {
		s.logger.WarnContext(ctx, "invalid PDF: missing magic bytes", slog.String("filename", filename))
		return &Result{
			Status:       StatusError,
			OriginalType: FileTypePDF,
			OriginalSize: int64(len(bounded)),
			Error:        fmt.Errorf("pdf: invalid file, missing %%PDF header"),
		}, nil
	}

	originalSize := int64(len(bounded))
	working := make([]byte, len(bounded))
	copy(working, bounded)

	// Single pass: scan once, replace all patterns in-place.
	// All replacements are same-length, so we can modify working directly.
	var threats []Threat
	for i := 0; i < len(working); i++ {
		// Check for cancellation every 1MB
		if i%(1024*1024) == 0 && i > 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("pdf: %w", ctx.Err())
			default:
			}
		}

		for _, pat := range pdfPatterns {
			if i+len(pat.old) <= len(working) && bytes.Equal(working[i:i+len(pat.old)], pat.old) {
				copy(working[i:i+len(pat.old)], pat.new)
				threats = append(threats, Threat{
					Type:        pat.threatType,
					Location:    fmt.Sprintf("byte pattern %q at offset %d", string(pat.old), i),
					Description: pat.desc,
					Severity:    pat.severity,
				})
				s.logger.InfoContext(ctx, "neutralized PDF threat",
					slog.String("filename", filename),
					slog.String("threat", pat.threatType),
					slog.Int("offset", i),
				)
				i += len(pat.old) - 1 // skip past the replacement
				break                  // only one pattern can match at this position
			}
		}
	}

	// Handle /AA (Additional Actions) separately — only match when followed
	// by whitespace, '<<', or a digit to avoid false positives.
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("pdf: %w", ctx.Err())
	default:
	}

	working, aaThreats := replaceAA(working)
	threats = append(threats, aaThreats...)
	if len(aaThreats) > 0 {
		s.logger.InfoContext(ctx, "neutralized PDF threat",
			slog.String("filename", filename),
			slog.String("threat", "auto_action"),
			slog.Int("count", len(aaThreats)),
		)
	}

	if len(threats) == 0 {
		return &Result{
			Status:        StatusClean,
			OriginalType:  FileTypePDF,
			OriginalSize:  originalSize,
			SanitizedSize: originalSize,
			Threats:       nil,
			SanitizedData: bounded,
		}, nil
	}

	return &Result{
		Status:        StatusSanitized,
		OriginalType:  FileTypePDF,
		OriginalSize:  originalSize,
		SanitizedSize: int64(len(working)),
		Threats:       threats,
		SanitizedData: working,
	}, nil
}

// replaceAA scans for /AA entries in PDF dictionary context. It only replaces
// occurrences where /AA is followed by whitespace, '<<', or a digit, which
// indicates it is a PDF dictionary key rather than part of a string or stream.
func replaceAA(data []byte) ([]byte, []Threat) {
	pattern := []byte("/AA")
	replacement := []byte("/XX")
	var threats []Threat

	i := 0
	for {
		idx := bytes.Index(data[i:], pattern)
		if idx < 0 {
			break
		}
		pos := i + idx
		afterPos := pos + len(pattern)

		// Check what follows /AA.
		if afterPos < len(data) {
			ch := data[afterPos]
			if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '<' || (ch >= '0' && ch <= '9') {
				// Replace in place (same length, safe).
				copy(data[pos:], replacement)
				threats = append(threats, Threat{
					Type:        "auto_action",
					Location:    fmt.Sprintf("byte offset %d", pos),
					Description: "Additional Actions dictionary neutralized",
					Severity:    "high",
				})
			}
		}
		i = afterPos
	}
	return data, threats
}
