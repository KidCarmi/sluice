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
		}, fmt.Errorf("pdf: reading input: %w", err)
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
		}, fmt.Errorf("pdf: invalid file, missing %%PDF header")
	}

	originalSize := int64(len(bounded))
	working := make([]byte, len(bounded))
	copy(working, bounded)

	var threats []Threat

	// Process each dangerous pattern.
	for _, pat := range pdfPatterns {
		// Check for cancellation between pattern scans.
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("pdf: %w", ctx.Err())
		default:
		}

		count := bytes.Count(working, pat.old)
		if count > 0 {
			working = bytes.ReplaceAll(working, pat.old, pat.new)
			for i := 0; i < count; i++ {
				threats = append(threats, Threat{
					Type:        pat.threatType,
					Location:    fmt.Sprintf("byte pattern %q", string(pat.old)),
					Description: pat.desc,
					Severity:    pat.severity,
				})
			}
			s.logger.InfoContext(ctx, "neutralized PDF threat",
				slog.String("filename", filename),
				slog.String("threat", pat.threatType),
				slog.Int("count", count),
			)
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
