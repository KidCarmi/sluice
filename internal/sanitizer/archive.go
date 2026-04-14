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

// maxArchiveEntrySize is the maximum decompressed size for a single ZIP entry
// (50 MB).
const maxArchiveEntrySize = 50 * 1024 * 1024

// maxArchiveDecompressed is the maximum total decompressed size across all
// entries in a ZIP archive (100 MB). Exceeding this limit signals a zip-bomb.
const maxArchiveDecompressed = 100 * 1024 * 1024

// maxArchiveDepth is the maximum nesting depth for ZIP-inside-ZIP archives.
const maxArchiveDepth = 3

// archiveDepthKey is the context key for tracking recursion depth.
type archiveDepthKey struct{}

// getArchiveDepth returns the current archive nesting depth from the context.
func getArchiveDepth(ctx context.Context) int {
	if v, ok := ctx.Value(archiveDepthKey{}).(int); ok {
		return v
	}
	return 0
}

// withArchiveDepth returns a child context with the given archive depth.
func withArchiveDepth(ctx context.Context, depth int) context.Context {
	return context.WithValue(ctx, archiveDepthKey{}, depth)
}

// ArchiveSanitizer unpacks ZIP archives, recursively sanitizes each entry
// through the CDR dispatcher, and repacks a clean archive.
type ArchiveSanitizer struct {
	dispatcher *Dispatcher
	logger     *slog.Logger
}

// NewArchiveSanitizer returns an ArchiveSanitizer that uses the given
// dispatcher to recursively sanitize contained files.
func NewArchiveSanitizer(dispatcher *Dispatcher, logger *slog.Logger) *ArchiveSanitizer {
	return &ArchiveSanitizer{
		dispatcher: dispatcher,
		logger:     logger,
	}
}

// SupportedTypes returns the file types this sanitizer handles.
func (s *ArchiveSanitizer) SupportedTypes() []FileType {
	return []FileType{FileTypeZIP}
}

// Sanitize processes a ZIP archive by unpacking it, running each entry through
// the CDR dispatcher, and rebuilding a clean archive.
func (s *ArchiveSanitizer) Sanitize(ctx context.Context, data []byte, filename string) (*Result, error) {
	result := &Result{
		OriginalType: FileTypeZIP,
		OriginalSize: int64(len(data)),
	}

	// Check context before starting.
	select {
	case <-ctx.Done():
		result.Status = StatusError
		result.Error = fmt.Errorf("archive sanitize: %w", ctx.Err())
		return result, result.Error
	default:
	}

	// Check nesting depth.
	depth := getArchiveDepth(ctx)
	if depth >= maxArchiveDepth {
		result.Status = StatusBlocked
		result.Error = fmt.Errorf("archive sanitize: nesting too deep (%d levels)", depth)
		result.Threats = []Threat{{
			Type:        "zip_bomb",
			Location:    filepath.Base(filename),
			Description: fmt.Sprintf("archive nesting depth %d exceeds maximum of %d", depth, maxArchiveDepth),
			Severity:    "critical",
		}}
		return result, result.Error
	}

	// Parse the ZIP archive.
	if len(data) == 0 {
		result.Status = StatusError
		result.Error = fmt.Errorf("archive sanitize: empty input")
		return result, result.Error
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		result.Status = StatusError
		result.Error = fmt.Errorf("archive sanitize: invalid zip: %w", err)
		return result, result.Error
	}

	var (
		buf             bytes.Buffer
		zw              = zip.NewWriter(&buf)
		threats         []Threat
		sanitizedAny    bool
		totalDecompSize int64
	)

	childCtx := withArchiveDepth(ctx, depth+1)

	for _, entry := range zr.File {
		// Check context between entries.
		select {
		case <-ctx.Done():
			result.Status = StatusError
			result.Error = fmt.Errorf("archive sanitize: %w", ctx.Err())
			return result, result.Error
		default:
		}

		name := entry.Name

		// Path traversal check.
		if strings.Contains(name, "..") {
			threats = append(threats, Threat{
				Type:        "path_traversal",
				Location:    filepath.Base(name),
				Description: "ZIP entry contains path traversal sequence",
				Severity:    "critical",
			})
			s.logger.Warn("rejecting path traversal entry",
				slog.String("entry", filepath.Base(name)),
				slog.String("file", filepath.Base(filename)),
			)
			continue
		}

		// Size check: skip entries larger than maxArchiveEntrySize.
		if entry.UncompressedSize64 > maxArchiveEntrySize {
			s.logger.Warn("skipping oversized entry",
				slog.String("entry", filepath.Base(name)),
				slog.Uint64("size", entry.UncompressedSize64),
				slog.String("file", filepath.Base(filename)),
			)
			continue
		}

		// Read the entry using io.LimitReader.
		rc, err := entry.Open()
		if err != nil {
			result.Status = StatusError
			result.Error = fmt.Errorf("archive sanitize: opening entry %q: %w", filepath.Base(name), err)
			return result, result.Error
		}

		lr := io.LimitReader(rc, maxArchiveEntrySize+1)
		entryData, err := io.ReadAll(lr)
		_ = rc.Close()
		if err != nil {
			result.Status = StatusError
			result.Error = fmt.Errorf("archive sanitize: reading entry %q: %w", filepath.Base(name), err)
			return result, result.Error
		}

		if int64(len(entryData)) > maxArchiveEntrySize {
			s.logger.Warn("entry exceeds max size after decompression",
				slog.String("entry", filepath.Base(name)),
				slog.String("file", filepath.Base(filename)),
			)
			continue
		}

		// Track total decompressed size.
		totalDecompSize += int64(len(entryData))
		if totalDecompSize > maxArchiveDecompressed {
			result.Status = StatusBlocked
			result.Error = fmt.Errorf("archive sanitize: total decompressed size exceeds %d bytes", maxArchiveDecompressed)
			result.Threats = append(threats, Threat{
				Type:        "zip_bomb",
				Location:    filepath.Base(filename),
				Description: fmt.Sprintf("total decompressed size exceeds %d bytes", maxArchiveDecompressed),
				Severity:    "critical",
			})
			return result, result.Error
		}

		// Recursively sanitize through the dispatcher.
		outputData := entryData
		subResult, err := s.dispatcher.Dispatch(childCtx, entryData, name)
		if err != nil {
			// If the file type is unsupported, pass through unchanged.
			if subResult != nil && subResult.Status == StatusUnsupported {
				// Pass through unchanged.
			} else {
				// Propagate blocked status from nested archives.
				if subResult != nil && subResult.Status == StatusBlocked {
					result.Status = StatusBlocked
					result.Error = fmt.Errorf("archive sanitize: nested entry %q blocked: %w", filepath.Base(name), err)
					// Collect threats from sub-result with prefixed location.
					for _, th := range subResult.Threats {
						threats = append(threats, Threat{
							Type:        th.Type,
							Location:    name + "/" + th.Location,
							Description: th.Description,
							Severity:    th.Severity,
						})
					}
					result.Threats = threats
					return result, result.Error
				}
				result.Status = StatusError
				result.Error = fmt.Errorf("archive sanitize: dispatching entry %q: %w", filepath.Base(name), err)
				return result, result.Error
			}
		} else if subResult != nil {
			// Collect threats with location prefixed by archive entry path.
			for _, th := range subResult.Threats {
				threats = append(threats, Threat{
					Type:        th.Type,
					Location:    name + "/" + th.Location,
					Description: th.Description,
					Severity:    th.Severity,
				})
			}

			if subResult.Status == StatusSanitized {
				sanitizedAny = true
				outputData = subResult.SanitizedData
			}
		}

		// Write the (sanitized or original) data to the output ZIP.
		fw, err := zw.Create(name)
		if err != nil {
			result.Status = StatusError
			result.Error = fmt.Errorf("archive sanitize: creating output entry %q: %w", filepath.Base(name), err)
			return result, result.Error
		}
		if _, err := fw.Write(outputData); err != nil {
			result.Status = StatusError
			result.Error = fmt.Errorf("archive sanitize: writing output entry %q: %w", filepath.Base(name), err)
			return result, result.Error
		}
	}

	if err := zw.Close(); err != nil {
		result.Status = StatusError
		result.Error = fmt.Errorf("archive sanitize: finalizing zip: %w", err)
		return result, result.Error
	}

	result.Threats = threats

	if len(threats) > 0 || sanitizedAny {
		result.Status = StatusSanitized
		result.SanitizedData = buf.Bytes()
		result.SanitizedSize = int64(len(result.SanitizedData))
	} else {
		result.Status = StatusClean
		result.SanitizedData = data
		result.SanitizedSize = int64(len(data))
	}

	return result, nil
}
