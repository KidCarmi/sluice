package sanitizer

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// maxSVGSize is the maximum number of bytes we read from an SVG. 50 MB.
const maxSVGSize = 50 * 1024 * 1024

// dangerousElements are SVG/XML element local names that must be stripped
// entirely, along with their threat metadata.
var dangerousElements = map[string]struct {
	threatType string
	severity   string
}{
	"script":        {threatType: "script", severity: "critical"},
	"foreignobject": {threatType: "foreign_object", severity: "high"},
	"iframe":        {threatType: "iframe", severity: "high"},
	"embed":         {threatType: "embed", severity: "high"},
	"object":        {threatType: "object", severity: "high"},
}

// dangerousCSSPatterns lists substrings inside <style> content that signal
// an attack vector.
var dangerousCSSPatterns = []struct {
	pattern    string
	threatType string
	severity   string
}{
	{pattern: "expression(", threatType: "css_expression", severity: "high"},
	{pattern: "url(javascript:", threatType: "javascript_uri", severity: "critical"},
	{pattern: "-moz-binding", threatType: "css_binding", severity: "high"},
}

// SVGSanitizer strips dangerous active content from SVG files while
// preserving visual elements.
type SVGSanitizer struct {
	logger *slog.Logger
}

// NewSVGSanitizer creates a new SVGSanitizer.
func NewSVGSanitizer(logger *slog.Logger) *SVGSanitizer {
	return &SVGSanitizer{logger: logger}
}

// SupportedTypes returns the file types this sanitizer handles.
func (s *SVGSanitizer) SupportedTypes() []FileType {
	return []FileType{FileTypeSVG}
}

// Sanitize processes an SVG document, stripping dangerous elements and
// attributes while preserving visual content.
func (s *SVGSanitizer) Sanitize(ctx context.Context, data []byte, filename string) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("svg sanitize: %w", err)
	}

	result := &Result{
		OriginalType: FileTypeSVG,
		OriginalSize: int64(len(data)),
	}

	if len(data) == 0 {
		result.Status = StatusError
		result.Error = fmt.Errorf("svg: empty file")
		return result, nil
	}

	// Bound the input via LimitReader.
	lr := io.LimitReader(bytes.NewReader(data), maxSVGSize)
	bounded, err := io.ReadAll(lr)
	if err != nil {
		result.Status = StatusError
		result.Error = fmt.Errorf("svg: reading input: %w", err)
		return result, nil
	}

	// Validate that the input is plausible XML/SVG by checking for an
	// opening angle bracket somewhere in the first 512 bytes.
	if !looksLikeSVG(bounded) {
		result.Status = StatusError
		result.Error = fmt.Errorf("svg: input does not appear to be SVG/XML")
		return result, nil
	}

	var threats []Threat
	var out bytes.Buffer
	decoder := xml.NewDecoder(bytes.NewReader(bounded))
	decoder.Entity = map[string]string{} // disable external entity resolution (XXE)
	decoder.Strict = false
	decoder.AutoClose = xml.HTMLAutoClose
	encoder := xml.NewEncoder(&out)

	skipDepth := 0        // >0 means we are inside a stripped element
	inStyle := false      // true when inside a non-stripped <style> element
	var styleStart *xml.StartElement // buffered <style> start element (not yet written)
	var styleContent bytes.Buffer
	tokenCount := 0
	const maxTokens = 1_000_000 // guard against XML entity expansion / billion laughs

	for {
		// Check for cancellation periodically.
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("svg sanitize: %w", ctx.Err())
		default:
		}

		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.Status = StatusError
			result.Error = fmt.Errorf("svg: parsing XML: %w", err)
			return result, nil
		}

		tokenCount++
		if tokenCount > maxTokens {
			result.Status = StatusBlocked
			result.Error = fmt.Errorf("svg: exceeded maximum token count (%d), possible entity expansion attack", maxTokens)
			return result, nil
		}

		switch t := tok.(type) {
		case xml.StartElement:
			localLower := strings.ToLower(t.Name.Local)

			// If we are already skipping, just increase depth.
			if skipDepth > 0 {
				skipDepth++
				continue
			}

			// Check for dangerous elements.
			if info, dangerous := dangerousElements[localLower]; dangerous {
				skipDepth = 1
				threats = append(threats, Threat{
					Type:        info.threatType,
					Location:    fmt.Sprintf("<%s> element", t.Name.Local),
					Description: fmt.Sprintf("Dangerous <%s> element stripped", t.Name.Local),
					Severity:    info.severity,
				})
				continue
			}

			// Check <style> elements — buffer the start element and content,
			// inspect CSS for dangerous patterns before writing anything.
			if localLower == "style" {
				inStyle = true
				styleContent.Reset()
				cleanAttrs, attrThreats := filterAttributes(t)
				threats = append(threats, attrThreats...)
				t.Attr = cleanAttrs
				copied := t.Copy()
				styleStart = &copied
				continue
			}

			// Filter dangerous attributes from all other elements.
			cleanAttrs, attrThreats := filterAttributes(t)
			threats = append(threats, attrThreats...)
			t.Attr = cleanAttrs
			if err := encoder.EncodeToken(t); err != nil {
				result.Status = StatusError
				result.Error = fmt.Errorf("svg: encoding token: %w", err)
				return result, nil
			}

		case xml.EndElement:
			if skipDepth > 0 {
				skipDepth--
				continue
			}

			localLower := strings.ToLower(t.Name.Local)
			if localLower == "style" && inStyle {
				// Check buffered style content for dangerous patterns.
				css := styleContent.String()
				cssLower := strings.ToLower(css)
				styleDangerous := false
				for _, pat := range dangerousCSSPatterns {
					if strings.Contains(cssLower, pat.pattern) {
						styleDangerous = true
						threats = append(threats, Threat{
							Type:        pat.threatType,
							Location:    "<style> element",
							Description: fmt.Sprintf("Dangerous CSS pattern %q found in <style>", pat.pattern),
							Severity:    pat.severity,
						})
					}
				}
				inStyle = false
				if styleDangerous {
					// Dangerous CSS: drop the entire <style> element.
					// Since we buffered the start element and content
					// without writing, we simply skip — nothing to undo.
					styleStart = nil
					continue
				}
				// Clean CSS: write the buffered start element, content, and end element.
				if styleStart != nil {
					if err := encoder.EncodeToken(*styleStart); err != nil {
						result.Status = StatusError
						result.Error = fmt.Errorf("svg: encoding style start: %w", err)
						return result, nil
					}
				}
				if css != "" {
					if err := encoder.EncodeToken(xml.CharData([]byte(css))); err != nil {
						result.Status = StatusError
						result.Error = fmt.Errorf("svg: encoding style content: %w", err)
						return result, nil
					}
				}
				if err := encoder.EncodeToken(t); err != nil {
					result.Status = StatusError
					result.Error = fmt.Errorf("svg: encoding token: %w", err)
					return result, nil
				}
				continue
			}

			if err := encoder.EncodeToken(t); err != nil {
				result.Status = StatusError
				result.Error = fmt.Errorf("svg: encoding token: %w", err)
				return result, nil
			}

		case xml.CharData:
			if skipDepth > 0 {
				continue
			}
			if inStyle {
				styleContent.Write(t)
				continue
			}
			if err := encoder.EncodeToken(t.Copy()); err != nil {
				result.Status = StatusError
				result.Error = fmt.Errorf("svg: encoding token: %w", err)
				return result, nil
			}

		case xml.Comment:
			if skipDepth > 0 {
				continue
			}
			if err := encoder.EncodeToken(t.Copy()); err != nil {
				result.Status = StatusError
				result.Error = fmt.Errorf("svg: encoding token: %w", err)
				return result, nil
			}

		case xml.ProcInst:
			if skipDepth > 0 {
				continue
			}
			if err := encoder.EncodeToken(t.Copy()); err != nil {
				result.Status = StatusError
				result.Error = fmt.Errorf("svg: encoding token: %w", err)
				return result, nil
			}

		case xml.Directive:
			if skipDepth > 0 {
				continue
			}
			if err := encoder.EncodeToken(t.Copy()); err != nil {
				result.Status = StatusError
				result.Error = fmt.Errorf("svg: encoding token: %w", err)
				return result, nil
			}
		}
	}

	if err := encoder.Flush(); err != nil {
		result.Status = StatusError
		result.Error = fmt.Errorf("svg: flushing output: %w", err)
		return result, nil
	}

	result.SanitizedData = out.Bytes()
	result.SanitizedSize = int64(len(result.SanitizedData))
	result.Threats = threats

	if len(threats) > 0 {
		result.Status = StatusSanitized
		s.logger.Info("svg sanitized",
			"filename", filename,
			"threats", len(threats),
			"original_size", result.OriginalSize,
			"sanitized_size", result.SanitizedSize,
		)
	} else {
		result.Status = StatusClean
	}

	return result, nil
}

// looksLikeSVG performs a quick sanity check: the first 512 bytes should
// contain either "<svg" or "<?xml" (case-insensitive).
func looksLikeSVG(data []byte) bool {
	limit := 512
	if len(data) < limit {
		limit = len(data)
	}
	prefix := strings.ToLower(string(data[:limit]))
	return strings.Contains(prefix, "<svg") || strings.Contains(prefix, "<?xml")
}

// javascriptURIAttrs is the set of attributes that must be checked for
// javascript: URI schemes on all elements.
var javascriptURIAttrs = map[string]bool{
	"href":       true,
	"xlink:href": true,
	"src":        true,
	"data":       true,
	"action":     true,
	"formaction": true,
	"poster":     true,
	"background": true,
}

// dangerousInlineStylePatterns lists substrings in inline style attributes
// that signal an attack vector.
var dangerousInlineStylePatterns = []string{
	"expression(",
	"javascript:",
	"-moz-binding",
	"behavior:",
}

// filterAttributes removes dangerous attributes from an element and returns
// the cleaned attribute slice plus any threats found.
func filterAttributes(elem xml.StartElement) ([]xml.Attr, []Threat) {
	var clean []xml.Attr
	var threats []Threat

	for _, attr := range elem.Attr {
		nameLower := strings.ToLower(attr.Name.Local)

		// Resolve the full attribute name including namespace prefix.
		fullNameLower := nameLower
		if attr.Name.Space != "" {
			// For xlink:href the Space is the namespace URI; also check
			// the raw prefix form used by some SVGs.
			spaceLower := strings.ToLower(attr.Name.Space)
			if strings.Contains(spaceLower, "xlink") || spaceLower == "xlink" {
				fullNameLower = "xlink:" + nameLower
			}
		}

		// Strip all on* event handlers.
		if strings.HasPrefix(nameLower, "on") && len(nameLower) > 2 {
			threats = append(threats, Threat{
				Type:        "event_handler",
				Location:    fmt.Sprintf("%s attribute on <%s>", attr.Name.Local, elem.Name.Local),
				Description: fmt.Sprintf("Event handler attribute %q stripped", attr.Name.Local),
				Severity:    "high",
			})
			continue
		}

		// Strip javascript: URIs on all relevant attributes.
		if javascriptURIAttrs[fullNameLower] || javascriptURIAttrs[nameLower] {
			valLower := strings.ToLower(strings.TrimSpace(attr.Value))
			if strings.HasPrefix(valLower, "javascript:") {
				threats = append(threats, Threat{
					Type:        "javascript_uri",
					Location:    fmt.Sprintf("%s attribute on <%s>", attr.Name.Local, elem.Name.Local),
					Description: fmt.Sprintf("javascript: URI in %s attribute stripped", attr.Name.Local),
					Severity:    "critical",
				})
				// Replace with empty value instead of removing entirely.
				attr.Value = ""
				clean = append(clean, attr)
				continue
			}
		}

		// Strip external references (http:// / https://) on href and
		// xlink:href for all elements, not just <use>.
		if fullNameLower == "href" || fullNameLower == "xlink:href" || nameLower == "href" {
			valLower := strings.ToLower(strings.TrimSpace(attr.Value))
			if strings.HasPrefix(valLower, "http://") || strings.HasPrefix(valLower, "https://") {
				threats = append(threats, Threat{
					Type:        "external_ref",
					Location:    fmt.Sprintf("%s attribute on <%s>", attr.Name.Local, elem.Name.Local),
					Description: fmt.Sprintf("External reference %q stripped", attr.Value),
					Severity:    "medium",
				})
				continue // strip the attribute entirely
			}
		}

		// Strip inline style attributes containing dangerous CSS.
		if nameLower == "style" {
			valLower := strings.ToLower(attr.Value)
			dangerous := false
			for _, pat := range dangerousInlineStylePatterns {
				if strings.Contains(valLower, pat) {
					dangerous = true
					break
				}
			}
			if dangerous {
				threats = append(threats, Threat{
					Type:        "dangerous_css",
					Location:    fmt.Sprintf("style attribute on <%s>", elem.Name.Local),
					Description: "Dangerous CSS in inline style attribute stripped",
					Severity:    "high",
				})
				continue // strip the attribute entirely
			}
		}

		clean = append(clean, attr)
	}

	return clean, threats
}

