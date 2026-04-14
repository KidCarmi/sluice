package sanitizer

import (
	"context"
	"strings"
	"testing"
)

func TestSVGSanitizer_SupportedTypes(t *testing.T) {
	s := NewSVGSanitizer(testLogger())
	types := s.SupportedTypes()

	if len(types) != 1 {
		t.Fatalf("expected 1 supported type, got %d", len(types))
	}
	if types[0] != FileTypeSVG {
		t.Errorf("expected FileTypeSVG, got %s", types[0])
	}
}

func TestSVGSanitizer_CleanSVG(t *testing.T) {
	s := NewSVGSanitizer(testLogger())
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="red"/>
</svg>`)

	result, err := s.Sanitize(context.Background(), svg, "clean.svg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Errorf("expected StatusClean, got %d", result.Status)
	}
	if len(result.Threats) != 0 {
		t.Errorf("expected no threats, got %d", len(result.Threats))
	}
	if len(result.SanitizedData) == 0 {
		t.Fatal("sanitized data is empty")
	}
}

func TestSVGSanitizer_StripScript(t *testing.T) {
	s := NewSVGSanitizer(testLogger())
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="red"/>
  <script>alert('xss')</script>
</svg>`)

	result, err := s.Sanitize(context.Background(), svg, "script.svg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	foundScript := false
	for _, threat := range result.Threats {
		if threat.Type == "script" {
			foundScript = true
		}
	}
	if !foundScript {
		t.Error("expected 'script' threat to be detected")
	}

	// The sanitized output must not contain a <script> element.
	out := strings.ToLower(string(result.SanitizedData))
	if strings.Contains(out, "<script") {
		t.Error("sanitized output still contains <script>")
	}
	if strings.Contains(out, "alert") {
		t.Error("sanitized output still contains script content")
	}
}

func TestSVGSanitizer_StripEventHandler(t *testing.T) {
	s := NewSVGSanitizer(testLogger())
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="red" onclick="alert(1)"/>
</svg>`)

	result, err := s.Sanitize(context.Background(), svg, "onclick.svg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	foundHandler := false
	for _, threat := range result.Threats {
		if threat.Type == "event_handler" {
			foundHandler = true
		}
	}
	if !foundHandler {
		t.Error("expected 'event_handler' threat to be detected")
	}

	out := strings.ToLower(string(result.SanitizedData))
	if strings.Contains(out, "onclick") {
		t.Error("sanitized output still contains onclick attribute")
	}
}

func TestSVGSanitizer_StripJavascriptURI(t *testing.T) {
	s := NewSVGSanitizer(testLogger())
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <a href="javascript:alert(1)"><text>Click me</text></a>
</svg>`)

	result, err := s.Sanitize(context.Background(), svg, "jsuri.svg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	foundJSURI := false
	for _, threat := range result.Threats {
		if threat.Type == "javascript_uri" {
			foundJSURI = true
		}
	}
	if !foundJSURI {
		t.Error("expected 'javascript_uri' threat to be detected")
	}

	out := strings.ToLower(string(result.SanitizedData))
	if strings.Contains(out, "javascript:") {
		t.Error("sanitized output still contains javascript: URI")
	}
}

func TestSVGSanitizer_StripForeignObject(t *testing.T) {
	s := NewSVGSanitizer(testLogger())
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="red"/>
  <foreignObject width="100" height="100">
    <div xmlns="http://www.w3.org/1999/xhtml">Hello</div>
  </foreignObject>
</svg>`)

	result, err := s.Sanitize(context.Background(), svg, "foreign.svg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	foundFO := false
	for _, threat := range result.Threats {
		if threat.Type == "foreign_object" {
			foundFO = true
		}
	}
	if !foundFO {
		t.Error("expected 'foreign_object' threat to be detected")
	}

	out := strings.ToLower(string(result.SanitizedData))
	if strings.Contains(out, "<foreignobject") {
		t.Error("sanitized output still contains <foreignObject>")
	}
}

func TestSVGSanitizer_StripOnload(t *testing.T) {
	s := NewSVGSanitizer(testLogger())
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" onload="alert(1)">
  <circle cx="50" cy="50" r="40" fill="red"/>
</svg>`)

	result, err := s.Sanitize(context.Background(), svg, "onload.svg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	foundHandler := false
	for _, threat := range result.Threats {
		if threat.Type == "event_handler" {
			foundHandler = true
		}
	}
	if !foundHandler {
		t.Error("expected 'event_handler' threat to be detected for onload")
	}

	out := strings.ToLower(string(result.SanitizedData))
	if strings.Contains(out, "onload") {
		t.Error("sanitized output still contains onload attribute")
	}
}

func TestSVGSanitizer_MultipleThreats(t *testing.T) {
	s := NewSVGSanitizer(testLogger())
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <script>alert('xss')</script>
  <circle cx="50" cy="50" r="40" fill="red" onclick="alert(1)"/>
  <a href="javascript:alert(2)"><text>Click</text></a>
</svg>`)

	result, err := s.Sanitize(context.Background(), svg, "multi.svg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	found := map[string]bool{
		"script":         false,
		"event_handler":  false,
		"javascript_uri": false,
	}
	for _, threat := range result.Threats {
		if _, ok := found[threat.Type]; ok {
			found[threat.Type] = true
		}
	}
	for typ, seen := range found {
		if !seen {
			t.Errorf("expected threat type %q to be detected", typ)
		}
	}

	out := strings.ToLower(string(result.SanitizedData))
	if strings.Contains(out, "<script") {
		t.Error("sanitized output still contains <script>")
	}
	if strings.Contains(out, "onclick") {
		t.Error("sanitized output still contains onclick")
	}
	if strings.Contains(out, "javascript:") {
		t.Error("sanitized output still contains javascript: URI")
	}
}

func TestSVGSanitizer_PreservesVisualContent(t *testing.T) {
	s := NewSVGSanitizer(testLogger())
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="red"/>
  <rect x="10" y="10" width="30" height="30" fill="blue"/>
  <script>alert('xss')</script>
</svg>`)

	result, err := s.Sanitize(context.Background(), svg, "visual.svg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	out := strings.ToLower(string(result.SanitizedData))
	if !strings.Contains(out, "<circle") {
		t.Error("sanitized output is missing <circle> element")
	}
	if !strings.Contains(out, "<rect") {
		t.Error("sanitized output is missing <rect> element")
	}
	if !strings.Contains(out, "<svg") {
		t.Error("sanitized output is missing <svg> root element")
	}
}

func TestSVGSanitizer_EmptyFile(t *testing.T) {
	s := NewSVGSanitizer(testLogger())

	result, err := s.Sanitize(context.Background(), []byte{}, "empty.svg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusError {
		t.Errorf("expected StatusError, got %d", result.Status)
	}
	if result.Error == nil {
		t.Error("expected non-nil Result.Error for empty input")
	}
}

func TestSVGSanitizer_InvalidXML(t *testing.T) {
	s := NewSVGSanitizer(testLogger())
	// Malformed XML that starts with <svg but is not valid.
	data := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><circle`)

	result, err := s.Sanitize(context.Background(), data, "invalid.svg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusError {
		t.Errorf("expected StatusError, got %d", result.Status)
	}
	if result.Error == nil {
		t.Error("expected non-nil Result.Error for invalid XML")
	}
}

func TestSVGSanitizer_ContextCancellation(t *testing.T) {
	s := NewSVGSanitizer(testLogger())
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="red"/>
</svg>`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := s.Sanitize(ctx, svg, "cancelled.svg")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func FuzzSVGSanitizer(f *testing.F) {
	f.Add([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><circle cx="50" cy="50" r="40"/></svg>`))
	f.Add([]byte(`<svg><script>alert(1)</script></svg>`))
	f.Add([]byte(`<svg onload="alert(1)"><circle/></svg>`))
	f.Add([]byte{})
	f.Add([]byte(`not xml at all`))
	f.Add([]byte(`<?xml version="1.0"?><svg></svg>`))

	s := NewSVGSanitizer(testLogger())

	f.Fuzz(func(t *testing.T, data []byte) {
		// The sanitizer must never panic on arbitrary input.
		_, _ = s.Sanitize(context.Background(), data, "fuzz.svg")
	})
}
