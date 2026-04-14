package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetrics_IncFilesProcessed(t *testing.T) {
	m := New()
	m.IncFilesProcessed("pdf", "sanitized")
	m.IncFilesProcessed("pdf", "sanitized")
	m.IncFilesProcessed("docx", "clean")

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `sluice_files_processed_total{type="pdf",result="sanitized"} 2`) {
		t.Errorf("expected pdf sanitized=2, got:\n%s", body)
	}
	if !strings.Contains(body, `sluice_files_processed_total{type="docx",result="clean"} 1`) {
		t.Errorf("expected docx clean=1, got:\n%s", body)
	}
}

func TestMetrics_IncThreatsRemoved(t *testing.T) {
	m := New()
	m.IncThreatsRemoved("macro")
	m.IncThreatsRemoved("macro")
	m.IncThreatsRemoved("javascript")

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `sluice_threats_removed_total{type="macro"} 2`) {
		t.Errorf("expected macro=2, got:\n%s", body)
	}
	if !strings.Contains(body, `sluice_threats_removed_total{type="javascript"} 1`) {
		t.Errorf("expected javascript=1, got:\n%s", body)
	}
}

func TestMetrics_ObserveDuration(t *testing.T) {
	m := New()
	m.ObserveDuration(0.05)
	m.ObserveDuration(0.5)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `sluice_sanitize_duration_seconds_count 2`) {
		t.Errorf("expected count=2, got:\n%s", body)
	}
}

func TestMetrics_Gauges(t *testing.T) {
	m := New()
	m.ActiveWorkers.Store(3)
	m.QueueDepth.Store(7)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, "sluice_active_workers 3") {
		t.Errorf("expected active_workers=3, got:\n%s", body)
	}
	if !strings.Contains(body, "sluice_queue_depth 7") {
		t.Errorf("expected queue_depth=7, got:\n%s", body)
	}
}

func TestMetrics_ContentType(t *testing.T) {
	m := New()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))

	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got: %s", ct)
	}
}
