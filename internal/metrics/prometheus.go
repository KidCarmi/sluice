package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
)

// Metrics holds all Prometheus-style counters and gauges.
// For the MVP we implement a simple /metrics endpoint without pulling in
// the full Prometheus client library — keeps deps minimal.
type Metrics struct {
	FilesProcessed  counterVec
	ThreatsRemoved  counterVec
	SanitizeDuration histogramSimple
	ActiveWorkers   atomic.Int64
	QueueDepth      atomic.Int64
	FileSize        histogramSimple
}

// New creates a zeroed Metrics instance.
func New() *Metrics {
	return &Metrics{
		FilesProcessed: counterVec{counts: make(map[string]map[string]*atomic.Int64)},
		ThreatsRemoved: counterVec{counts: make(map[string]map[string]*atomic.Int64)},
		SanitizeDuration: histogramSimple{
			buckets: []float64{0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0},
			counts:  make([]atomic.Int64, 8),
		},
		FileSize: histogramSimple{
			buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 52428800},
			counts:  make([]atomic.Int64, 6),
		},
	}
}

// IncFilesProcessed increments the files_processed counter for a given type and result.
func (m *Metrics) IncFilesProcessed(fileType, result string) {
	m.FilesProcessed.Inc(fileType, result)
}

// IncThreatsRemoved increments the threats_removed counter for a given threat type.
func (m *Metrics) IncThreatsRemoved(threatType string) {
	m.ThreatsRemoved.Inc(threatType, "")
}

// ObserveDuration records a sanitization duration in seconds.
func (m *Metrics) ObserveDuration(seconds float64) {
	m.SanitizeDuration.Observe(seconds)
}

// ObserveFileSize records a file size in bytes.
func (m *Metrics) ObserveFileSize(bytes float64) {
	m.FileSize.Observe(bytes)
}

// Handler returns an HTTP handler that serves /metrics in Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		// Files processed
		m.FilesProcessed.mu.RLock()
		for label1, inner := range m.FilesProcessed.counts {
			for label2, val := range inner {
				if label2 == "" {
					_, _ = fmt.Fprintf(w, "sluice_files_processed_total{type=%q} %d\n", label1, val.Load())
				} else {
					_, _ = fmt.Fprintf(w, "sluice_files_processed_total{type=%q,result=%q} %d\n", label1, label2, val.Load())
				}
			}
		}
		m.FilesProcessed.mu.RUnlock()

		// Threats removed
		m.ThreatsRemoved.mu.RLock()
		for label1, inner := range m.ThreatsRemoved.counts {
			for _, val := range inner {
				_, _ = fmt.Fprintf(w, "sluice_threats_removed_total{type=%q} %d\n", label1, val.Load())
			}
		}
		m.ThreatsRemoved.mu.RUnlock()

		// Duration histogram
		for i, bucket := range m.SanitizeDuration.buckets {
			_, _ = fmt.Fprintf(w, "sluice_sanitize_duration_seconds_bucket{le=\"%.2f\"} %d\n", bucket, m.SanitizeDuration.counts[i].Load())
		}
		_, _ = fmt.Fprintf(w, "sluice_sanitize_duration_seconds_count %d\n", m.SanitizeDuration.count.Load())

		// Gauges
		_, _ = fmt.Fprintf(w, "sluice_active_workers %d\n", m.ActiveWorkers.Load())
		_, _ = fmt.Fprintf(w, "sluice_queue_depth %d\n", m.QueueDepth.Load())

		// File size histogram
		for i, bucket := range m.FileSize.buckets {
			_, _ = fmt.Fprintf(w, "sluice_file_size_bytes_bucket{le=\"%.0f\"} %d\n", bucket, m.FileSize.counts[i].Load())
		}
	})
}

// counterVec is a simple two-label counter vector using atomic counters.
type counterVec struct {
	mu     sync.RWMutex
	counts map[string]map[string]*atomic.Int64
}

func (c *counterVec) Inc(label1, label2 string) {
	c.mu.RLock()
	if inner, ok := c.counts[label1]; ok {
		if val, ok := inner[label2]; ok {
			val.Add(1)
			c.mu.RUnlock()
			return
		}
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.counts[label1]; !ok {
		c.counts[label1] = make(map[string]*atomic.Int64)
	}
	if _, ok := c.counts[label1][label2]; !ok {
		c.counts[label1][label2] = &atomic.Int64{}
	}
	c.counts[label1][label2].Add(1)
}

// histogramSimple is a minimal histogram with fixed buckets.
type histogramSimple struct {
	buckets []float64
	counts  []atomic.Int64
	sum     atomic.Int64 // stored as fixed-point (x1000)
	count   atomic.Int64
}

func (h *histogramSimple) Observe(value float64) {
	h.count.Add(1)
	h.sum.Add(int64(value * 1000))
	for i, b := range h.buckets {
		if value <= b {
			h.counts[i].Add(1)
		}
	}
}

