package worker

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// echoFunc is a simple ProcessFunc that returns the job ID.
func echoFunc(_ context.Context, job Job) (interface{}, error) {
	return job.ID, nil
}

func TestBasicSubmit(t *testing.T) {
	pool := NewPool(PoolConfig{MaxWorkers: 2, QueueDepth: 5, JobTimeout: time.Second}, echoFunc)
	defer pool.Stop()

	job := Job{ID: "job-1", Data: []byte("hello"), Filename: "test.txt"}
	res, err := pool.Submit(context.Background(), job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ID != "job-1" {
		t.Fatalf("expected ID job-1, got %s", res.ID)
	}
	if res.Result != "job-1" {
		t.Fatalf("expected result job-1, got %v", res.Result)
	}
	if res.Error != nil {
		t.Fatalf("unexpected job error: %v", res.Error)
	}
}

func TestConcurrentWorkers(t *testing.T) {
	const maxWorkers = 5

	var running atomic.Int64
	var maxSeen atomic.Int64

	slowFunc := func(_ context.Context, job Job) (interface{}, error) {
		cur := running.Add(1)
		defer running.Add(-1)

		// Track peak concurrency.
		for {
			old := maxSeen.Load()
			if cur <= old || maxSeen.CompareAndSwap(old, cur) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		return job.ID, nil
	}

	pool := NewPool(PoolConfig{MaxWorkers: maxWorkers, QueueDepth: maxWorkers * 2, JobTimeout: 5 * time.Second}, slowFunc)
	defer pool.Stop()

	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			job := Job{ID: fmt.Sprintf("job-%d", i)}
			res, err := pool.Submit(context.Background(), job)
			if err != nil {
				t.Errorf("submit error for job-%d: %v", i, err)
				return
			}
			if res.Error != nil {
				t.Errorf("job error for job-%d: %v", i, res.Error)
			}
		}(i)
	}
	wg.Wait()

	if peak := maxSeen.Load(); peak > int64(maxWorkers) {
		t.Fatalf("peak concurrency %d exceeded max workers %d", peak, maxWorkers)
	}
}

func TestBackpressure(t *testing.T) {
	const queueDepth = 2
	const maxWorkers = 1

	// blockCh keeps workers busy so the queue fills up.
	blockCh := make(chan struct{})
	blockFunc := func(_ context.Context, _ Job) (interface{}, error) {
		<-blockCh
		return nil, nil
	}

	pool := NewPool(PoolConfig{MaxWorkers: maxWorkers, QueueDepth: queueDepth, JobTimeout: 5 * time.Second}, blockFunc)
	defer func() {
		close(blockCh)
		pool.Stop()
	}()

	// Each Submit takes one queue slot. With queueDepth=2, we can have 2
	// in-flight jobs before backpressure kicks in.
	for i := 0; i < queueDepth; i++ {
		go func(i int) {
			_, _ = pool.Submit(context.Background(), Job{ID: fmt.Sprintf("fill-%d", i)})
		}(i)
	}

	// Wait for the goroutines to acquire their queue slots.
	time.Sleep(100 * time.Millisecond)

	// The next submit should fail with a queue-full error.
	_, err := pool.Submit(context.Background(), Job{ID: "overflow"})
	if err == nil {
		t.Fatal("expected backpressure error, got nil")
	}
}

func TestTimeout(t *testing.T) {
	slowFunc := func(ctx context.Context, _ Job) (interface{}, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return "done", nil
		}
	}

	pool := NewPool(PoolConfig{MaxWorkers: 2, QueueDepth: 5, JobTimeout: 50 * time.Millisecond}, slowFunc)
	defer pool.Stop()

	res, err := pool.Submit(context.Background(), Job{ID: "slow-job"})
	if err != nil {
		t.Fatalf("submit error: %v", err)
	}
	if res.Error == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestPanicRecovery(t *testing.T) {
	panicFunc := func(_ context.Context, _ Job) (interface{}, error) {
		panic("kaboom")
	}

	pool := NewPool(PoolConfig{MaxWorkers: 2, QueueDepth: 5, JobTimeout: time.Second}, panicFunc)
	defer pool.Stop()

	res, err := pool.Submit(context.Background(), Job{ID: "panic-job"})
	if err != nil {
		t.Fatalf("submit error: %v", err)
	}
	if res.Error == nil {
		t.Fatal("expected panic error, got nil")
	}
	if res.ID != "panic-job" {
		t.Fatalf("expected ID panic-job, got %s", res.ID)
	}
}

func TestGracefulShutdown(t *testing.T) {
	var completed atomic.Int64

	slowFunc := func(_ context.Context, _ Job) (interface{}, error) {
		time.Sleep(50 * time.Millisecond)
		completed.Add(1)
		return "ok", nil
	}

	pool := NewPool(PoolConfig{MaxWorkers: 3, QueueDepth: 10, JobTimeout: 5 * time.Second}, slowFunc)

	const n = 5
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = pool.Submit(context.Background(), Job{ID: fmt.Sprintf("job-%d", i)})
		}(i)
	}

	// Give submissions time to enqueue.
	time.Sleep(20 * time.Millisecond)

	pool.Stop()
	wg.Wait()

	if c := completed.Load(); c != n {
		t.Fatalf("expected %d completed jobs, got %d", n, c)
	}
}

func TestActiveWorkersCounter(t *testing.T) {
	blockCh := make(chan struct{})
	blockFunc := func(_ context.Context, _ Job) (interface{}, error) {
		<-blockCh
		return nil, nil
	}

	pool := NewPool(PoolConfig{MaxWorkers: 5, QueueDepth: 10, JobTimeout: 5 * time.Second}, blockFunc)
	defer func() {
		close(blockCh)
		pool.Stop()
	}()

	// Submit 3 blocking jobs.
	for i := 0; i < 3; i++ {
		go func(i int) { _, _ = pool.Submit(context.Background(), Job{ID: fmt.Sprintf("block-%d", i)}) }(i)
	}

	// Wait for workers to spin up.
	time.Sleep(100 * time.Millisecond)

	active := pool.ActiveWorkers()
	if active != 3 {
		t.Fatalf("expected 3 active workers, got %d", active)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := PoolConfig{}.defaults()
	if cfg.MaxWorkers != 10 {
		t.Fatalf("expected default MaxWorkers 10, got %d", cfg.MaxWorkers)
	}
	if cfg.QueueDepth != 50 {
		t.Fatalf("expected default QueueDepth 50, got %d", cfg.QueueDepth)
	}
	if cfg.JobTimeout != 30*time.Second {
		t.Fatalf("expected default JobTimeout 30s, got %v", cfg.JobTimeout)
	}
}

func TestSubmitAfterStop(t *testing.T) {
	pool := NewPool(PoolConfig{MaxWorkers: 2, QueueDepth: 5, JobTimeout: time.Second}, echoFunc)
	pool.Stop()

	_, err := pool.Submit(context.Background(), Job{ID: "late"})
	if err == nil {
		t.Fatal("expected error submitting to stopped pool, got nil")
	}
}
