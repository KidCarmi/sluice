package worker

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Job represents a unit of work to be processed by the pool.
type Job struct {
	ID       string
	Data     []byte
	Filename string
}

// JobResult holds the outcome of processing a single Job.
type JobResult struct {
	ID     string
	Result interface{} // Will hold *sanitizer.Result in practice
	Error  error
}

// ProcessFunc is the function signature that workers execute for each job.
type ProcessFunc func(ctx context.Context, job Job) (interface{}, error)

// PoolConfig controls pool sizing and timeouts.
type PoolConfig struct {
	MaxWorkers int
	QueueDepth int
	JobTimeout time.Duration
}

// defaults applies sensible defaults to zero-valued config fields.
func (c PoolConfig) defaults() PoolConfig {
	if c.MaxWorkers <= 0 {
		c.MaxWorkers = 10
	}
	if c.QueueDepth <= 0 {
		c.QueueDepth = 50
	}
	if c.JobTimeout <= 0 {
		c.JobTimeout = 30 * time.Second
	}
	return c
}

// Pool is a bounded worker pool with backpressure and per-job timeouts.
type Pool struct {
	cfg PoolConfig
	fn  ProcessFunc
	sem chan struct{} // buffered to MaxWorkers; acts as a concurrency semaphore

	// mu protects the stopped flag and coordinates with wg so that
	// Stop() never calls wg.Wait() while a Submit is between the
	// stopped check and wg.Add(1).
	mu      sync.Mutex
	wg      sync.WaitGroup
	stopped bool

	// queue is a buffered channel used purely for backpressure accounting.
	// When a Submit cannot push into this channel without blocking, the
	// queue is full and Submit returns an error immediately.
	queue chan struct{}

	activeWorkers atomic.Int64
}

// NewPool creates a Pool ready to accept work. Call Stop() when done.
func NewPool(cfg PoolConfig, fn ProcessFunc) *Pool {
	cfg = cfg.defaults()
	return &Pool{
		cfg:   cfg,
		fn:    fn,
		sem:   make(chan struct{}, cfg.MaxWorkers),
		queue: make(chan struct{}, cfg.QueueDepth),
	}
}

// Submit enqueues a job and blocks until the result is available.
// It returns an error immediately if the queue is full (backpressure)
// or if the pool has been stopped.
func (p *Pool) Submit(ctx context.Context, job Job) (*JobResult, error) {
	// Lock to coordinate stopped check + wg.Add atomically with Stop().
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return nil, fmt.Errorf("submit: pool is stopped")
	}

	// Try to enqueue — non-blocking check for backpressure.
	select {
	case p.queue <- struct{}{}:
		// Slot acquired; will be released when the job completes.
	default:
		p.mu.Unlock()
		return nil, fmt.Errorf("submit: queue full (depth %d)", p.cfg.QueueDepth)
	}

	// Track this in-flight job for graceful shutdown.
	p.wg.Add(1)
	p.mu.Unlock()

	resultCh := make(chan JobResult, 1)

	go func() {
		defer func() {
			<-p.queue // release queue slot
			p.wg.Done()
		}()

		// Acquire a worker slot — blocks until one is free but respects
		// the caller's context cancellation.
		select {
		case p.sem <- struct{}{}:
			// Got a worker slot.
		case <-ctx.Done():
			resultCh <- JobResult{ID: job.ID, Error: fmt.Errorf("submit: %w", ctx.Err())}
			return
		}

		p.activeWorkers.Add(1)
		defer func() {
			<-p.sem
			p.activeWorkers.Add(-1)
		}()

		resultCh <- p.execute(ctx, job)
	}()

	// Wait for result or caller cancellation.
	select {
	case res := <-resultCh:
		return &res, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("submit: %w", ctx.Err())
	}
}

// Stop signals the pool to stop accepting new work, then waits for all
// in-flight jobs to complete.
func (p *Pool) Stop() {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()

	p.wg.Wait()
}

// ActiveWorkers returns the number of workers currently executing jobs.
func (p *Pool) ActiveWorkers() int {
	return int(p.activeWorkers.Load())
}

// QueueDepth returns the number of jobs waiting in the queue.
func (p *Pool) QueueDepth() int {
	return len(p.queue)
}

// execute runs the process function for a single job, handling panics
// and per-job timeouts.
func (p *Pool) execute(parent context.Context, job Job) JobResult {
	ctx, cancel := context.WithTimeout(parent, p.cfg.JobTimeout)
	defer cancel()

	result := JobResult{ID: job.ID}

	func() {
		defer func() {
			if r := recover(); r != nil {
				result.Error = fmt.Errorf("execute: panic recovered: %v", r)
			}
		}()

		res, err := p.fn(ctx, job)
		if err != nil {
			result.Error = fmt.Errorf("execute: %w", err)
		} else {
			result.Result = res
		}
	}()

	return result
}
