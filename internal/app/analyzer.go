// Package app provides the core application orchestration layer for LogRadar.
//
// The Analyzer component coordinates log reading, threat detection, and alert
// dispatch through a concurrent worker pool architecture optimized for
// high-throughput (>50K lines/second) production workloads.
package app

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/internal/ports"
)

// Analyzer orchestrates the log analysis pipeline from input to output.
//
// Responsibilities:
//   - Coordinates log reader startup and shutdown
//   - Manages worker pool lifecycle
//   - Collects and exposes runtime metrics
//   - Handles graceful shutdown with timeout
//
// Thread Safety:
//   - Safe for concurrent method calls via internal mutex
//   - Alert subscribers notified synchronously from worker goroutines
//
// Lifecycle:
//  1. Create with NewAnalyzer()
//  2. Configure via SetWorkerConfig() (before start)
//  3. Add subscribers via AddAlertSubscriber()
//  4. Start with Start(ctx) or Run(ctx)
//  5. Stop with Stop() or context cancellation
type Analyzer struct {
	reader     ports.LogReader         // Log entry source (FileTailer or DemoGenerator)
	workerPool *WorkerPool             // Concurrent detection pipeline
	metrics    *domain.AnalysisMetrics // Runtime metrics collector
	alertSubs  []ports.AlertSubscriber // Notification callbacks

	ctx     context.Context    // Lifecycle context
	cancel  context.CancelFunc // Shutdown trigger
	wg      sync.WaitGroup     // Goroutine completion tracking
	running bool               // Running state flag
	mu      sync.RWMutex       // Protects running flag and alertSubs

	lastLinesProcessed int64     // For LPS calculation
	lastLPSCheck       time.Time // For LPS calculation
}

// AnalyzerConfig aggregates configuration for the analyzer and its components.
type AnalyzerConfig struct {
	WorkerConfig WorkerPoolConfig // Worker pool configuration
}

// NewAnalyzer creates an Analyzer with the specified components.
//
// Parameters:
//   - reader: Log source (FileTailer for production, DemoGenerator for testing)
//   - detectors: Slice of threat detectors to apply to each entry
//   - alerters: Slice of alert outputs (JSON, memory, etc.)
//
// Returns:
//   - Configured Analyzer ready for Start()
//
// Example:
//
//	reader := input.NewFileTailer(path, parser, bufferSize)
//	detectors := []ports.ThreatDetector{sigDetector, behavDetector}
//	alerters := []ports.Alerter{memAlerter, jsonAlerter}
//	analyzer := app.NewAnalyzer(reader, detectors, alerters)
func NewAnalyzer(
	reader ports.LogReader,
	detectors []ports.ThreatDetector,
	alerters []ports.Alerter,
) *Analyzer {
	metrics := domain.NewAnalysisMetrics()

	workerPool := NewWorkerPool(DefaultWorkerPoolConfig(), detectors, alerters, metrics)

	return &Analyzer{
		reader:       reader,
		workerPool:   workerPool,
		metrics:      metrics,
		lastLPSCheck: time.Now(),
	}
}

// SetWorkerConfig updates worker pool configuration before startup.
//
// Parameters:
//   - config: Worker pool settings (worker count, buffer sizes)
//
// Precondition: Analyzer must not be running. No-op if already started.
//
// Warning: Calling this after Start() has no effect and logs a warning.
func (a *Analyzer) SetWorkerConfig(config WorkerPoolConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		log.Warn().Msg("Cannot change worker config while running")
		return
	}

	a.workerPool = NewWorkerPool(config, a.workerPool.detectors, a.workerPool.alerters, a.metrics)
}

// AddAlertSubscriber registers a callback for alert notifications.
//
// Parameters:
//   - sub: Subscriber to notify when alerts are generated
//
// Thread Safety: Safe to call before or during operation.
// Subscribers added after start will receive new alerts immediately.
func (a *Analyzer) AddAlertSubscriber(sub ports.AlertSubscriber) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alertSubs = append(a.alertSubs, sub)
	a.workerPool.AddSubscriber(sub)
}

// Start begins asynchronous log analysis.
//
// Parameters:
//   - ctx: Context for lifecycle management (cancellation triggers shutdown)
//
// Returns:
//   - nil on successful startup
//   - nil if already running (idempotent)
//
// Behavior:
//   - Starts worker pool
//   - Starts log reader
//   - Spawns goroutines for entry processing and metrics updates
//   - Returns immediately (non-blocking)
func (a *Analyzer) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return nil
	}
	a.running = true
	a.mu.Unlock()

	a.ctx, a.cancel = context.WithCancel(ctx)

	a.workerPool.Start(a.ctx)

	entryChan, errChan := a.reader.Start(a.ctx)

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.processEntries(entryChan, errChan)
	}()

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.updateMetrics()
	}()

	log.Info().Msg("Analyzer started")
	return nil
}

// processEntries reads from input channels and submits to worker pool.
// Runs in a dedicated goroutine until context cancellation or channel close.
func (a *Analyzer) processEntries(entryChan <-chan *domain.LogEntry, errChan <-chan error) {
	for {
		select {
		case <-a.ctx.Done():
			return
		case err, ok := <-errChan:
			if !ok {
				continue
			}
			log.Error().Err(err).Msg("Error reading log")
		case entry, ok := <-entryChan:
			if !ok {
				log.Info().Msg("Entry channel closed")
				return
			}
			if !a.workerPool.SubmitBlocking(a.ctx, entry) {
				log.Warn().Msg("Failed to submit entry to worker pool")
			}
		}
	}
}

// updateMetrics periodically calculates LPS and updates memory metrics.
// Runs in a dedicated goroutine until context cancellation.
func (a *Analyzer) updateMetrics() {
	ticker := time.NewTicker(1 * time.Second)
	memTicker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	defer memTicker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-memTicker.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			a.metrics.SetMemoryUsage(float64(m.Alloc) / 1024 / 1024)
		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(a.lastLPSCheck).Seconds()
			if elapsed >= 1.0 {
				currentLines := a.metrics.TotalLines()
				lps := float64(currentLines-a.lastLinesProcessed) / elapsed
				a.metrics.UpdateLPS(lps)
				a.lastLinesProcessed = currentLines
				a.lastLPSCheck = now
			}
		}
	}
}

// Stop initiates graceful shutdown of the analyzer.
//
// Behavior:
//   - Triggers context cancellation
//   - Stops log reader
//   - Drains and stops worker pool
//   - Waits for goroutine completion
//
// Thread Safety: Safe to call multiple times (idempotent).
func (a *Analyzer) Stop() {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return
	}
	a.running = false
	a.mu.Unlock()

	log.Info().Msg("Stopping analyzer gracefully...")

	if a.cancel != nil {
		a.cancel()
	}
	if err := a.reader.Stop(); err != nil {
		log.Error().Err(err).Msg("Error stopping reader")
	}

	a.workerPool.Stop()

	a.wg.Wait()

	log.Info().Msg("Analyzer stopped")
}

// Metrics returns a point-in-time snapshot of runtime metrics.
//
// Returns:
//   - MetricsSnapshot with throughput, alert counts, memory usage
//
// Thread Safety: Safe to call from any goroutine.
func (a *Analyzer) Metrics() domain.MetricsSnapshot {
	return a.metrics.GetSnapshot()
}

// InternalMetrics returns the raw metrics collector for Prometheus integration.
// Use Metrics() for point-in-time snapshots in application code.
func (a *Analyzer) InternalMetrics() *domain.AnalysisMetrics {
	return a.metrics
}

// IsRunning returns true if the analyzer is currently processing logs.
func (a *Analyzer) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// WaitForSignal blocks until SIGINT or SIGTERM is received, then stops.
// Typically used in console mode without TUI.
func (a *Analyzer) WaitForSignal() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")

	a.Stop()
}

// Run starts the analyzer and blocks until shutdown signal.
// Convenience method combining Start() and WaitForSignal().
//
// Parameters:
//   - ctx: Context for lifecycle management
//
// Returns:
//   - Error from Start() if startup fails
//   - nil on clean shutdown
func (a *Analyzer) Run(ctx context.Context) error {
	if err := a.Start(ctx); err != nil {
		return err
	}

	a.WaitForSignal()
	return nil
}
