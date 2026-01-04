// Package app provides the concurrent worker pool for threat detection.
//
// The WorkerPool manages a fixed set of worker goroutines that process log entries
// in parallel, applying threat detectors and dispatching alerts. It includes
// resilience features like backpressure, dead-letter queues, and overflow handling.
package app

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/internal/ports"
)

// ToxicMessage represents an entry that caused a worker panic.
// Used for Dead Letter Queue (DLQ) processing and forensic analysis.
type ToxicMessage struct {
	Entry     *domain.LogEntry // Clone of the problematic entry
	PanicErr  interface{}      // The panic value
	Timestamp time.Time        // When the panic occurred
	WorkerID  int              // Which worker crashed
}

// WorkerPool manages concurrent log entry processing with threat detection.
//
// Features:
//   - Fixed worker count for predictable resource usage
//   - Backpressure with configurable timeouts
//   - Dead Letter Queue for toxic message handling
//   - Overflow to disk when channels saturate
//   - Quarantine for messages causing panics
//   - Automatic worker restart on panic
//
// Thread Safety: All public methods are safe for concurrent access.
type WorkerPool struct {
	workerCount int                     // Number of worker goroutines
	inputChan   chan *domain.LogEntry   // Buffered input channel
	outputChan  chan *domain.Alert      // Buffered alert output
	detectors   []ports.ThreatDetector  // Detectors to apply
	alerters    []ports.Alerter         // Alert output destinations
	subscribers []ports.AlertSubscriber // Alert notification callbacks
	metrics     *domain.AnalysisMetrics // Runtime metrics collector
	bufferSize  int                     // Channel buffer size

	submitTimeout   time.Duration // Max wait for channel space
	useBackpressure bool          // Enable timeout-based backpressure

	dlqChan    chan *ToxicMessage // Dead Letter Queue channel
	dlqEnabled bool               // DLQ feature flag

	overflow        *OverflowWriter // Overflow file writer
	overflowEntries atomic.Int64    // Entries written to overflow
	overflowAlerts  atomic.Int64    // Alerts written to overflow

	quarantine *QuarantineWriter // Quarantine for toxic messages

	wg       sync.WaitGroup // Tracks worker goroutines
	stopOnce sync.Once      // Ensures single shutdown
	stopChan chan struct{}  // Shutdown signal
	running  bool           // Running state
	mu       sync.RWMutex   // Protects running state and subscribers
}

// WorkerPoolConfig defines worker pool configuration options.
type WorkerPoolConfig struct {
	WorkerCount    int           // Number of worker goroutines (default: 32)
	BufferSize     int           // Input/output channel buffer (default: 50000)
	SubmitTimeout  time.Duration // Backpressure timeout (default: 100ms)
	EnableDLQ      bool          // Enable Dead Letter Queue (default: true)
	DLQSize        int           // DLQ channel buffer (default: 1000)
	OverflowPath   string        // Path for overflow file (empty disables)
	QuarantinePath string        // Path for quarantine file (empty disables)
}

// DefaultWorkerPoolConfig returns production-ready default configuration.
func DefaultWorkerPoolConfig() WorkerPoolConfig {
	return WorkerPoolConfig{
		WorkerCount:    32,
		BufferSize:     50000,
		SubmitTimeout:  100 * time.Millisecond,
		EnableDLQ:      true,
		DLQSize:        1000,
		OverflowPath:   "",
		QuarantinePath: "",
	}
}

// NewWorkerPool creates a configured worker pool.
//
// Parameters:
//   - config: Pool configuration options
//   - detectors: Threat detectors to apply to each entry
//   - alerters: Alert output destinations
//   - metrics: Runtime metrics collector
//
// Returns:
//   - Configured WorkerPool ready for Start()
func NewWorkerPool(config WorkerPoolConfig, detectors []ports.ThreatDetector, alerters []ports.Alerter, metrics *domain.AnalysisMetrics) *WorkerPool {
	if config.WorkerCount <= 0 {
		config.WorkerCount = 4
	}
	if config.BufferSize <= 0 {
		config.BufferSize = 1000
	}
	if config.DLQSize <= 0 {
		config.DLQSize = 100
	}
	if config.SubmitTimeout <= 0 {
		config.SubmitTimeout = 100 * time.Millisecond
	}

	wp := &WorkerPool{
		workerCount:     config.WorkerCount,
		inputChan:       make(chan *domain.LogEntry, config.BufferSize),
		outputChan:      make(chan *domain.Alert, config.BufferSize),
		detectors:       detectors,
		alerters:        alerters,
		metrics:         metrics,
		bufferSize:      config.BufferSize,
		submitTimeout:   config.SubmitTimeout,
		useBackpressure: config.SubmitTimeout > 0,
		dlqEnabled:      config.EnableDLQ,
		stopChan:        make(chan struct{}),
	}

	if config.EnableDLQ {
		wp.dlqChan = make(chan *ToxicMessage, config.DLQSize)
	}

	if config.OverflowPath != "" {
		overflow, err := NewOverflowWriter(config.OverflowPath)
		if err != nil {
			log.Error().Err(err).Str("path", config.OverflowPath).Msg("Failed to create overflow writer")
		} else {
			wp.overflow = overflow
		}
	}

	if config.QuarantinePath != "" {
		quarantine, err := NewQuarantineWriter(config.QuarantinePath)
		if err != nil {
			log.Error().Err(err).Str("path", config.QuarantinePath).Msg("Failed to create quarantine writer")
		} else {
			wp.quarantine = quarantine
		}
	}

	return wp
}

// Start launches worker goroutines and alert dispatcher.
//
// Parameters:
//   - ctx: Context for lifecycle management
//
// Behavior:
//   - Spawns WorkerCount worker goroutines
//   - Spawns alert dispatcher goroutine
//   - Updates metrics with worker count
//   - Idempotent (safe to call multiple times)
func (wp *WorkerPool) Start(ctx context.Context) {
	wp.mu.Lock()
	if wp.running {
		wp.mu.Unlock()
		return
	}
	wp.running = true
	wp.mu.Unlock()

	for i := 0; i < wp.workerCount; i++ {
		wp.wg.Add(1)
		go wp.worker(ctx, i)
	}

	wp.wg.Add(1)
	go wp.alertDispatcher(ctx)

	if wp.metrics != nil {
		wp.metrics.SetActiveWorkers(wp.workerCount)
	}

	log.Info().
		Int("workers", wp.workerCount).
		Bool("backpressure", wp.useBackpressure).
		Bool("dlq", wp.dlqEnabled).
		Msg("Worker pool started")
}

// worker is the main processing loop for a single worker goroutine.
// It reads entries from the input channel, applies detectors, and generates alerts.
// Includes panic recovery with automatic restart.
func (wp *WorkerPool) worker(ctx context.Context, id int) {
	defer wp.wg.Done()

	var currentEntry *domain.LogEntry

	// Panic recovery with worker restart and toxic message handling
	defer func() {
		if r := recover(); r != nil {
			log.Error().
				Interface("panic", r).
				Int("worker_id", id).
				Msg("Worker panic recovered")

			// Write to quarantine file
			if wp.quarantine != nil && wp.quarantine.Enabled() {
				if err := wp.quarantine.WriteToxicMessage(id, r, currentEntry); err != nil {
					log.Error().Err(err).Int("worker_id", id).Msg("Failed to quarantine toxic message")
				}
			}

			// Send to DLQ for potential reprocessing
			if wp.dlqEnabled && currentEntry != nil {
				select {
				case wp.dlqChan <- &ToxicMessage{
					Entry:     currentEntry.Clone(),
					PanicErr:  r,
					Timestamp: time.Now(),
					WorkerID:  id,
				}:
					log.Debug().Int("worker_id", id).Msg("Toxic message sent to DLQ")
				default:
					log.Warn().Int("worker_id", id).Msg("DLQ full, toxic message only in quarantine file")
				}
			}

			// Restart worker
			wp.wg.Add(1)
			go wp.worker(ctx, id)
		}
	}()

	log.Debug().Int("worker_id", id).Msg("Worker started")

	for {
		select {
		case <-ctx.Done():
			log.Debug().Int("worker_id", id).Msg("Worker stopped (context cancelled)")
			return
		case <-wp.stopChan:
			log.Debug().Int("worker_id", id).Msg("Worker stopped (stop signal)")
			return
		case entry, ok := <-wp.inputChan:
			if !ok {
				log.Debug().Int("worker_id", id).Msg("Worker stopped (input channel closed)")
				return
			}

			currentEntry = entry
			lineHasThreat := false

			// Apply all detectors
			for _, detector := range wp.detectors {
				result := detector.Detect(ctx, entry)
				if result.Detected {
					alert := domain.NewAlert(
						entry.IP,
						result.ThreatType,
						result.Level,
						entry.RawLine,
						result.RiskScore,
						result.Message,
					)

					// Add detector metadata
					for k, v := range result.Details {
						if str, ok := v.(string); ok {
							alert.AddMetadata(k, str)
						}
					}
					alert.AddMetadata("detector", detector.Name())

					if entry.Truncated {
						alert.AddMetadata("truncated", "true")
					}

					if wp.sendAlert(alert) {
						if wp.metrics != nil {
							wp.metrics.IncrementAlerts()
						}
						lineHasThreat = true
					}
				}
			}

			if lineHasThreat && wp.metrics != nil {
				wp.metrics.IncrementMaliciousLines()
			}

			if wp.metrics != nil {
				wp.metrics.IncrementLines()
			}

			currentEntry = nil
			domain.ReleaseLogEntry(entry)
		}
	}
}

// sendAlert attempts to send an alert to the output channel.
// Uses backpressure with timeout, falling back to overflow file.
func (wp *WorkerPool) sendAlert(alert *domain.Alert) bool {
	// Fast path: non-blocking send
	select {
	case wp.outputChan <- alert:
		return true
	default:
	}

	// Backpressure: wait with timeout
	if wp.useBackpressure {
		timer := time.NewTimer(wp.submitTimeout)
		select {
		case wp.outputChan <- alert:
			timer.Stop()
			return true
		case <-timer.C:
			if wp.overflow != nil && wp.overflow.Enabled() {
				if err := wp.overflow.WriteAlert(alert); err != nil {
					log.Error().Err(err).Msg("Failed to write alert to overflow")
					return false
				}
				wp.overflowAlerts.Add(1)
				return true
			}
			return false
		}
	}

	// No backpressure: overflow immediately
	if wp.overflow != nil && wp.overflow.Enabled() {
		if err := wp.overflow.WriteAlert(alert); err != nil {
			log.Error().Err(err).Msg("Failed to write alert to overflow")
			return false
		}
		wp.overflowAlerts.Add(1)
		return true
	}
	return false
}

// alertDispatcher reads from the output channel and sends to alerters/subscribers.
func (wp *WorkerPool) alertDispatcher(ctx context.Context) {
	defer wp.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-wp.stopChan:
			return
		case alert, ok := <-wp.outputChan:
			if !ok {
				return
			}

			// Send to all alerters
			for _, alerter := range wp.alerters {
				if err := alerter.Send(ctx, alert); err != nil {
					log.Debug().Err(err).Msg("Alert send failed")
				}
			}

			// Notify all subscribers
			wp.mu.RLock()
			for _, sub := range wp.subscribers {
				sub.OnAlert(alert)
			}
			wp.mu.RUnlock()
		}
	}
}

// Submit attempts non-blocking entry submission with backpressure fallback.
//
// Parameters:
//   - entry: LogEntry to process
//
// Returns:
//   - true if submitted (channel, backpressure wait, or overflow)
//   - false if pool not running or all fallbacks failed
func (wp *WorkerPool) Submit(entry *domain.LogEntry) bool {
	wp.mu.RLock()
	running := wp.running
	wp.mu.RUnlock()

	if !running {
		return false
	}

	// Fast path
	select {
	case wp.inputChan <- entry:
		return true
	default:
	}

	// Backpressure path
	if wp.useBackpressure {
		timer := time.NewTimer(wp.submitTimeout)
		select {
		case wp.inputChan <- entry:
			timer.Stop()
			return true
		case <-timer.C:
			if wp.overflow != nil && wp.overflow.Enabled() {
				if err := wp.overflow.WriteEntry(entry); err != nil {
					log.Error().Err(err).Msg("Failed to write entry to overflow")
					return false
				}
				wp.overflowEntries.Add(1)
				return true
			}
			return false
		}
	}

	// Overflow fallback
	if wp.overflow != nil && wp.overflow.Enabled() {
		if err := wp.overflow.WriteEntry(entry); err != nil {
			log.Error().Err(err).Msg("Failed to write entry to overflow")
			return false
		}
		wp.overflowEntries.Add(1)
		return true
	}
	return false
}

// SubmitBlocking blocks until entry is submitted or context cancelled.
//
// Parameters:
//   - ctx: Context for cancellation
//   - entry: LogEntry to process
//
// Returns:
//   - true if submitted successfully
//   - false if context cancelled or pool stopped
func (wp *WorkerPool) SubmitBlocking(ctx context.Context, entry *domain.LogEntry) bool {
	select {
	case wp.inputChan <- entry:
		return true
	case <-ctx.Done():
		return false
	case <-wp.stopChan:
		return false
	}
}

// Alerts returns the read-only alert output channel.
func (wp *WorkerPool) Alerts() <-chan *domain.Alert {
	return wp.outputChan
}

// DLQ returns the Dead Letter Queue channel for toxic message handling.
func (wp *WorkerPool) DLQ() <-chan *ToxicMessage {
	return wp.dlqChan
}

// OverflowEntries returns count of entries written to overflow file.
func (wp *WorkerPool) OverflowEntries() int64 {
	return wp.overflowEntries.Load()
}

// OverflowAlerts returns count of alerts written to overflow file.
func (wp *WorkerPool) OverflowAlerts() int64 {
	return wp.overflowAlerts.Load()
}

// Stop performs graceful shutdown of the worker pool.
// Closes channels, waits for workers, and cleans up resources.
// Idempotent via sync.Once protection.
func (wp *WorkerPool) Stop() {
	wp.stopOnce.Do(func() {
		wp.mu.Lock()
		wp.running = false
		wp.mu.Unlock()

		close(wp.stopChan)
		close(wp.inputChan)

		wp.wg.Wait()

		close(wp.outputChan)
		if wp.dlqChan != nil {
			close(wp.dlqChan)
		}

		if wp.overflow != nil {
			if err := wp.overflow.Close(); err != nil {
				log.Error().Err(err).Msg("Failed to close overflow writer")
			}
		}

		if wp.quarantine != nil {
			if err := wp.quarantine.Close(); err != nil {
				log.Error().Err(err).Msg("Failed to close quarantine writer")
			}
		}

		if wp.metrics != nil {
			wp.metrics.SetActiveWorkers(0)
		}

		overflowed := wp.overflowEntries.Load() + wp.overflowAlerts.Load()
		if overflowed > 0 {
			log.Warn().
				Int64("overflow_entries", wp.overflowEntries.Load()).
				Int64("overflow_alerts", wp.overflowAlerts.Load()).
				Msg("Worker pool stopped with items in overflow file")
		} else {
			log.Info().Msg("Worker pool stopped")
		}
	})
}

// IsRunning returns true if the pool is actively processing.
func (wp *WorkerPool) IsRunning() bool {
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	return wp.running
}

// QueueLength returns current entries waiting in input channel.
func (wp *WorkerPool) QueueLength() int {
	return len(wp.inputChan)
}

// QueueCapacity returns the input channel buffer size.
func (wp *WorkerPool) QueueCapacity() int {
	return wp.bufferSize
}

// QueueUtilization returns percentage of input channel capacity in use.
func (wp *WorkerPool) QueueUtilization() float64 {
	if wp.bufferSize == 0 {
		return 0
	}
	return float64(len(wp.inputChan)) / float64(wp.bufferSize) * 100
}

// AddDetector dynamically adds a threat detector.
// Thread-safe for runtime detector updates.
func (wp *WorkerPool) AddDetector(detector ports.ThreatDetector) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	wp.detectors = append(wp.detectors, detector)
}

// AddAlerter dynamically adds an alert output.
func (wp *WorkerPool) AddAlerter(alerter ports.Alerter) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	wp.alerters = append(wp.alerters, alerter)
}

// AddSubscriber registers an alert notification callback.
func (wp *WorkerPool) AddSubscriber(sub ports.AlertSubscriber) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	wp.subscribers = append(wp.subscribers, sub)
}
