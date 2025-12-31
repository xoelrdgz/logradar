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

type ToxicMessage struct {
	Entry     *domain.LogEntry
	PanicErr  interface{}
	Timestamp time.Time
	WorkerID  int
}

type WorkerPool struct {
	workerCount int
	inputChan   chan *domain.LogEntry
	outputChan  chan *domain.Alert
	detectors   []ports.ThreatDetector
	alerters    []ports.Alerter
	subscribers []ports.AlertSubscriber
	metrics     *domain.AnalysisMetrics
	bufferSize  int

	submitTimeout   time.Duration
	useBackpressure bool

	dlqChan    chan *ToxicMessage
	dlqEnabled bool

	overflow        *OverflowWriter
	overflowEntries atomic.Int64
	overflowAlerts  atomic.Int64

	quarantine *QuarantineWriter

	wg       sync.WaitGroup
	stopOnce sync.Once
	stopChan chan struct{}
	running  bool
	mu       sync.RWMutex
}

type WorkerPoolConfig struct {
	WorkerCount    int
	BufferSize     int
	SubmitTimeout  time.Duration
	EnableDLQ      bool
	DLQSize        int
	OverflowPath   string
	QuarantinePath string
}

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

func (wp *WorkerPool) worker(ctx context.Context, id int) {
	defer wp.wg.Done()

	var currentEntry *domain.LogEntry

	defer func() {
		if r := recover(); r != nil {
			log.Error().
				Interface("panic", r).
				Int("worker_id", id).
				Msg("Worker panic recovered")

			if wp.quarantine != nil && wp.quarantine.Enabled() {
				if err := wp.quarantine.WriteToxicMessage(id, r, currentEntry); err != nil {
					log.Error().Err(err).Int("worker_id", id).Msg("Failed to quarantine toxic message")
				}
			}

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

func (wp *WorkerPool) sendAlert(alert *domain.Alert) bool {
	select {
	case wp.outputChan <- alert:
		return true
	default:
	}

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

			for _, alerter := range wp.alerters {
				if err := alerter.Send(ctx, alert); err != nil {
					log.Debug().Err(err).Msg("Alert send failed")
				}
			}

			wp.mu.RLock()
			for _, sub := range wp.subscribers {
				sub.OnAlert(alert)
			}
			wp.mu.RUnlock()
		}
	}
}

func (wp *WorkerPool) Submit(entry *domain.LogEntry) bool {
	wp.mu.RLock()
	running := wp.running
	wp.mu.RUnlock()

	if !running {
		return false
	}

	select {
	case wp.inputChan <- entry:
		return true
	default:
	}

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

func (wp *WorkerPool) Alerts() <-chan *domain.Alert {
	return wp.outputChan
}
func (wp *WorkerPool) DLQ() <-chan *ToxicMessage {
	return wp.dlqChan
}

func (wp *WorkerPool) OverflowEntries() int64 {
	return wp.overflowEntries.Load()
}

func (wp *WorkerPool) OverflowAlerts() int64 {
	return wp.overflowAlerts.Load()
}

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

func (wp *WorkerPool) IsRunning() bool {
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	return wp.running
}

func (wp *WorkerPool) QueueLength() int {
	return len(wp.inputChan)
}
func (wp *WorkerPool) QueueCapacity() int {
	return wp.bufferSize
}

func (wp *WorkerPool) QueueUtilization() float64 {
	if wp.bufferSize == 0 {
		return 0
	}
	return float64(len(wp.inputChan)) / float64(wp.bufferSize) * 100
}

func (wp *WorkerPool) AddDetector(detector ports.ThreatDetector) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	wp.detectors = append(wp.detectors, detector)
}

func (wp *WorkerPool) AddAlerter(alerter ports.Alerter) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	wp.alerters = append(wp.alerters, alerter)
}

func (wp *WorkerPool) AddSubscriber(sub ports.AlertSubscriber) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	wp.subscribers = append(wp.subscribers, sub)
}
