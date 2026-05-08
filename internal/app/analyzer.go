package app

import (
	"context"
	"fmt"
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

type expectedEOFReader interface {
	ExpectedEOF() bool
}

type Analyzer struct {
	reader     ports.LogReader
	workerPool *WorkerPool
	metrics    *domain.AnalysisMetrics
	alertSubs  []ports.AlertSubscriber
	observers  []ports.ProcessingObserver

	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
	wg      sync.WaitGroup
	running bool
	mu      sync.RWMutex

	lastLinesProcessed int64
	lastLPSCheck       time.Time
}

type AnalyzerConfig struct {
	WorkerConfig WorkerPoolConfig
}

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
		done:         make(chan struct{}),
		lastLPSCheck: time.Now(),
	}
}

func (a *Analyzer) SetWorkerConfig(config WorkerPoolConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		log.Warn().Msg("Cannot change worker config while running")
		return
	}

	a.workerPool = NewWorkerPool(config, a.workerPool.detectors, a.workerPool.alerters, a.metrics)
}

func (a *Analyzer) AddAlertSubscriber(sub ports.AlertSubscriber) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alertSubs = append(a.alertSubs, sub)
	a.workerPool.AddSubscriber(sub)
}

func (a *Analyzer) AddProcessingObserver(obs ports.ProcessingObserver) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.observers = append(a.observers, obs)
	a.workerPool.AddObserver(obs)
}

func (a *Analyzer) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return nil
	}
	a.running = true
	a.err = nil
	a.done = make(chan struct{})
	a.mu.Unlock()

	a.ctx, a.cancel = context.WithCancel(ctx)

	a.workerPool.Start(a.ctx)

	entryChan, errChan := a.reader.Start(a.ctx)

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer a.finish(nil)
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
			a.notifyProcessingResult("parse_error")
			a.notifyParseError(err)
		case entry, ok := <-entryChan:
			if !ok {
				log.Info().Msg("Entry channel closed")
				if a.ctx.Err() == nil && !a.readerExpectedEOF() {
					a.finish(fmt.Errorf("log reader stopped unexpectedly"))
				}
				return
			}
			if !a.workerPool.Submit(entry) {
				log.Warn().Msg("Failed to submit entry to worker pool")
			}
		}
	}
}

func (a *Analyzer) notifyParseError(err error) {
	a.mu.RLock()
	observers := append([]ports.ProcessingObserver(nil), a.observers...)
	a.mu.RUnlock()
	for _, obs := range observers {
		if detailed, ok := obs.(ports.DetailedProcessingObserver); ok {
			detailed.IncrementParseErrors()
			if err != nil {
				detailed.IncrementParseErrorByReason(err.Error())
			}
		}
	}
}

func (a *Analyzer) notifyProcessingResult(result string) {
	a.mu.RLock()
	observers := append([]ports.ProcessingObserver(nil), a.observers...)
	a.mu.RUnlock()
	for _, obs := range observers {
		obs.IncrementLinesProcessedByResult(result)
	}
}

func (a *Analyzer) readerExpectedEOF() bool {
	reader, ok := a.reader.(expectedEOFReader)
	return ok && reader.ExpectedEOF()
}

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

func (a *Analyzer) finish(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil && a.err == nil {
		a.err = err
	}
	if err != nil && a.cancel != nil {
		a.cancel()
	}
	select {
	case <-a.done:
	default:
		close(a.done)
	}
}

func (a *Analyzer) Metrics() domain.MetricsSnapshot {
	return a.metrics.GetSnapshot()
}

func (a *Analyzer) InternalMetrics() *domain.AnalysisMetrics {
	return a.metrics
}

func (a *Analyzer) QueueStats() (int, int) {
	return a.workerPool.QueueLength(), a.workerPool.QueueCapacity()
}

func (a *Analyzer) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

func (a *Analyzer) Done() <-chan struct{} {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.done
}

func (a *Analyzer) Err() error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.err
}

func (a *Analyzer) WaitForSignal() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")

	a.Stop()
}

func (a *Analyzer) Run(ctx context.Context) error {
	if err := a.Start(ctx); err != nil {
		return err
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	select {
	case sig := <-sigChan:
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		a.Stop()
		return nil
	case <-a.Done():
		a.Stop()
		return a.Err()
	case <-ctx.Done():
		a.Stop()
		return ctx.Err()
	}
}
