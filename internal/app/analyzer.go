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

type Analyzer struct {
	reader     ports.LogReader
	workerPool *WorkerPool
	metrics    *domain.AnalysisMetrics
	alertSubs  []ports.AlertSubscriber

	ctx     context.Context
	cancel  context.CancelFunc
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

func (a *Analyzer) Metrics() domain.MetricsSnapshot {
	return a.metrics.GetSnapshot()
}

func (a *Analyzer) InternalMetrics() *domain.AnalysisMetrics {
	return a.metrics
}

func (a *Analyzer) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
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

	a.WaitForSignal()
	return nil
}
