package app

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/internal/ports"
)

type mockDetector struct {
	shouldDetect bool
	shouldPanic  bool
	detectCount  atomic.Int64
}

func (m *mockDetector) Detect(ctx context.Context, entry *domain.LogEntry) domain.DetectionResult {
	m.detectCount.Add(1)
	if m.shouldPanic {
		panic("intentional panic for testing")
	}
	if m.shouldDetect {
		return domain.DetectionResult{
			Detected:   true,
			ThreatType: domain.ThreatTypeSQLInjection,
			Level:      domain.AlertLevelCritical,
			RiskScore:  9,
			Message:    "Test detection",
		}
	}
	return domain.NoDetection()
}

func (m *mockDetector) Name() string            { return "mock" }
func (m *mockDetector) Type() domain.ThreatType { return domain.ThreatTypeUnknown }

type mockAlerter struct {
	alertCount atomic.Int64
}

func (m *mockAlerter) Send(ctx context.Context, alert *domain.Alert) error {
	m.alertCount.Add(1)
	return nil
}

func (m *mockAlerter) Flush() error { return nil }
func (m *mockAlerter) Close() error { return nil }

func TestWorkerPool_Basic(t *testing.T) {
	metrics := domain.NewAnalysisMetrics()
	detector := &mockDetector{shouldDetect: false}
	alerter := &mockAlerter{}

	config := WorkerPoolConfig{
		WorkerCount: 4,
		BufferSize:  100,
	}

	pool := NewWorkerPool(config, []ports.ThreatDetector{detector}, []ports.Alerter{alerter}, metrics)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)

	for i := 0; i < 10; i++ {
		entry := domain.AcquireLogEntry()
		entry.Path = "/test"
		if !pool.SubmitBlocking(ctx, entry) {
			t.Error("Failed to submit entry")
		}
	}

	time.Sleep(100 * time.Millisecond)

	pool.Stop()

	if detector.detectCount.Load() != 10 {
		t.Errorf("Expected 10 detections, got %d", detector.detectCount.Load())
	}
}

func TestWorkerPool_Detection(t *testing.T) {
	metrics := domain.NewAnalysisMetrics()
	detector := &mockDetector{shouldDetect: true}
	alerter := &mockAlerter{}

	config := WorkerPoolConfig{
		WorkerCount: 2,
		BufferSize:  100,
	}

	pool := NewWorkerPool(config, []ports.ThreatDetector{detector}, []ports.Alerter{alerter}, metrics)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)

	for i := 0; i < 5; i++ {
		entry := domain.AcquireLogEntry()
		entry.Path = "/attack"
		pool.SubmitBlocking(ctx, entry)
	}

	time.Sleep(200 * time.Millisecond)

	pool.Stop()

	if alerter.alertCount.Load() != 5 {
		t.Errorf("Expected 5 alerts, got %d", alerter.alertCount.Load())
	}
}

func TestWorkerPool_PanicRecovery(t *testing.T) {
	metrics := domain.NewAnalysisMetrics()
	detector := &mockDetector{shouldPanic: true}
	alerter := &mockAlerter{}

	config := WorkerPoolConfig{
		WorkerCount: 2,
		BufferSize:  100,
	}

	pool := NewWorkerPool(config, []ports.ThreatDetector{detector}, []ports.Alerter{alerter}, metrics)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)

	entry := domain.AcquireLogEntry()
	entry.Path = "/panic"
	pool.SubmitBlocking(ctx, entry)
	time.Sleep(200 * time.Millisecond)

	if !pool.IsRunning() {
		t.Error("Worker pool should still be running after panic")
	}

	pool.Stop()
}

func TestWorkerPool_GracefulShutdown(t *testing.T) {
	metrics := domain.NewAnalysisMetrics()
	detector := &mockDetector{shouldDetect: false}
	alerter := &mockAlerter{}

	config := WorkerPoolConfig{
		WorkerCount: 4,
		BufferSize:  100,
	}

	pool := NewWorkerPool(config, []ports.ThreatDetector{detector}, []ports.Alerter{alerter}, metrics)

	ctx, cancel := context.WithCancel(context.Background())

	pool.Start(ctx)

	for i := 0; i < 50; i++ {
		entry := domain.AcquireLogEntry()
		entry.Path = "/test"
		pool.Submit(entry)
	}

	done := make(chan struct{})
	go func() {
		cancel()
		pool.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("Shutdown took too long")
	}

	if pool.IsRunning() {
		t.Error("Pool should not be running after stop")
	}
}

func TestWorkerPool_ConcurrentSubmit(t *testing.T) {
	metrics := domain.NewAnalysisMetrics()
	detector := &mockDetector{shouldDetect: false}
	alerter := &mockAlerter{}

	config := WorkerPoolConfig{
		WorkerCount: 8,
		BufferSize:  1000,
	}

	pool := NewWorkerPool(config, []ports.ThreatDetector{detector}, []ports.Alerter{alerter}, metrics)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)

	var wg sync.WaitGroup
	submitCount := 100
	goroutines := 10

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < submitCount; i++ {
				entry := domain.AcquireLogEntry()
				entry.Path = "/concurrent"
				pool.SubmitBlocking(ctx, entry)
			}
		}()
	}

	wg.Wait()
	time.Sleep(200 * time.Millisecond)

	pool.Stop()

	expected := int64(submitCount * goroutines)
	if detector.detectCount.Load() != expected {
		t.Errorf("Expected %d detections, got %d", expected, detector.detectCount.Load())
	}
}

func TestWorkerPool_QueueLength(t *testing.T) {
	metrics := domain.NewAnalysisMetrics()
	detector := &mockDetector{shouldDetect: false}
	alerter := &mockAlerter{}

	config := WorkerPoolConfig{
		WorkerCount: 1,
		BufferSize:  100,
	}

	pool := NewWorkerPool(config, []ports.ThreatDetector{detector}, []ports.Alerter{alerter}, metrics)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)

	submitted := 0
	for i := 0; i < 50; i++ {
		entry := domain.AcquireLogEntry()
		entry.Path = "/test"
		if pool.Submit(entry) {
			submitted++
		}
	}

	queueLen := pool.QueueLength()
	if queueLen < 0 || queueLen > 50 {
		t.Errorf("Queue length should be between 0 and 50, got %d", queueLen)
	}

	pool.Stop()
}

type mockObserver struct {
	cleanCount     atomic.Int64
	maliciousCount atomic.Int64
}

func (m *mockObserver) IncrementLinesProcessedByResult(result string) {
	if result == "clean" {
		m.cleanCount.Add(1)
	} else if result == "malicious" {
		m.maliciousCount.Add(1)
	}
}

func TestWorkerPool_ProcessingObserver(t *testing.T) {
	metrics := domain.NewAnalysisMetrics()
	detector := &mockDetector{shouldDetect: false}
	alerter := &mockAlerter{}
	observer := &mockObserver{}

	// Create a detector that we can toggle for the second phase
	maliciousDetector := &mockDetector{shouldDetect: true}

	config := WorkerPoolConfig{
		WorkerCount: 2,
		BufferSize:  100,
	}

	// Phase 1: Clean lines
	pool := NewWorkerPool(config, []ports.ThreatDetector{detector}, []ports.Alerter{alerter}, metrics)
	pool.AddObserver(observer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)

	for i := 0; i < 10; i++ {
		entry := domain.AcquireLogEntry()
		entry.Path = "/clean"
		pool.SubmitBlocking(ctx, entry)
	}

	// Give workers time to process
	time.Sleep(100 * time.Millisecond)

	pool.Stop()

	if observer.cleanCount.Load() != 10 {
		t.Errorf("Expected 10 clean lines, got %d", observer.cleanCount.Load())
	}
	if observer.maliciousCount.Load() != 0 {
		t.Errorf("Expected 0 malicious lines, got %d", observer.maliciousCount.Load())
	}

	// Phase 2: Malicious lines
	// Need new pool because Stop() closes channels
	pool2 := NewWorkerPool(config, []ports.ThreatDetector{maliciousDetector}, []ports.Alerter{alerter}, metrics)
	pool2.AddObserver(observer)

	pool2.Start(ctx)

	for i := 0; i < 5; i++ {
		entry := domain.AcquireLogEntry()
		entry.Path = "/malicious"
		pool2.SubmitBlocking(ctx, entry)
	}

	time.Sleep(100 * time.Millisecond)
	pool2.Stop()

	if observer.maliciousCount.Load() != 5 {
		t.Errorf("Expected 5 malicious lines, got %d", observer.maliciousCount.Load())
	}
	// Clean count should stay same (10)
	if observer.cleanCount.Load() != 10 {
		t.Errorf("Expected 10 clean lines total, got %d", observer.cleanCount.Load())
	}
}
