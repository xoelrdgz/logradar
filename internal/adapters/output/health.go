package output

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/xoelrdgz/logradar/internal/app"
	"github.com/xoelrdgz/logradar/internal/domain"
)

type HealthStatus struct {
	Healthy         bool          `json:"healthy"`
	Status          string        `json:"status"`
	Latency         time.Duration `json:"latency_ns"`
	QueueLength     int           `json:"queue_length"`
	QueueCapacity   int           `json:"queue_capacity"`
	Utilization     float64       `json:"utilization_percent"`
	OverflowedItems int64         `json:"overflowed_items"`
	Uptime          time.Duration `json:"uptime_ns"`
	Reason          string        `json:"reason,omitempty"`
}

type HealthChecker struct {
	workerPool *app.WorkerPool
	metrics    *domain.AnalysisMetrics
	maxLatency time.Duration
	startTime  time.Time

	lastCheck     HealthStatus
	lastCheckTime time.Time
	lastCheckMu   sync.RWMutex
	checkInterval time.Duration
}

type HealthCheckerConfig struct {
	MaxLatency    time.Duration
	CheckInterval time.Duration
}

func DefaultHealthCheckerConfig() HealthCheckerConfig {
	return HealthCheckerConfig{
		MaxLatency:    500 * time.Millisecond,
		CheckInterval: 5 * time.Second,
	}
}

func NewHealthChecker(wp *app.WorkerPool, metrics *domain.AnalysisMetrics, config HealthCheckerConfig) *HealthChecker {
	return &HealthChecker{
		workerPool:    wp,
		metrics:       metrics,
		maxLatency:    config.MaxLatency,
		checkInterval: config.CheckInterval,
		startTime:     time.Now(),
	}
}

func (h *HealthChecker) Check(ctx context.Context) HealthStatus {
	h.lastCheckMu.RLock()
	if time.Since(h.lastCheckTime) < h.checkInterval {
		cached := h.lastCheck
		h.lastCheckMu.RUnlock()
		return cached
	}
	h.lastCheckMu.RUnlock()

	status := h.performCheck(ctx)

	h.lastCheckMu.Lock()
	h.lastCheck = status
	h.lastCheckTime = time.Now()
	h.lastCheckMu.Unlock()

	return status
}

func (h *HealthChecker) performCheck(ctx context.Context) HealthStatus {
	status := HealthStatus{
		Uptime: time.Since(h.startTime),
	}
	if h.workerPool == nil || !h.workerPool.IsRunning() {
		status.Healthy = false
		status.Status = "OFFLINE"
		status.Reason = "worker pool not running"
		return status
	}

	status.QueueLength = h.workerPool.QueueLength()
	status.QueueCapacity = h.workerPool.QueueCapacity()
	status.Utilization = h.workerPool.QueueUtilization()
	status.OverflowedItems = h.workerPool.OverflowEntries() + h.workerPool.OverflowAlerts()

	if status.Utilization >= 95 {
		status.Healthy = false
		status.Status = "SATURATED"
		status.Reason = fmt.Sprintf("queue utilization at %.1f%%", status.Utilization)
		return status
	}

	start := time.Now()
	testEntry := domain.AcquireLogEntry()
	testEntry.Path = "/__health_ping__"
	testEntry.Method = "GET"
	submitCtx, cancel := context.WithTimeout(ctx, h.maxLatency)
	defer cancel()

	submitted := h.workerPool.SubmitBlocking(submitCtx, testEntry)
	status.Latency = time.Since(start)

	if !submitted {
		domain.ReleaseLogEntry(testEntry)
		status.Healthy = false
		status.Status = "BLOCKED"
		status.Reason = "pipeline blocked - submit timed out"
		return status
	}

	if status.Latency > h.maxLatency {
		status.Healthy = false
		status.Status = "SLOW"
		status.Reason = fmt.Sprintf("latency %v exceeds threshold %v", status.Latency, h.maxLatency)
		return status
	}

	status.Healthy = true
	if status.Utilization >= 80 {
		status.Status = "DEGRADED"
		status.Reason = fmt.Sprintf("queue utilization elevated at %.1f%%", status.Utilization)
	} else {
		status.Status = "HEALTHY"
	}

	return status
}

func (h *HealthChecker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	status := h.Check(ctx)

	w.Header().Set("Content-Type", "application/json")
	if status.Healthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	fmt.Fprintf(w, `{"healthy":%t,"status":"%s","latency_ms":%.2f,"queue_length":%d,"queue_capacity":%d,"utilization_percent":%.1f,"overflowed_items":%d,"uptime_seconds":%.0f`,
		status.Healthy,
		status.Status,
		float64(status.Latency)/float64(time.Millisecond),
		status.QueueLength,
		status.QueueCapacity,
		status.Utilization,
		status.OverflowedItems,
		status.Uptime.Seconds(),
	)

	if status.Reason != "" {
		fmt.Fprintf(w, `,"reason":"%s"`, status.Reason)
	}
	fmt.Fprint(w, "}")
}
