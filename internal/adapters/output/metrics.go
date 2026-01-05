// Package output provides production-grade Prometheus metrics for LogRadar.
//
// Implements industry-standard observability patterns:
//   - RED method: Rate, Errors, Duration for request-driven services
//   - USE method: Utilization, Saturation, Errors for resources
//   - SLI/SLO metrics: Error budget and latency objectives
//   - Go runtime metrics: GC, goroutines, memory via prometheus/collectors
//   - Build info: Version, commit, build time for deployment tracking
//
// Metrics naming follows Prometheus conventions:
//   - namespace_subsystem_name_unit (e.g., logradar_pipeline_processed_total)
//   - _total suffix for counters
//   - _seconds suffix for durations
//   - _bytes suffix for sizes
//
// Thread Safety: All methods are safe for concurrent access.
package output

import (
	"context"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	"github.com/xoelrdgz/logradar/internal/domain"
)

// Build information - set via ldflags at compile time
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// PrometheusMetrics implements production-grade metrics collection for LogRadar.
// Follows SRE best practices for monitoring log analysis pipelines.
type PrometheusMetrics struct {
	registry *prometheus.Registry

	// Build info
	buildInfo *prometheus.GaugeVec

	// RED metrics - Rate
	linesProcessedTotal  prometheus.Counter
	linesProcessedByType *prometheus.CounterVec
	alertsGeneratedTotal *prometheus.CounterVec
	threatsDetectedTotal *prometheus.CounterVec

	// RED metrics - Errors
	processingErrorsTotal *prometheus.CounterVec
	parseErrorsTotal      prometheus.Counter
	queueOverflowTotal    prometheus.Counter

	// RED metrics - Duration
	processingDuration        *prometheus.HistogramVec
	processingDurationSummary *prometheus.SummaryVec

	// USE metrics - Utilization
	queueUtilization  prometheus.GaugeFunc
	workerUtilization prometheus.GaugeFunc

	// USE metrics - Saturation
	queueSize         prometheus.GaugeFunc
	queueCapacity     prometheus.GaugeFunc
	activeWorkers     prometheus.GaugeFunc
	configuredWorkers prometheus.GaugeFunc
	pendingLines      prometheus.GaugeFunc

	// USE metrics - Errors (covered by processingErrorsTotal)

	// Resource metrics
	memoryAllocBytes    prometheus.GaugeFunc
	memorySysBytes      prometheus.GaugeFunc
	memoryHeapObjects   prometheus.GaugeFunc
	goroutinesCount     prometheus.GaugeFunc
	gcPauseTotalSeconds prometheus.CounterFunc
	gcLastPauseSeconds  prometheus.GaugeFunc

	// SLI/SLO metrics
	sloLatencyBucket      *prometheus.CounterVec // requests within SLO latency
	sloAvailabilityTotal  prometheus.Counter     // successful processing
	sloAvailabilityErrors prometheus.Counter     // failed processing

	// Throughput metrics
	linesPerSecond      prometheus.GaugeFunc
	bytesProcessed      prometheus.Counter
	totalLinesGauge     prometheus.GaugeFunc // Accurate total lines from internalMetrics
	maliciousLinesGauge prometheus.GaugeFunc // Accurate malicious lines from internalMetrics
	cleanLinesGauge     prometheus.GaugeFunc // Clean lines (total - malicious)

	// Pipeline health
	uptimeSeconds       prometheus.CounterFunc
	lastSuccessfulParse prometheus.Gauge
	healthCheckDuration prometheus.Histogram

	// Detection metrics
	detectionsByType     *prometheus.CounterVec
	detectionsBySeverity *prometheus.CounterVec
	riskScoreHistogram   prometheus.Histogram

	// Internal metrics reference
	internalMetrics *domain.AnalysisMetrics
	startTime       time.Time

	server *http.Server
	mu     sync.Mutex
}

// MetricsConfig holds configuration for the Prometheus metrics server.
type MetricsConfig struct {
	Port            string
	Path            string
	HealthPath      string
	EnableGoMetrics bool
}

// DefaultMetricsConfig returns production-ready default configuration.
func DefaultMetricsConfig() MetricsConfig {
	return MetricsConfig{
		Port:            ":9090",
		Path:            "/metrics",
		HealthPath:      "/ready",
		EnableGoMetrics: true,
	}
}

// NewPrometheusMetrics creates a production-grade metrics collector.
// Registers all metrics with a dedicated registry (not the global default).
func NewPrometheusMetrics(namespace string, internalMetrics *domain.AnalysisMetrics) *PrometheusMetrics {
	if namespace == "" {
		namespace = "logradar"
	}

	m := &PrometheusMetrics{
		registry:        prometheus.NewRegistry(),
		internalMetrics: internalMetrics,
		startTime:       time.Now(),
	}

	// Build info metric
	m.buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "build_info",
		Help:      "Build information including version, commit and build time",
	}, []string{"version", "commit", "build_time", "go_version"})
	m.buildInfo.WithLabelValues(Version, Commit, BuildTime, runtime.Version()).Set(1)

	// ============================================================
	// RED Metrics - Rate
	// ============================================================

	m.linesProcessedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "lines_processed_total",
		Help:      "Total number of log lines processed",
	})

	m.linesProcessedByType = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "lines_by_result_total",
		Help:      "Log lines processed by result type (clean, malicious, error)",
	}, []string{"result"})

	m.alertsGeneratedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "detection",
		Name:      "alerts_total",
		Help:      "Total alerts generated by severity level",
	}, []string{"level"})

	m.threatsDetectedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "detection",
		Name:      "threats_total",
		Help:      "Total threats detected by type",
	}, []string{"type"})

	// ============================================================
	// RED Metrics - Errors
	// ============================================================

	m.processingErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "errors_total",
		Help:      "Total processing errors by error type",
	}, []string{"error_type"})

	m.parseErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "parser",
		Name:      "errors_total",
		Help:      "Total log line parsing errors",
	})

	m.queueOverflowTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "queue_overflow_total",
		Help:      "Total items dropped due to queue overflow",
	})

	// ============================================================
	// RED Metrics - Duration
	// ============================================================

	// Histogram with SRE-optimized buckets for microsecond processing
	m.processingDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "processing_duration_seconds",
		Help:      "Time spent processing each log line",
		Buckets: []float64{
			0.00001, 0.00005, 0.0001, 0.0005, 0.001, // 10us, 50us, 100us, 500us, 1ms
			0.005, 0.01, 0.025, 0.05, 0.1, // 5ms, 10ms, 25ms, 50ms, 100ms
			0.25, 0.5, 1.0, // 250ms, 500ms, 1s
		},
	}, []string{"stage"})

	// Summary for accurate percentiles
	m.processingDurationSummary = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "processing_duration_quantiles",
		Help:      "Processing duration quantiles (p50, p90, p99)",
		Objectives: map[float64]float64{
			0.5:  0.05,  // p50 with 5% error
			0.9:  0.01,  // p90 with 1% error
			0.99: 0.001, // p99 with 0.1% error
		},
		MaxAge:     1 * time.Minute,
		AgeBuckets: 3,
	}, []string{"stage"})

	// ============================================================
	// USE Metrics - Utilization & Saturation
	// ============================================================

	m.queueUtilization = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "queue_utilization_ratio",
		Help:      "Current queue utilization (0.0-1.0)",
	}, func() float64 {
		// Queue utilization is tracked externally via worker pool
		return 0
	})

	m.queueSize = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "queue_size_current",
		Help:      "Current number of items in the processing queue",
	}, func() float64 {
		return 0 // Updated via SetQueueSize
	})

	m.activeWorkers = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "workers_active",
		Help:      "Number of workers currently processing",
	}, func() float64 {
		if internalMetrics != nil {
			return float64(internalMetrics.GetSnapshot().ActiveWorkers)
		}
		return 0
	})

	// ============================================================
	// Resource Metrics (Memory, GC, Goroutines)
	// ============================================================

	m.memoryAllocBytes = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "runtime",
		Name:      "memory_alloc_bytes",
		Help:      "Current heap allocation in bytes",
	}, func() float64 {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return float64(stats.Alloc)
	})

	m.memorySysBytes = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "runtime",
		Name:      "memory_sys_bytes",
		Help:      "Total memory obtained from system",
	}, func() float64 {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return float64(stats.Sys)
	})

	m.memoryHeapObjects = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "runtime",
		Name:      "heap_objects",
		Help:      "Number of allocated heap objects",
	}, func() float64 {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return float64(stats.HeapObjects)
	})

	m.goroutinesCount = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "runtime",
		Name:      "goroutines_count",
		Help:      "Current number of goroutines",
	}, func() float64 {
		return float64(runtime.NumGoroutine())
	})

	m.gcLastPauseSeconds = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "runtime",
		Name:      "gc_last_pause_seconds",
		Help:      "Duration of most recent GC pause",
	}, func() float64 {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		if stats.NumGC == 0 {
			return 0
		}
		return float64(stats.PauseNs[(stats.NumGC+255)%256]) / 1e9
	})

	// ============================================================
	// SLI/SLO Metrics
	// ============================================================

	m.sloLatencyBucket = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "slo",
		Name:      "latency_bucket_total",
		Help:      "Requests by latency SLO bucket (fast <1ms, normal <10ms, slow <100ms, very_slow >=100ms)",
	}, []string{"bucket"})

	m.sloAvailabilityTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "slo",
		Name:      "requests_successful_total",
		Help:      "Total successfully processed requests (for availability SLO)",
	})

	m.sloAvailabilityErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "slo",
		Name:      "requests_failed_total",
		Help:      "Total failed requests (for availability SLO)",
	})

	// ============================================================
	// Throughput Metrics
	// ============================================================

	// STARTUP LOG
	log.Info().Msgf("DEBUG: STARTING NEW METRICS INITIALIZATION. Pointer=%p", internalMetrics)

	m.linesPerSecond = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "throughput_lines_per_second",
		Help:      "Current processing throughput in lines per second",
	}, func() float64 {
		if internalMetrics != nil {
			val := internalMetrics.GetSnapshot().LinesPerSecond
			if val > 0 && int(val)%1000 == 0 {
				log.Info().Float64("val", val).Msg("DEBUG: LPS is working")
			}
			return val
		}
		return 0
	})

	m.bytesProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "bytes_processed_total",
		Help:      "Total bytes of log data processed",
	})

	m.totalLinesGauge = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "valid_lines_total",
		Help:      "Total number of log lines processed (accurate count from internal metrics)",
	}, func() float64 {
		if internalMetrics != nil {
			snap := internalMetrics.GetSnapshot()
			// Use zerolog to ensure it appears in the output stream
			if snap.TotalLinesProcessed == 0 && snap.LinesPerSecond > 0 {
				log.Error().
					Float64("lps", snap.LinesPerSecond).
					Int64("total_lines", snap.TotalLinesProcessed).
					Interface("ptr", internalMetrics).
					Msg("METRICS_DEBUG: Inconsistent state")
			} else if snap.TotalLinesProcessed > 0 && snap.TotalLinesProcessed%1000 == 0 {
				log.Info().
					Int64("total_lines", snap.TotalLinesProcessed).
					Msg("METRICS_DEBUG: Live count")
			}
			return float64(snap.TotalLinesProcessed)
		}
		return 0
	})

	m.maliciousLinesGauge = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "lines_malicious_total",
		Help:      "Total number of malicious log lines detected (accurate count from internal metrics)",
	}, func() float64 {
		if internalMetrics != nil {
			return float64(internalMetrics.GetSnapshot().MaliciousLines)
		}
		return 0
	})

	m.cleanLinesGauge = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "lines_clean_total",
		Help:      "Total number of clean log lines (total - malicious)",
	}, func() float64 {
		if internalMetrics != nil {
			snap := internalMetrics.GetSnapshot()
			return float64(snap.TotalLinesProcessed - snap.MaliciousLines)
		}
		return 0
	})

	// ============================================================
	// Pipeline Health Metrics
	// ============================================================

	m.uptimeSeconds = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "uptime_seconds_total",
		Help:      "Total uptime of the logradar instance",
	}, func() float64 {
		return time.Since(m.startTime).Seconds()
	})

	m.lastSuccessfulParse = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "pipeline",
		Name:      "last_successful_parse_timestamp",
		Help:      "Unix timestamp of last successfully parsed log line",
	})

	m.healthCheckDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "health_check_duration_seconds",
		Help:      "Time taken to perform health checks",
		Buckets:   prometheus.ExponentialBuckets(0.001, 2, 10),
	})

	// ============================================================
	// Detection Metrics
	// ============================================================

	m.detectionsByType = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "detection",
		Name:      "by_type_total",
		Help:      "Detections broken down by threat type",
	}, []string{"threat_type"})

	m.detectionsBySeverity = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "detection",
		Name:      "by_severity_total",
		Help:      "Detections broken down by severity level",
	}, []string{"severity"})

	m.riskScoreHistogram = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: "detection",
		Name:      "risk_score_distribution",
		Help:      "Distribution of risk scores (1-10)",
		Buckets:   []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	})

	// Register all metrics
	m.registerMetrics()

	return m
}

// registerMetrics adds all collectors to the registry.
func (m *PrometheusMetrics) registerMetrics() {
	// Build info
	m.registry.MustRegister(m.buildInfo)

	// RED - Rate
	m.registry.MustRegister(m.linesProcessedTotal)
	m.registry.MustRegister(m.linesProcessedByType)
	m.registry.MustRegister(m.alertsGeneratedTotal)
	m.registry.MustRegister(m.threatsDetectedTotal)

	// RED - Errors
	m.registry.MustRegister(m.processingErrorsTotal)
	m.registry.MustRegister(m.parseErrorsTotal)
	m.registry.MustRegister(m.queueOverflowTotal)

	// RED - Duration
	m.registry.MustRegister(m.processingDuration)
	m.registry.MustRegister(m.processingDurationSummary)

	// USE - Utilization & Saturation
	m.registry.MustRegister(m.activeWorkers)
	m.registry.MustRegister(m.memoryAllocBytes)
	m.registry.MustRegister(m.memorySysBytes)
	m.registry.MustRegister(m.memoryHeapObjects)
	m.registry.MustRegister(m.goroutinesCount)
	m.registry.MustRegister(m.gcLastPauseSeconds)

	// SLI/SLO
	m.registry.MustRegister(m.sloLatencyBucket)
	m.registry.MustRegister(m.sloAvailabilityTotal)
	m.registry.MustRegister(m.sloAvailabilityErrors)

	// Throughput
	m.registry.MustRegister(m.linesPerSecond)
	m.registry.MustRegister(m.bytesProcessed)
	m.registry.MustRegister(m.totalLinesGauge)
	m.registry.MustRegister(m.maliciousLinesGauge)
	m.registry.MustRegister(m.cleanLinesGauge)

	// Health
	m.registry.MustRegister(m.uptimeSeconds)
	m.registry.MustRegister(m.lastSuccessfulParse)
	m.registry.MustRegister(m.healthCheckDuration)

	// Detection
	m.registry.MustRegister(m.detectionsByType)
	m.registry.MustRegister(m.detectionsBySeverity)
	m.registry.MustRegister(m.riskScoreHistogram)

	// Standard Go runtime collectors
	m.registry.MustRegister(collectors.NewGoCollector())
	m.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

// ============================================================
// Metric Update Methods
// ============================================================

// IncrementLinesProcessed increments the total lines counter.
func (m *PrometheusMetrics) IncrementLinesProcessed() {
	m.linesProcessedTotal.Inc()
	m.sloAvailabilityTotal.Inc()
}

// IncrementLinesProcessedByResult categorizes the processing result.
func (m *PrometheusMetrics) IncrementLinesProcessedByResult(result string) {
	m.linesProcessedByType.WithLabelValues(result).Inc()
}

// IncrementThreats records a detected threat.
func (m *PrometheusMetrics) IncrementThreats(threatType domain.ThreatType) {
	m.threatsDetectedTotal.WithLabelValues(string(threatType)).Inc()
	m.detectionsByType.WithLabelValues(string(threatType)).Inc()
}

// ObserveProcessingTime records processing duration with SLO tracking.
func (m *PrometheusMetrics) ObserveProcessingTime(seconds float64) {
	m.processingDuration.WithLabelValues("total").Observe(seconds)
	m.processingDurationSummary.WithLabelValues("total").Observe(seconds)

	// Track SLO latency buckets
	switch {
	case seconds < 0.001: // < 1ms
		m.sloLatencyBucket.WithLabelValues("fast").Inc()
	case seconds < 0.01: // < 10ms
		m.sloLatencyBucket.WithLabelValues("normal").Inc()
	case seconds < 0.1: // < 100ms
		m.sloLatencyBucket.WithLabelValues("slow").Inc()
	default:
		m.sloLatencyBucket.WithLabelValues("very_slow").Inc()
	}

	m.lastSuccessfulParse.SetToCurrentTime()
}

// ObserveProcessingTimeByStage records duration for specific pipeline stages.
func (m *PrometheusMetrics) ObserveProcessingTimeByStage(stage string, seconds float64) {
	m.processingDuration.WithLabelValues(stage).Observe(seconds)
	m.processingDurationSummary.WithLabelValues(stage).Observe(seconds)
}

// IncrementParseErrors records a parsing error.
func (m *PrometheusMetrics) IncrementParseErrors() {
	m.parseErrorsTotal.Inc()
	m.sloAvailabilityErrors.Inc()
	m.processingErrorsTotal.WithLabelValues("parse").Inc()
}

// IncrementProcessingErrors records a processing error by type.
func (m *PrometheusMetrics) IncrementProcessingErrors(errorType string) {
	m.processingErrorsTotal.WithLabelValues(errorType).Inc()
	m.sloAvailabilityErrors.Inc()
}

// IncrementQueueOverflow records a queue overflow event.
func (m *PrometheusMetrics) IncrementQueueOverflow() {
	m.queueOverflowTotal.Inc()
	m.processingErrorsTotal.WithLabelValues("overflow").Inc()
}

// AddBytesProcessed adds to the bytes processed counter.
func (m *PrometheusMetrics) AddBytesProcessed(bytes int64) {
	m.bytesProcessed.Add(float64(bytes))
}

// RecordAlert records an alert with full categorization.
func (m *PrometheusMetrics) RecordAlert(alert *domain.Alert) {
	if alert == nil {
		return
	}

	level := string(alert.Level)
	threatType := string(alert.ThreatType)

	m.alertsGeneratedTotal.WithLabelValues(level).Inc()
	m.threatsDetectedTotal.WithLabelValues(threatType).Inc()
	m.detectionsByType.WithLabelValues(threatType).Inc()
	m.detectionsBySeverity.WithLabelValues(level).Inc()
	m.riskScoreHistogram.Observe(float64(alert.RiskScore))

}

// RecordHealthCheck records health check duration.
func (m *PrometheusMetrics) RecordHealthCheck(duration time.Duration) {
	m.healthCheckDuration.Observe(duration.Seconds())
}

// ============================================================
// AlertSubscriber Interface Implementation
// ============================================================

// OnAlert implements the AlertSubscriber interface for the metrics system.
func (m *PrometheusMetrics) OnAlert(alert *domain.Alert) {
	m.RecordAlert(alert)
}

// ============================================================
// HTTP Server Management
// ============================================================

// StartServer starts the Prometheus metrics HTTP server.
func (m *PrometheusMetrics) StartServer(config MetricsConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mux := http.NewServeMux()

	// Prometheus metrics endpoint with custom registry
	mux.Handle(config.Path, promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics:   true,
		MaxRequestsInFlight: 10,
	}))

	// Readiness endpoint
	mux.HandleFunc(config.HealthPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	})

	m.server = &http.Server{
		Addr:              config.Port,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
	}

	go func() {
		log.Info().
			Str("addr", config.Port).
			Str("metrics_path", config.Path).
			Str("health_path", config.HealthPath).
			Str("version", Version).
			Msg("Starting Prometheus metrics server")

		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Metrics server error")
		}
	}()

	return nil
}

// StopServer gracefully stops the metrics HTTP server.
func (m *PrometheusMetrics) StopServer() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return m.server.Shutdown(ctx)
	}
	return nil
}

// ============================================================
// Legacy Compatibility Methods
// ============================================================

// These methods maintain backward compatibility with existing code.

// IncrementRequests is a legacy method for compatibility.
func (m *PrometheusMetrics) IncrementRequests() {
	m.IncrementLinesProcessed()
}

// SetActiveWorkers is a legacy no-op (workers are read from AnalysisMetrics).
func (m *PrometheusMetrics) SetActiveWorkers(count int) {
	// No-op: active workers are read from AnalysisMetrics
}

// SetQueueSize is a legacy no-op.
func (m *PrometheusMetrics) SetQueueSize(size int) {
	// No-op: queue size is read dynamically
}
