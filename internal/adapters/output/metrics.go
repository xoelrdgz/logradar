package output

import (
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	"github.com/xoelrdgz/logradar/internal/domain"
)

type PrometheusMetrics struct {
	totalRequests   prometheus.CounterFunc
	threatsDetected *prometheus.CounterVec
	processingTime  prometheus.Histogram
	activeWorkers   prometheus.GaugeFunc
	alertsByLevel   *prometheus.CounterVec
	alertsByType    *prometheus.CounterVec
	queueSize       prometheus.Gauge
	memoryUsage     prometheus.GaugeFunc

	server *http.Server
	mu     sync.Mutex
}

type MetricsConfig struct {
	Port string
	Path string
}

func DefaultMetricsConfig() MetricsConfig {
	return MetricsConfig{
		Port: ":9090",
		Path: "/metrics",
	}
}

func NewPrometheusMetrics(namespace string, internalMetrics *domain.AnalysisMetrics) *PrometheusMetrics {
	if namespace == "" {
		namespace = "logradar"
	}

	m := &PrometheusMetrics{}

	m.totalRequests = promauto.NewCounterFunc(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "total_requests",
		Help:      "Total number of log lines processed",
	}, func() float64 {
		if internalMetrics != nil {
			return float64(internalMetrics.TotalLines())
		}
		return 0
	})

	m.threatsDetected = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "threats_detected_total",
		Help:      "Total number of threats detected by type",
	}, []string{"type"})

	m.processingTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "processing_duration_seconds",
		Help:      "Time spent processing each log entry",
		Buckets:   prometheus.ExponentialBuckets(0.0001, 2, 10),
	})

	m.activeWorkers = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "active_workers",
		Help:      "Number of active worker goroutines",
	}, func() float64 {
		if internalMetrics != nil {
			return float64(internalMetrics.GetSnapshot().ActiveWorkers)
		}
		return 0
	})

	m.alertsByLevel = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "alerts_by_level_total",
		Help:      "Total alerts by severity level",
	}, []string{"level"})

	m.alertsByType = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "alerts_by_type_total",
		Help:      "Total alerts by threat type",
	}, []string{"type"})

	m.queueSize = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "queue_size",
		Help:      "Current size of the processing queue",
	})

	m.memoryUsage = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_bytes",
		Help:      "Current memory usage in bytes",
	}, func() float64 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return float64(m.Alloc)
	})

	return m
}

func (m *PrometheusMetrics) IncrementRequests() {
}

func (m *PrometheusMetrics) IncrementThreats(threatType domain.ThreatType) {
	m.threatsDetected.WithLabelValues(string(threatType)).Inc()
}

func (m *PrometheusMetrics) ObserveProcessingTime(seconds float64) {
	m.processingTime.Observe(seconds)
}

func (m *PrometheusMetrics) SetActiveWorkers(count int) {
}

func (m *PrometheusMetrics) RecordAlert(alert *domain.Alert) {
	m.alertsByLevel.WithLabelValues(string(alert.Level)).Inc()
	m.alertsByType.WithLabelValues(string(alert.ThreatType)).Inc()
	m.threatsDetected.WithLabelValues(string(alert.ThreatType)).Inc()
}

func (m *PrometheusMetrics) SetQueueSize(size int) {
	m.queueSize.Set(float64(size))
}

func (m *PrometheusMetrics) StartServer(config MetricsConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mux := http.NewServeMux()
	mux.Handle(config.Path, promhttp.Handler())

	m.server = &http.Server{
		Addr:              config.Port,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Info().Str("addr", config.Port).Str("path", config.Path).Msg("Starting Prometheus metrics server")
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Metrics server error")
		}
	}()

	return nil
}

func (m *PrometheusMetrics) StopServer() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.server != nil {
		return m.server.Close()
	}
	return nil
}

func (m *PrometheusMetrics) OnAlert(alert *domain.Alert) {
	m.RecordAlert(alert)
}
