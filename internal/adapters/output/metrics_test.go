package output

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xoelrdgz/logradar/internal/domain"
)

func TestPrometheusMetricsExposeDocumentedAndRuleMetrics(t *testing.T) {
	internal := domain.NewAnalysisMetrics()
	internal.IncrementLines()
	internal.IncrementMaliciousLines()
	internal.SetActiveWorkers(4)
	internal.UpdateLPS(12.5)

	metrics := NewPrometheusMetrics("logradar", internal)
	metrics.IncrementLinesProcessedByResult("clean")
	metrics.IncrementLinesProcessedByResult("malicious")
	metrics.IncrementParseErrors()
	metrics.IncrementParseErrorByReason("invalid combined log")
	metrics.IncrementQueueOverflow()
	metrics.IncrementAlerterErrors("json")
	metrics.AddBytesProcessed(128)
	metrics.SetQueueStatsFunc(func() (int, int) { return 3, 10 })
	metrics.ObserveProcessingTime(0.002)
	metrics.RecordHealthCheck(3 * time.Millisecond)
	metrics.SetThreatIntelStats(12, time.Unix(1000, 0), 1)
	metrics.RecordAlert(domain.NewAlert(
		netip.MustParseAddr("192.0.2.10"),
		domain.ThreatTypeSQLInjection,
		domain.AlertLevelCritical,
		"GET /?id=1 HTTP/1.1",
		9,
		"test alert",
	))

	families, err := metrics.registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	names := make(map[string]bool, len(families))
	for _, family := range families {
		names[family.GetName()] = true
	}

	required := []string{
		"logradar_build_info",
		"logradar_pipeline_throughput_lines_per_second",
		"logradar_pipeline_lines_processed_total",
		"logradar_pipeline_lines_by_result_total",
		"logradar_pipeline_valid_lines_total",
		"logradar_pipeline_lines_malicious_total",
		"logradar_pipeline_lines_clean_total",
		"logradar_pipeline_bytes_processed_total",
		"logradar_pipeline_errors_total",
		"logradar_pipeline_queue_overflow_total",
		"logradar_alerter_errors_total",
		"logradar_pipeline_queue_utilization_ratio",
		"logradar_pipeline_queue_size_current",
		"logradar_pipeline_queue_capacity",
		"logradar_pipeline_processing_duration_seconds",
		"logradar_parser_errors_total",
		"logradar_parser_errors_by_reason_total",
		"logradar_detection_threats_total",
		"logradar_detection_alerts_total",
		"logradar_detection_by_type_total",
		"logradar_detection_by_severity_total",
		"logradar_detection_risk_score_distribution",
		"logradar_threat_intel_entries_loaded",
		"logradar_threat_intel_last_reload_timestamp",
		"logradar_threat_intel_feed_errors_total",
		"logradar_slo_requests_successful_total",
		"logradar_slo_requests_failed_total",
		"logradar_slo_latency_bucket_total",
		"logradar_runtime_memory_alloc_bytes",
		"logradar_runtime_memory_sys_bytes",
		"logradar_runtime_goroutines_count",
		"logradar_pipeline_workers_active",
		"logradar_uptime_seconds_total",
		"logradar_health_check_duration_seconds",
	}
	for _, name := range required {
		if !names[name] {
			t.Fatalf("metric %q not exposed", name)
		}
	}
}

func TestPrometheusRuleFilesReferenceMaintainedMetrics(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	var combined strings.Builder
	for _, path := range []string{
		filepath.Join(root, "configs", "prometheus", "recording_rules.yml"),
		filepath.Join(root, "configs", "prometheus", "alerting_rules.yml"),
	} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		text := string(content)
		if strings.Contains(text, "grafana") || strings.Contains(text, "Grafana") {
			t.Fatalf("%s references Grafana, which is out of scope", path)
		}
		combined.WriteString(text)
	}
	text := combined.String()
	for _, metric := range []string{
		"logradar_pipeline_lines_processed_total",
		"logradar_pipeline_errors_total",
		"logradar_detection_threats_total",
		"logradar_runtime_memory_alloc_bytes",
	} {
		if !strings.Contains(text, metric) {
			t.Fatalf("Prometheus rules do not reference maintained metric %s", metric)
		}
	}
}
