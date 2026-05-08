# Monitoring

LogRadar exposes Prometheus metrics and health endpoints when `output.metrics.enabled=true`.

Endpoints:

- `/live`: process is alive.
- `/ready`: analyzer is running and has no fatal pipeline error.
- `/metrics`: Prometheus scrape endpoint.

Maintained alert rule files:

- `configs/prometheus/recording_rules.yml`
- `configs/prometheus/alerting_rules.yml`

Core metrics:

- `logradar_pipeline_lines_processed_total`
- `logradar_pipeline_lines_by_result_total`
- `logradar_parser_errors_total`
- `logradar_parser_errors_by_reason_total`
- `logradar_pipeline_errors_total`
- `logradar_pipeline_queue_overflow_total`
- `logradar_pipeline_queue_size_current`
- `logradar_pipeline_queue_capacity`
- `logradar_pipeline_queue_utilization_ratio`
- `logradar_alerter_errors_total`
- `logradar_detection_alerts_total`
- `logradar_detection_threats_total`
- `logradar_threat_intel_entries_loaded`
- `logradar_threat_intel_last_reload_timestamp`
- `logradar_threat_intel_feed_errors_total`

Discard/error reasons currently emitted include `parse_error`, `allowlisted`, `audit`, `overflow`, `timeout`, `overflow_write_failed` and `alerter_error`.

Grafana is intentionally not part of the maintained deployment.

