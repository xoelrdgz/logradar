# Configuration

Supported runtime keys are the keys loaded by `internal/app/runtime_config.go`.

```yaml
log:
  path: "./access.log"
  format: "combined" # combined, json, auto
  checkpoint:
    enabled: false
    path: "./output/logradar.checkpoint.json"

app:
  shutdown_timeout_seconds: 5

workers:
  count: 16
  buffer_size: 50000
  submit_timeout_ms: 100
  overflow_path: ""
  quarantine_path: ""

detection:
  allowlist:
    ips: []
    cidrs: []
    path_prefixes: ["/health", "/metrics"]
    user_agent_substrings: []
  signatures:
    enabled: true
    rules_file: ""
    patterns: {}
  behavioral:
    enabled: true
    brute_force:
      threshold: 10
      window_seconds: 60
      status_code: 401
    rate_limit:
      threshold: 100
      window_seconds: 10

threat_intel:
  enabled: false
  malicious_ips_file: ""
  feed_files: []
  bloom_filter_size: 10000
  bloom_false_positive_rate: 0.01
  default_ttl_seconds: 0

output:
  dedup:
    enabled: false
    window_seconds: 60
  json:
    enabled: false
    path: "./output/alerts.json"
    stdout: false
    redact_sensitive: true
    include_raw_log: true
    max_alert_bytes: 65536
  metrics:
    enabled: true
    port: ":9090"
    path: "/metrics"

tui:
  enabled: true
  refresh_interval_ms: 100
  max_alerts_displayed: 50

logging:
  level: "info"
  format: "console"
```

Environment variables use `LOGRADAR_` and replace dots with underscores, for example `LOGRADAR_LOG_FORMAT=json`.

Validation happens at startup. Invalid worker sizes, ports, thresholds and writable output paths fail before the analyzer starts.

