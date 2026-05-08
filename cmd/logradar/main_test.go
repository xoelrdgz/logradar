package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"

	"github.com/xoelrdgz/logradar/internal/app"
)

func TestInitConfigLoadsYAMLAndEnvironmentOverrides(t *testing.T) {
	oldCfgFile := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "config.yaml")
	defer func() {
		cfgFile = oldCfgFile
		viper.Reset()
	}()

	config := []byte(`log:
  path: /from/config/access.log
  format: combined
  checkpoint:
    enabled: true
    path: /from/config/checkpoint.json
app:
  shutdown_timeout_seconds: 12
workers:
  count: 4
  buffer_size: 1234
  submit_timeout_ms: 250
  overflow_path: /from/config/overflow.jsonl
  quarantine_path: /from/config/quarantine.jsonl
detection:
  allowlist:
    ips:
      - 192.0.2.10
    cidrs:
      - 198.51.100.0/24
    path_prefixes:
      - /health
    user_agent_substrings:
      - uptime-check
  signatures:
    enabled: true
    rules_file: /from/config/rules.yaml
  behavioral:
    enabled: true
    brute_force:
      threshold: 7
      window_seconds: 30
      status_code: 403
    rate_limit:
      threshold: 80
      window_seconds: 5
threat_intel:
  enabled: true
  malicious_ips_file: /from/config/ips.txt
  feed_files:
    - /from/config/feed-a.txt
    - /from/config/feed-b.txt
  bloom_filter_size: 5000
  bloom_false_positive_rate: 0.02
  default_ttl_seconds: 3600
output:
  dedup:
    enabled: true
    window_seconds: 45
  json:
    enabled: false
    path: /from/config/alerts.jsonl
    stdout: false
    redact_sensitive: true
    include_raw_log: false
    max_alert_bytes: 12345
  metrics:
    enabled: true
    port: :19090
    path: /custom_metrics
tui:
  enabled: false
logging:
  level: warn
  format: json
`)
	if err := os.WriteFile(cfgFile, config, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("LOGRADAR_LOG_FORMAT", "json")
	t.Setenv("LOGRADAR_WORKERS_COUNT", "9")
	t.Setenv("LOGRADAR_THREAT_INTEL_ENABLED", "false")
	t.Setenv("LOGRADAR_OUTPUT_JSON_ENABLED", "true")

	viper.Reset()
	initConfig()
	cfg := app.LoadRuntimeConfig()

	if cfg.Log.Path != "/from/config/access.log" {
		t.Fatalf("Log.Path = %q, want config value", cfg.Log.Path)
	}
	if cfg.Log.Format != "json" {
		t.Fatalf("Log.Format = %q, want env override", cfg.Log.Format)
	}
	if !cfg.Log.Checkpoint.Enabled {
		t.Fatalf("Log.Checkpoint.Enabled = false, want config value true")
	}
	if cfg.Log.Checkpoint.Path != "/from/config/checkpoint.json" {
		t.Fatalf("Log.Checkpoint.Path = %q, want config value", cfg.Log.Checkpoint.Path)
	}
	if cfg.App.ShutdownTimeoutSeconds != 12 {
		t.Fatalf("App.ShutdownTimeoutSeconds = %d, want config value 12", cfg.App.ShutdownTimeoutSeconds)
	}
	if cfg.Workers.Count != 9 {
		t.Fatalf("Workers.Count = %d, want env override", cfg.Workers.Count)
	}
	if cfg.Workers.BufferSize != 1234 {
		t.Fatalf("Workers.BufferSize = %d, want config value", cfg.Workers.BufferSize)
	}
	if cfg.Workers.SubmitTimeout != 250 {
		t.Fatalf("Workers.SubmitTimeout = %d, want config value", cfg.Workers.SubmitTimeout)
	}
	if cfg.Workers.OverflowPath != "/from/config/overflow.jsonl" {
		t.Fatalf("Workers.OverflowPath = %q, want config value", cfg.Workers.OverflowPath)
	}
	if cfg.Workers.QuarantinePath != "/from/config/quarantine.jsonl" {
		t.Fatalf("Workers.QuarantinePath = %q, want config value", cfg.Workers.QuarantinePath)
	}
	if len(cfg.Detection.Allowlist.IPs) != 1 || cfg.Detection.Allowlist.IPs[0] != "192.0.2.10" {
		t.Fatalf("Detection.Allowlist.IPs = %#v, want configured IP", cfg.Detection.Allowlist.IPs)
	}
	if len(cfg.Detection.Allowlist.CIDRs) != 1 || cfg.Detection.Allowlist.CIDRs[0] != "198.51.100.0/24" {
		t.Fatalf("Detection.Allowlist.CIDRs = %#v, want configured CIDR", cfg.Detection.Allowlist.CIDRs)
	}
	if len(cfg.Detection.Allowlist.PathPrefixes) != 1 || cfg.Detection.Allowlist.PathPrefixes[0] != "/health" {
		t.Fatalf("Detection.Allowlist.PathPrefixes = %#v, want configured prefix", cfg.Detection.Allowlist.PathPrefixes)
	}
	if len(cfg.Detection.Allowlist.UserAgentSubstr) != 1 || cfg.Detection.Allowlist.UserAgentSubstr[0] != "uptime-check" {
		t.Fatalf("Detection.Allowlist.UserAgentSubstr = %#v, want configured substring", cfg.Detection.Allowlist.UserAgentSubstr)
	}
	if cfg.Detection.Signatures.RulesFile != "/from/config/rules.yaml" {
		t.Fatalf("Detection.Signatures.RulesFile = %q, want config value", cfg.Detection.Signatures.RulesFile)
	}
	if cfg.ThreatIntel.Enabled {
		t.Fatalf("ThreatIntel.Enabled = true, want env override false")
	}
	if len(cfg.ThreatIntel.FeedFiles) != 2 || cfg.ThreatIntel.FeedFiles[1] != "/from/config/feed-b.txt" {
		t.Fatalf("ThreatIntel.FeedFiles = %#v, want configured feed files", cfg.ThreatIntel.FeedFiles)
	}
	if cfg.ThreatIntel.DefaultTTLSeconds != 3600 {
		t.Fatalf("ThreatIntel.DefaultTTLSeconds = %d, want config value 3600", cfg.ThreatIntel.DefaultTTLSeconds)
	}
	if !cfg.Output.JSON.Enabled {
		t.Fatalf("Output.JSON.Enabled = false, want env override true")
	}
	if cfg.Output.Metrics.Path != "/custom_metrics" {
		t.Fatalf("Output.Metrics.Path = %q, want config value", cfg.Output.Metrics.Path)
	}
	if !cfg.Output.Dedup.Enabled {
		t.Fatalf("Output.Dedup.Enabled = false, want config value true")
	}
	if cfg.Output.Dedup.WindowSeconds != 45 {
		t.Fatalf("Output.Dedup.WindowSeconds = %d, want config value 45", cfg.Output.Dedup.WindowSeconds)
	}
	if !cfg.Output.JSON.RedactSensitive {
		t.Fatalf("Output.JSON.RedactSensitive = false, want config value true")
	}
	if cfg.Output.JSON.IncludeRawLog {
		t.Fatalf("Output.JSON.IncludeRawLog = true, want config value false")
	}
	if cfg.Output.JSON.MaxAlertBytes != 12345 {
		t.Fatalf("Output.JSON.MaxAlertBytes = %d, want config value 12345", cfg.Output.JSON.MaxAlertBytes)
	}
	if cfg.Logging.Level != "warn" {
		t.Fatalf("Logging.Level = %q, want config value", cfg.Logging.Level)
	}
}

func TestConfiguredParserRejectsUnsupportedFormat(t *testing.T) {
	if _, err := configuredParser("unsupported"); err == nil {
		t.Fatal("configuredParser() error = nil, want unsupported format error")
	}
}
