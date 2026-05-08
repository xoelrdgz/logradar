package output

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xoelrdgz/logradar/internal/domain"
)

func TestJSONAlerterRedactsSensitiveValues(t *testing.T) {
	alertPath := filepath.Join(t.TempDir(), "alerts.jsonl")
	alerter, err := NewJSONAlerter(JSONAlerterConfig{
		FilePath:      alertPath,
		Redact:        true,
		IncludeRawLog: true,
	})
	if err != nil {
		t.Fatalf("NewJSONAlerter() error = %v", err)
	}

	alert := domain.NewAlert(
		netip.MustParseAddr("192.0.2.10"),
		domain.ThreatTypeSQLInjection,
		domain.AlertLevelCritical,
		`GET /login?password=s3cr3t&token=abc HTTP/1.1`,
		9,
		"test alert",
	)
	alert.AddMetadata("target", "Cookie: session=abcdef")

	if err := alerter.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := alerter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	content, err := os.ReadFile(alertPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	output := string(content)
	for _, secret := range []string{"password=s3cr3t", "token=abc", "session=abcdef"} {
		if strings.Contains(output, secret) {
			t.Fatalf("output contains unredacted secret %q: %s", secret, output)
		}
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Fatalf("output does not contain redaction marker: %s", output)
	}
}

func TestJSONAlerterEmitsVersionedJSONLines(t *testing.T) {
	alertPath := filepath.Join(t.TempDir(), "alerts.jsonl")
	alerter, err := NewJSONAlerter(JSONAlerterConfig{
		FilePath: alertPath,
	})
	if err != nil {
		t.Fatalf("NewJSONAlerter() error = %v", err)
	}

	alert := domain.NewAlert(
		netip.MustParseAddr("192.0.2.10"),
		domain.ThreatTypeXSS,
		domain.AlertLevelWarning,
		`GET /?q=<script> HTTP/1.1`,
		6,
		"test alert",
	)
	if err := alerter.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := alerter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	content, err := os.ReadFile(alertPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 1 {
		t.Fatalf("line count = %d, want 1: %q", len(lines), string(content))
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &payload); err != nil {
		t.Fatalf("alert line is not valid JSON: %v", err)
	}
	if payload["schema_version"] != domain.AlertSchemaVersion {
		t.Fatalf("schema_version = %v, want %q", payload["schema_version"], domain.AlertSchemaVersion)
	}
}

func TestJSONAlerterGoldenVersionedSchema(t *testing.T) {
	alertPath := filepath.Join(t.TempDir(), "alerts.jsonl")
	alerter, err := NewJSONAlerter(JSONAlerterConfig{
		FilePath:      alertPath,
		IncludeRawLog: true,
		MaxAlertBytes: 4096,
	})
	if err != nil {
		t.Fatalf("NewJSONAlerter() error = %v", err)
	}

	alert := &domain.Alert{
		SchemaVersion: domain.AlertSchemaVersion,
		ID:            "alert-1",
		Timestamp:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		SourceIP:      netip.MustParseAddr("192.0.2.10"),
		ThreatType:    domain.ThreatTypeSQLInjection,
		Level:         domain.AlertLevelCritical,
		RawLog:        `GET /?id=1 UNION SELECT HTTP/1.1`,
		RiskScore:     9,
		Message:       "SQL Injection - UNION",
		RuleID:        "signature.sqli.union",
		RuleVersion:   "1",
		Confidence:    0.95,
		Evidence: domain.Evidence{
			Field:    "path",
			Fragment: "UNION SELECT",
		},
		Metadata: map[string]string{
			"detector": "signature",
		},
	}

	if err := alerter.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := alerter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	content, err := os.ReadFile(alertPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	got := strings.TrimSpace(string(content))
	want := `{"schema_version":"1.0","id":"alert-1","timestamp":"2026-01-01T00:00:00Z","source_ip":"192.0.2.10","threat_type":"SQL_INJECTION","level":"CRITICAL","raw_log":"GET /?id=1 UNION SELECT HTTP/1.1","risk_score":9,"message":"SQL Injection - UNION","rule_id":"signature.sqli.union","rule_version":"1","confidence":0.95,"evidence":{"field":"path","fragment":"UNION SELECT"},"metadata":{"detector":"signature"}}`
	if got != want {
		t.Fatalf("golden JSON mismatch\ngot:  %s\nwant: %s", got, want)
	}
}

func TestJSONAlerterCanOmitRawLog(t *testing.T) {
	alertPath := filepath.Join(t.TempDir(), "alerts.jsonl")
	alerter, err := NewJSONAlerter(JSONAlerterConfig{
		FilePath:      alertPath,
		IncludeRawLog: false,
	})
	if err != nil {
		t.Fatalf("NewJSONAlerter() error = %v", err)
	}

	alert := domain.NewAlert(
		netip.MustParseAddr("192.0.2.10"),
		domain.ThreatTypeSQLInjection,
		domain.AlertLevelCritical,
		`GET /login?password=s3cr3t HTTP/1.1`,
		9,
		"test alert",
	)

	if err := alerter.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := alerter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	content, err := os.ReadFile(alertPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(content, &payload); err != nil {
		t.Fatalf("alert line is not valid JSON: %v", err)
	}
	if payload["raw_log"] != "" {
		t.Fatalf("raw_log = %q, want empty string", payload["raw_log"])
	}
	if alert.RawLog == "" {
		t.Fatal("Send mutated original alert RawLog")
	}
}

func TestJSONAlerterRejectsOversizedAlert(t *testing.T) {
	alertPath := filepath.Join(t.TempDir(), "alerts.jsonl")
	alerter, err := NewJSONAlerter(JSONAlerterConfig{
		FilePath:      alertPath,
		IncludeRawLog: true,
		MaxAlertBytes: 128,
	})
	if err != nil {
		t.Fatalf("NewJSONAlerter() error = %v", err)
	}
	defer alerter.Close()

	alert := domain.NewAlert(
		netip.MustParseAddr("192.0.2.10"),
		domain.ThreatTypeSQLInjection,
		domain.AlertLevelCritical,
		strings.Repeat("x", 512),
		9,
		"test alert",
	)

	err = alerter.Send(context.Background(), alert)
	if err == nil {
		t.Fatal("Send() error = nil, want oversized alert error")
	}
	if !strings.Contains(err.Error(), "max_alert_bytes") {
		t.Fatalf("Send() error = %q, want max_alert_bytes", err)
	}
}

func TestJSONAlerterCloseIsIdempotent(t *testing.T) {
	alerter, err := NewJSONAlerter(JSONAlerterConfig{
		FilePath: filepath.Join(t.TempDir(), "alerts.jsonl"),
	})
	if err != nil {
		t.Fatalf("NewJSONAlerter() error = %v", err)
	}

	alert := domain.NewAlert(
		netip.MustParseAddr("192.0.2.10"),
		domain.ThreatTypeSQLInjection,
		domain.AlertLevelCritical,
		`192.0.2.10 - - [01/Jan/2024:00:00:00 +0000] "GET /?id=1 HTTP/1.1" 200 0`,
		9,
		"test alert",
	)
	if err := alerter.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if err := alerter.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := alerter.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
