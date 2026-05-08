package detection

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/xoelrdgz/logradar/internal/domain"
)

func TestLoadSignatureRulesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	rules := []byte(`version: "1"
rules:
  - id: custom-rce
    version: "2026-05-02"
    name: Custom RCE
    pattern: "(?i)custom_exec"
    threat_type: RCE
    level: CRITICAL
    risk_score: 10
    confidence: 0.98
    keywords: ["custom_exec"]
`)
	if err := os.WriteFile(path, rules, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	patterns, err := LoadSignatureRulesFile(path)
	if err != nil {
		t.Fatalf("LoadSignatureRulesFile() error = %v", err)
	}
	detector := NewSignatureDetector(patterns)
	result := detector.Detect(context.Background(), &domain.LogEntry{
		IP:   netip.MustParseAddr("192.0.2.10"),
		Path: "/?cmd=custom_exec",
	})

	if !result.Detected {
		t.Fatal("Detected = false, want true")
	}
	if result.ThreatType != domain.ThreatTypeRCE {
		t.Fatalf("ThreatType = %s, want RCE", result.ThreatType)
	}
	if result.RiskScore != 10 {
		t.Fatalf("RiskScore = %d, want 10", result.RiskScore)
	}
	if result.RuleID != "custom-rce" {
		t.Fatalf("RuleID = %q, want custom-rce", result.RuleID)
	}
	if result.RuleVersion != "2026-05-02" {
		t.Fatalf("RuleVersion = %q, want 2026-05-02", result.RuleVersion)
	}
	if result.Confidence != 0.98 {
		t.Fatalf("Confidence = %f, want 0.98", result.Confidence)
	}
}
