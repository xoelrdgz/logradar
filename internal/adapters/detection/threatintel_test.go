package detection

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xoelrdgz/logradar/internal/domain"
)

func TestParseThreatIntelLineExtendedFormat(t *testing.T) {
	now := time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)

	ip, info, expiresAt, err := parseThreatIntelLine("192.0.2.10,abuseipdb,0.75,scanner|botnet,24h", now, 0)
	if err != nil {
		t.Fatalf("parseThreatIntelLine() error = %v", err)
	}
	if ip != "192.0.2.10" {
		t.Fatalf("ip = %q, want 192.0.2.10", ip)
	}
	if info.Source != "abuseipdb" {
		t.Fatalf("Source = %q, want abuseipdb", info.Source)
	}
	if info.Confidence != 0.75 {
		t.Fatalf("Confidence = %v, want 0.75", info.Confidence)
	}
	if len(info.Categories) != 2 || info.Categories[0] != "scanner" || info.Categories[1] != "botnet" {
		t.Fatalf("Categories = %#v, want scanner and botnet", info.Categories)
	}
	if !expiresAt.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("expiresAt = %v, want %v", expiresAt, now.Add(24*time.Hour))
	}
}

func TestThreatIntelligenceLoadSkipsExpiredEntries(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "ips.txt")
	content := "192.0.2.10,feed,0.9,scanner,2000-01-01T00:00:00Z\n198.51.100.10,feed,0.8,botnet,24h\n"
	if err := os.WriteFile(feedPath, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	intel := NewThreatIntelligence(ThreatIntelConfig{
		Filepath:          feedPath,
		BloomSize:         100,
		FalsePositiveRate: 0.01,
	})
	if err := intel.Load(context.Background()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if intel.IsKnownMalicious("192.0.2.10") {
		t.Fatal("expired IP is known malicious, want skipped")
	}
	if !intel.IsKnownMalicious("198.51.100.10") {
		t.Fatal("valid IP is not known malicious")
	}
}

func TestThreatIntelligenceLoadMergesFeedFiles(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "primary.txt")
	secondary := filepath.Join(dir, "secondary.txt")
	if err := os.WriteFile(primary, []byte("192.0.2.10,primary\n"), 0600); err != nil {
		t.Fatalf("WriteFile(primary) error = %v", err)
	}
	if err := os.WriteFile(secondary, []byte("198.51.100.10,secondary\n"), 0600); err != nil {
		t.Fatalf("WriteFile(secondary) error = %v", err)
	}

	intel := NewThreatIntelligence(ThreatIntelConfig{
		Filepath:          primary,
		FeedFiles:         []string{secondary},
		BloomSize:         100,
		FalsePositiveRate: 0.01,
	})
	if err := intel.Load(context.Background()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	for _, ip := range []string{"192.0.2.10", "198.51.100.10"} {
		if !intel.IsKnownMalicious(ip) {
			t.Fatalf("%s is not known malicious", ip)
		}
	}
	if intel.Count() != 2 {
		t.Fatalf("Count() = %d, want 2", intel.Count())
	}
}

func TestThreatIntelDetectorIncludesSourceConfidenceAndLastUpdated(t *testing.T) {
	intel := NewThreatIntelligence(DefaultThreatIntelConfig())
	intel.AddMaliciousIP("192.0.2.10", &domain.ThreatInfo{
		IP:          netip.MustParseAddr("192.0.2.10"),
		Source:      "local-feed",
		Confidence:  0.6,
		Categories:  []string{"scanner"},
		LastUpdated: time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC),
	})
	detector := NewThreatIntelDetector(intel)

	result := detector.Detect(context.Background(), &domain.LogEntry{
		IP: netip.MustParseAddr("192.0.2.10"),
	})

	if !result.Detected {
		t.Fatal("Detected = false, want true")
	}
	if result.Details["source"] != "local-feed" {
		t.Fatalf("source = %v, want local-feed", result.Details["source"])
	}
	if result.Details["confidence"] != "0.60" {
		t.Fatalf("confidence = %v, want 0.60", result.Details["confidence"])
	}
	if result.Details["last_updated"] != "2026-05-02T12:00:00Z" {
		t.Fatalf("last_updated = %v, want RFC3339 timestamp", result.Details["last_updated"])
	}
}
