// Package detection implements User-Agent entropy analysis for bot detection.
//
// This file detects automated tools and bots by analyzing User-Agent rotation
// patterns. Legitimate users maintain consistent UAs while scanners rotate.
//
// Detection Strategies:
//   - Rotation ratio: Percentage of requests with changed UA
//   - Rapid changes: Multiple UA changes within short period
//   - Mid-session changes: UA changing during active session
//
// Thread Safety: Uses 16-way sharding for concurrent access with minimal contention.
package detection

import (
	"context"
	"hash/fnv"
	"sync"

	"github.com/xoelrdgz/logradar/internal/domain"
)

// UAEntropyConfig configures User-Agent entropy analysis.
type UAEntropyConfig struct {
	WindowSeconds          int64   // Time window for analysis (default: 60)
	MinRequestsForAnalysis int     // Min requests before alerting (default: 10)
	RotationThreshold      float64 // Ratio of changes to trigger (default: 0.5)
	RapidChangeThreshold   int     // Rapid changes to trigger (default: 5)
	RapidChangePeriodSec   int64   // Period for rapid change detection (default: 10)
}

// DefaultUAEntropyConfig returns production defaults.
//
// Defaults:
//   - 60 second analysis window
//   - 10 requests minimum before analysis
//   - 50% rotation ratio triggers alert
//   - 5 rapid changes in 10 seconds triggers critical alert
func DefaultUAEntropyConfig() UAEntropyConfig {
	return UAEntropyConfig{
		WindowSeconds:          60,
		MinRequestsForAnalysis: 10,
		RotationThreshold:      0.5,
		RapidChangeThreshold:   5,
		RapidChangePeriodSec:   10,
	}
}

// UAEvent records a single User-Agent observation.
type UAEvent struct {
	UAHash    uint32 // FNV hash of User-Agent string
	Timestamp int64  // Unix timestamp of request
}

// UARotationWindow tracks UA rotation patterns for a single IP.
type UARotationWindow struct {
	Events          []UAEvent    // Recent UA events
	LastUA          uint32       // Hash of last seen UA
	ChangeCount     int64        // Total UA changes
	TotalRequests   int64        // Total requests seen
	LastChangeTime  int64        // Timestamp of last change
	RapidChangeSpan int          // Consecutive rapid changes
	mu              sync.RWMutex // Protects all fields
}

// UAEntropyDetector detects bots via User-Agent rotation analysis.
//
// Detection Logic:
//   - Track all UAs per IP with timestamps
//   - Detect rapid rotation (many changes in short period)
//   - Detect high rotation ratio (many unique UAs)
//   - Detect mid-session changes (UA swap during activity)
type UAEntropyDetector struct {
	config     UAEntropyConfig    // Detection thresholds
	shards     []*uaEntropyShards // Sharded IP tracking
	shardCount int                // Number of shards
}

// uaEntropyShards holds UA tracking for a subset of IPs.
type uaEntropyShards struct {
	windows map[string]*UARotationWindow // IP -> UA tracking
	mu      sync.RWMutex                 // Protects map
}

// NewUAEntropyDetector creates a UA entropy detector.
//
// Parameters:
//   - config: Detection thresholds and settings
//
// Returns:
//   - Configured UAEntropyDetector ready for Detect()
func NewUAEntropyDetector(config UAEntropyConfig) *UAEntropyDetector {
	shardCount := 16
	shards := make([]*uaEntropyShards, shardCount)
	for i := 0; i < shardCount; i++ {
		shards[i] = &uaEntropyShards{
			windows: make(map[string]*UARotationWindow),
		}
	}

	return &UAEntropyDetector{
		config:     config,
		shards:     shards,
		shardCount: shardCount,
	}
}

// getShard returns the shard for an IP using FNV hash.
func (d *UAEntropyDetector) getShard(ip string) *uaEntropyShards {
	h := fnv.New32a()
	h.Write([]byte(ip))
	return d.shards[h.Sum32()%uint32(d.shardCount)]
}

// Detect analyzes a log entry for User-Agent rotation patterns.
//
// Parameters:
//   - ctx: Context for cancellation
//   - entry: Log entry to analyze
//
// Returns:
//   - DetectionResult with Detected=true if bot behavior detected
//
// Alert Levels:
//   - CRITICAL: Rapid UA rotation (bot evasion pattern)
//   - WARNING: High rotation ratio (possible scanner)
//   - INFO: Mid-session UA change
func (d *UAEntropyDetector) Detect(ctx context.Context, entry *domain.LogEntry) domain.DetectionResult {
	if entry == nil || !entry.IP.IsValid() {
		return domain.NoDetection()
	}

	ip := entry.IP.String()
	ua := entry.UserAgent
	timestamp := entry.Timestamp.Unix()

	// Hash User-Agent for efficient comparison
	h := fnv.New32a()
	h.Write([]byte(ua))
	uaHash := h.Sum32()

	shard := d.getShard(ip)

	// Get or create window for IP
	shard.mu.Lock()
	window, exists := shard.windows[ip]
	if !exists {
		window = &UARotationWindow{
			Events: make([]UAEvent, 0, 100),
		}
		shard.windows[ip] = window
	}
	shard.mu.Unlock()

	window.mu.Lock()
	defer window.mu.Unlock()

	// Expire old events outside window
	cutoff := timestamp - d.config.WindowSeconds
	newEvents := window.Events[:0]
	for _, e := range window.Events {
		if e.Timestamp >= cutoff {
			newEvents = append(newEvents, e)
		}
	}
	window.Events = newEvents

	// Record this request
	window.TotalRequests++
	uaChanged := false
	if window.LastUA != 0 && window.LastUA != uaHash {
		window.ChangeCount++
		uaChanged = true

		// Track rapid changes
		if timestamp-window.LastChangeTime <= d.config.RapidChangePeriodSec {
			window.RapidChangeSpan++
		} else {
			window.RapidChangeSpan = 1
		}
		window.LastChangeTime = timestamp
	}
	window.LastUA = uaHash

	window.Events = append(window.Events, UAEvent{
		UAHash:    uaHash,
		Timestamp: timestamp,
	})

	// Need minimum requests before analysis
	if window.TotalRequests < int64(d.config.MinRequestsForAnalysis) {
		return domain.NoDetection()
	}

	// Check for rapid rotation (bot evasion pattern)
	if window.RapidChangeSpan >= d.config.RapidChangeThreshold {
		return domain.DetectionResult{
			Detected:   true,
			ThreatType: domain.ThreatTypeBotDetection,
			Level:      domain.AlertLevelCritical,
			RiskScore:  9,
			Message:    "Rapid User-Agent rotation detected (bot evasion pattern)",
			Details: map[string]interface{}{
				"rapid_changes": window.RapidChangeSpan,
				"threshold":     d.config.RapidChangeThreshold,
				"period_sec":    d.config.RapidChangePeriodSec,
				"ip":            ip,
			},
		}
	}

	// Check rotation ratio
	rotationRatio := float64(window.ChangeCount) / float64(window.TotalRequests)
	if rotationRatio >= d.config.RotationThreshold {
		return domain.DetectionResult{
			Detected:   true,
			ThreatType: domain.ThreatTypeBotDetection,
			Level:      domain.AlertLevelWarning,
			RiskScore:  7,
			Message:    "High User-Agent rotation ratio (possible scanner)",
			Details: map[string]interface{}{
				"rotation_ratio": rotationRatio,
				"threshold":      d.config.RotationThreshold,
				"changes":        window.ChangeCount,
				"requests":       window.TotalRequests,
				"ip":             ip,
			},
		}
	}

	// Check mid-session change with elevated ratio
	if uaChanged && rotationRatio > 0.3 {
		return domain.DetectionResult{
			Detected:   true,
			ThreatType: domain.ThreatTypeBotDetection,
			Level:      domain.AlertLevelInfo,
			RiskScore:  4,
			Message:    "User-Agent changed mid-session",
			Details: map[string]interface{}{
				"rotation_ratio": rotationRatio,
				"ip":             ip,
			},
		}
	}

	return domain.NoDetection()
}

// Name returns the detector identifier for logging and metrics.
func (d *UAEntropyDetector) Name() string {
	return "ua_entropy"
}

// Type returns the primary threat type this detector handles.
func (d *UAEntropyDetector) Type() domain.ThreatType {
	return domain.ThreatTypeBotDetection
}
