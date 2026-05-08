package detection

import (
	"context"
	"hash/fnv"
	"sync"

	"github.com/xoelrdgz/logradar/internal/domain"
)

type UAEntropyConfig struct {
	WindowSeconds          int64
	MinRequestsForAnalysis int
	RotationThreshold      float64
	RapidChangeThreshold   int
	RapidChangePeriodSec   int64
}

func DefaultUAEntropyConfig() UAEntropyConfig {
	return UAEntropyConfig{
		WindowSeconds:          60,
		MinRequestsForAnalysis: 10,
		RotationThreshold:      0.5,
		RapidChangeThreshold:   5,
		RapidChangePeriodSec:   10,
	}
}

type UAEvent struct {
	UAHash    uint32
	Timestamp int64
}

type UARotationWindow struct {
	Events          []UAEvent
	LastUA          uint32
	ChangeCount     int64
	TotalRequests   int64
	LastChangeTime  int64
	RapidChangeSpan int
	mu              sync.RWMutex
}

type UAEntropyDetector struct {
	config     UAEntropyConfig
	shards     []*uaEntropyShards
	shardCount int
}

type uaEntropyShards struct {
	windows map[string]*UARotationWindow
	mu      sync.RWMutex
}

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

func (d *UAEntropyDetector) getShard(ip string) *uaEntropyShards {
	h := fnv.New32a()
	h.Write([]byte(ip))
	return d.shards[h.Sum32()%uint32(d.shardCount)]
}

func (d *UAEntropyDetector) Detect(ctx context.Context, entry *domain.LogEntry) domain.DetectionResult {
	if entry == nil || !entry.IP.IsValid() {
		return domain.NoDetection()
	}

	ip := entry.IP.String()
	ua := entry.UserAgent
	timestamp := entry.Timestamp.Unix()

	h := fnv.New32a()
	h.Write([]byte(ua))
	uaHash := h.Sum32()

	shard := d.getShard(ip)

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

	cutoff := timestamp - d.config.WindowSeconds
	newEvents := window.Events[:0]
	for _, e := range window.Events {
		if e.Timestamp >= cutoff {
			newEvents = append(newEvents, e)
		}
	}
	window.Events = newEvents

	window.TotalRequests++
	uaChanged := false
	if window.LastUA != 0 && window.LastUA != uaHash {
		window.ChangeCount++
		uaChanged = true

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

	if window.TotalRequests < int64(d.config.MinRequestsForAnalysis) {
		return domain.NoDetection()
	}

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

func (d *UAEntropyDetector) Name() string {
	return "ua_entropy"
}

func (d *UAEntropyDetector) Type() domain.ThreatType {
	return domain.ThreatTypeBotDetection
}
