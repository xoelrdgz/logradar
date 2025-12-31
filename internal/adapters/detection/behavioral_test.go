package detection

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/xoelrdgz/logradar/internal/domain"
)

func TestBehavioralDetector_BruteForce(t *testing.T) {
	config := BehavioralConfig{
		ShardCount:          4,
		BruteForceThreshold: 5,
		BruteForceWindow:    60,
		BruteForceStatus:    401,
		RateLimitThreshold:  100,
		RateLimitWindow:     10,
		CleanupInterval:     1 * time.Hour,
	}
	detector := NewBehavioralDetector(config)
	defer detector.Stop()

	ctx := context.Background()
	ip := netip.MustParseAddr("10.0.0.1")

	for i := 0; i < 5; i++ {
		entry := &domain.LogEntry{
			IP:         ip,
			Timestamp:  time.Now(),
			StatusCode: 401,
		}
		result := detector.Detect(ctx, entry)
		assert.False(t, result.Detected, "Attempt %d should not trigger", i+1)
	}

	entry := &domain.LogEntry{
		IP:         ip,
		Timestamp:  time.Now(),
		StatusCode: 401,
	}
	result := detector.Detect(ctx, entry)
	assert.True(t, result.Detected)
	assert.Equal(t, domain.ThreatTypeBruteForce, result.ThreatType)
	assert.Equal(t, domain.AlertLevelCritical, result.Level)
}

func TestBehavioralDetector_RateLimit(t *testing.T) {
	config := BehavioralConfig{
		ShardCount:          4,
		BruteForceThreshold: 100,
		BruteForceWindow:    60,
		BruteForceStatus:    401,
		RateLimitThreshold:  10,
		RateLimitWindow:     10,
		CleanupInterval:     1 * time.Hour,
	}
	detector := NewBehavioralDetector(config)
	defer detector.Stop()

	ctx := context.Background()
	ip := netip.MustParseAddr("10.0.0.2")

	for i := 0; i < 10; i++ {
		entry := &domain.LogEntry{
			IP:         ip,
			Timestamp:  time.Now(),
			StatusCode: 200,
		}
		result := detector.Detect(ctx, entry)
		assert.False(t, result.Detected, "Request %d should not trigger", i+1)
	}

	entry := &domain.LogEntry{
		IP:         ip,
		Timestamp:  time.Now(),
		StatusCode: 200,
	}
	result := detector.Detect(ctx, entry)
	assert.True(t, result.Detected)
	assert.Equal(t, domain.ThreatTypeRateLimitDoS, result.ThreatType)
}

func TestBehavioralDetector_DifferentIPs(t *testing.T) {
	config := DefaultBehavioralConfig()
	config.BruteForceThreshold = 3
	config.CleanupInterval = 1 * time.Hour
	detector := NewBehavioralDetector(config)
	defer detector.Stop()

	ctx := context.Background()

	for i := 0; i < 3; i++ {
		entry := &domain.LogEntry{
			IP:         netip.MustParseAddr("10.0.0.1"),
			Timestamp:  time.Now(),
			StatusCode: 401,
		}
		detector.Detect(ctx, entry)
	}

	for i := 0; i < 3; i++ {
		entry := &domain.LogEntry{
			IP:         netip.MustParseAddr("10.0.0.2"),
			Timestamp:  time.Now(),
			StatusCode: 401,
		}
		detector.Detect(ctx, entry)
	}

	entry1 := &domain.LogEntry{
		IP:         netip.MustParseAddr("10.0.0.1"),
		Timestamp:  time.Now(),
		StatusCode: 401,
	}
	result1 := detector.Detect(ctx, entry1)
	assert.True(t, result1.Detected)

	entry2 := &domain.LogEntry{
		IP:         netip.MustParseAddr("10.0.0.2"),
		Timestamp:  time.Now(),
		StatusCode: 401,
	}
	result2 := detector.Detect(ctx, entry2)
	assert.True(t, result2.Detected)
}

func TestBehavioralDetector_NilEntry(t *testing.T) {
	detector := NewBehavioralDetector(DefaultBehavioralConfig())
	defer detector.Stop()

	result := detector.Detect(context.Background(), nil)
	assert.False(t, result.Detected)
}

func TestBehavioralDetector_InvalidIP(t *testing.T) {
	detector := NewBehavioralDetector(DefaultBehavioralConfig())
	defer detector.Stop()

	entry := &domain.LogEntry{
		IP:        netip.Addr{},
		Timestamp: time.Now(),
	}

	result := detector.Detect(context.Background(), entry)
	assert.False(t, result.Detected)
}

func TestBehavioralDetector_GetEventCount(t *testing.T) {
	detector := NewBehavioralDetector(DefaultBehavioralConfig())
	defer detector.Stop()

	ip := "10.0.0.5"

	now := time.Now().Unix()
	detector.RecordEvent(ip, 200, "", now)
	detector.RecordEvent(ip, 200, "", now)
	detector.RecordEvent(ip, 401, "", now)

	count := detector.GetEventCount(ip, 60)
	assert.Equal(t, int64(3), count)

	statusCount := detector.GetStatusCodeCount(ip, 401, 60)
	assert.Equal(t, int64(1), statusCount)
}

func TestBehavioralDetector_Name(t *testing.T) {
	detector := NewBehavioralDetector(DefaultBehavioralConfig())
	defer detector.Stop()
	assert.Equal(t, "behavioral", detector.Name())
}

func TestBehavioralDetector_Cleanup(t *testing.T) {
	config := DefaultBehavioralConfig()
	config.CleanupInterval = 1 * time.Hour
	detector := NewBehavioralDetector(config)
	defer detector.Stop()

	ip := "10.0.0.10"
	oldTime := time.Now().Unix() - 3600
	detector.RecordEvent(ip, 200, "", oldTime)
	detector.Cleanup()

	count := detector.GetEventCount(ip, 60)
	assert.Equal(t, int64(0), count)
}

func BenchmarkBehavioralDetector(b *testing.B) {
	detector := NewBehavioralDetector(DefaultBehavioralConfig())
	defer detector.Stop()

	entry := &domain.LogEntry{
		IP:         netip.MustParseAddr("192.168.1.1"),
		Timestamp:  time.Now(),
		StatusCode: 200,
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect(ctx, entry)
	}
}

func BenchmarkBehavioralDetectorParallel(b *testing.B) {
	detector := NewBehavioralDetector(DefaultBehavioralConfig())
	defer detector.Stop()
	ctx := context.Background()

	b.RunParallel(func(pb *testing.PB) {
		entry := &domain.LogEntry{
			IP:         netip.MustParseAddr("192.168.1.1"),
			Timestamp:  time.Now(),
			StatusCode: 200,
		}
		for pb.Next() {
			detector.Detect(ctx, entry)
		}
	})
}
