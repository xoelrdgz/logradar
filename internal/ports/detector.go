package ports

import (
	"context"

	"github.com/xoelrdgz/logradar/internal/domain"
)

type ThreatDetector interface {
	Detect(ctx context.Context, entry *domain.LogEntry) domain.DetectionResult
	Name() string
	Type() domain.ThreatType
}

type ThreatIntelligence interface {
	IsKnownMalicious(ip string) bool
	GetThreatInfo(ip string) (*domain.ThreatInfo, bool)
	Load(ctx context.Context) error
	Count() int
}

type BehavioralTracker interface {
	RecordEvent(ip string, statusCode int, timestamp int64)
	GetEventCount(ip string, windowSeconds int64) int64
	GetStatusCodeCount(ip string, statusCode int, windowSeconds int64) int64
	Cleanup()
}
