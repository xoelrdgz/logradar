package ports

import (
	"context"

	"github.com/xoelrdgz/logradar/internal/domain"
)

type Alerter interface {
	Send(ctx context.Context, alert *domain.Alert) error
	Flush() error
	Close() error
}

type AlertSubscriber interface {
	OnAlert(alert *domain.Alert)
}

type MetricsCollector interface {
	IncrementRequests()
	IncrementThreats(threatType domain.ThreatType)
	ObserveProcessingTime(seconds float64)
	SetActiveWorkers(count int)
}
