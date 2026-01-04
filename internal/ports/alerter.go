// Package ports defines the primary and secondary port interfaces following
// hexagonal architecture (ports and adapters pattern).
//
// This package contains interfaces that define the contract between the core
// domain logic and external infrastructure (input sources, output destinations).
//
// Design Principles:
//   - Interfaces are small and focused (Interface Segregation Principle)
//   - Dependencies flow inward (core domain has no external dependencies)
//   - Implementations provided by adapters in internal/adapters/
package ports

import (
	"context"

	"github.com/xoelrdgz/logradar/internal/domain"
)

// Alerter defines the interface for dispatching security alerts to outputs.
//
// Implementations:
//   - JSONAlerter: Writes alerts as JSON to file or stdout
//   - MemoryAlerter: In-memory ring buffer for TUI display
//   - (External: Splunk, Elasticsearch, Kafka, etc.)
//
// Thread Safety: Implementations MUST be safe for concurrent Send() calls.
type Alerter interface {
	// Send dispatches an alert to the output destination.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - alert: Immutable alert to dispatch
	//
	// Returns:
	//   - nil on success
	//   - Error if dispatch fails (caller may retry or log)
	//
	// Thread Safety: Must support concurrent calls from multiple workers.
	Send(ctx context.Context, alert *domain.Alert) error

	// Flush forces pending alerts to be written to destination.
	// Called during graceful shutdown to ensure alert delivery.
	//
	// Returns:
	//   - nil on success
	//   - Error if flush fails
	Flush() error

	// Close releases resources and ensures all alerts are flushed.
	// Must be called during application shutdown.
	//
	// Returns:
	//   - nil on success
	//   - Error if close fails
	Close() error
}

// AlertSubscriber defines the callback interface for alert notification.
// Used by the worker pool to notify interested components (TUI, metrics).
//
// Design: Push-based notification for real-time UI updates and metric collection.
type AlertSubscriber interface {
	// OnAlert is called synchronously when an alert is generated.
	//
	// Parameters:
	//   - alert: The generated alert (immutable, safe to store reference)
	//
	// Performance: Implementation should return quickly to avoid blocking
	// the worker pool. Use buffering for expensive operations.
	OnAlert(alert *domain.Alert)
}

// MetricsCollector defines the interface for observability metric collection.
// Implemented by Prometheus adapter for scraping by monitoring systems.
//
// Thread Safety: All methods MUST be safe for concurrent calls.
type MetricsCollector interface {
	// IncrementRequests increments the total request counter.
	// Called once per successfully parsed log entry.
	IncrementRequests()

	// IncrementThreats increments the threat counter by type.
	// Called once per detection (may be multiple per entry).
	//
	// Parameters:
	//   - threatType: The category of detected threat
	IncrementThreats(threatType domain.ThreatType)

	// ObserveProcessingTime records the processing duration for histograms.
	// Used for latency monitoring and SLA tracking.
	//
	// Parameters:
	//   - seconds: Processing duration in seconds (float for sub-second precision)
	ObserveProcessingTime(seconds float64)

	// SetActiveWorkers updates the active worker gauge.
	// Called when worker pool scales up/down.
	//
	// Parameters:
	//   - count: Current number of active workers
	SetActiveWorkers(count int)
}
