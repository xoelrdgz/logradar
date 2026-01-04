// Package ports defines the detection engine interfaces.
//
// ThreatDetector is the primary interface for all detection engines.
// Implementations analyze log entries and return standardized detection results.
package ports

import (
	"context"

	"github.com/xoelrdgz/logradar/internal/domain"
)

// ThreatDetector defines the interface for threat detection engines.
//
// Implementations:
//   - SignatureDetector: Pattern-based detection (regex, Aho-Corasick)
//   - BehavioralDetector: Statistical anomaly detection
//   - ThreatIntelDetector: Known-bad IP matching
//   - SQLTokenizerDetector: Token-based SQL injection detection
//   - UAEntropyDetector: Bot detection via User-Agent analysis
//
// Thread Safety: Implementations MUST be safe for concurrent Detect() calls.
// The worker pool invokes Detect() from multiple goroutines simultaneously.
type ThreatDetector interface {
	// Detect analyzes a log entry for threat indicators.
	//
	// Parameters:
	//   - ctx: Context for cancellation (long-running analysis should check)
	//   - entry: Parsed log entry to analyze (immutable, do not modify)
	//
	// Returns:
	//   - DetectionResult with Detected=true if threat found
	//   - DetectionResult with Detected=false if entry is benign
	//
	// Contract:
	//   - MUST be thread-safe
	//   - MUST NOT modify the entry
	//   - SHOULD return quickly (<1ms for signature, <10ms for behavioral)
	//   - SHOULD respect context cancellation
	Detect(ctx context.Context, entry *domain.LogEntry) domain.DetectionResult

	// Name returns the detector's identifier for logging and metrics.
	// Format: lowercase with underscores (e.g., "signature", "behavioral")
	Name() string

	// Type returns the primary threat type this detector specializes in.
	// Used for metric labeling and alert categorization.
	Type() domain.ThreatType
}

// ThreatIntelligence defines the interface for threat intelligence lookups.
//
// Implementations:
//   - ThreatIntelligence: In-memory with atomic pointer swap
//   - HybridThreatStore: BoltDB + Bloom filter for large datasets
//
// Thread Safety: All methods MUST be safe for concurrent access.
type ThreatIntelligence interface {
	// IsKnownMalicious checks if an IP is in the threat intelligence database.
	// Optimized for hot-path performance using Bloom filter pre-check.
	//
	// Parameters:
	//   - ip: IP address string to check
	//
	// Returns:
	//   - true if IP is known malicious
	//   - false if IP is not in database (or false positive on Bloom check)
	IsKnownMalicious(ip string) bool

	// GetThreatInfo retrieves detailed threat intelligence for an IP.
	// Called only when IsKnownMalicious returns true (after Bloom check).
	//
	// Parameters:
	//   - ip: IP address string to lookup
	//
	// Returns:
	//   - ThreatInfo with source, confidence, categories
	//   - bool indicating if info was found
	GetThreatInfo(ip string) (*domain.ThreatInfo, bool)

	// Load initializes or refreshes threat intelligence from source.
	// Supports zero-downtime reload via atomic pointer swap.
	//
	// Parameters:
	//   - ctx: Context for cancellation during load
	//
	// Returns:
	//   - nil on success
	//   - Error if load fails (previous data retained)
	Load(ctx context.Context) error

	// Count returns the number of entries in the threat intelligence database.
	Count() int
}

// BehavioralTracker defines the interface for IP behavior tracking.
// Used by behavioral detectors to maintain per-IP state for anomaly detection.
//
// Thread Safety: All methods MUST be safe for concurrent access.
// Implementations should use sharding to reduce lock contention.
type BehavioralTracker interface {
	// RecordEvent records a request event for an IP address.
	//
	// Parameters:
	//   - ip: Client IP address
	//   - statusCode: HTTP response status
	//   - timestamp: Unix timestamp of the request
	RecordEvent(ip string, statusCode int, timestamp int64)

	// GetEventCount returns the request count for an IP within a time window.
	//
	// Parameters:
	//   - ip: Client IP address
	//   - windowSeconds: Time window in seconds
	//
	// Returns:
	//   - Number of events in the window
	GetEventCount(ip string, windowSeconds int64) int64

	// GetStatusCodeCount returns the count of specific status codes for an IP.
	//
	// Parameters:
	//   - ip: Client IP address
	//   - statusCode: HTTP status code to count
	//   - windowSeconds: Time window in seconds
	//
	// Returns:
	//   - Number of matching status codes in the window
	GetStatusCodeCount(ip string, statusCode int, windowSeconds int64) int64

	// Cleanup removes expired entries to prevent memory growth.
	// Should be called periodically by a background goroutine.
	Cleanup()
}
