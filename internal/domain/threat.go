// Package domain provides core threat intelligence and metrics structures.
//
// This file contains:
//   - ThreatInfo: Threat intelligence data for known malicious IPs
//   - IPStats: Per-IP request statistics for behavioral analysis
//   - DetectionResult: Standardized detector output format
//   - AnalysisMetrics: Runtime metrics with atomic counters
package domain

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ThreatInfo represents threat intelligence data for a known malicious IP.
// Populated from threat feeds, blocklists, or local intelligence sources.
type ThreatInfo struct {
	// IP is the threat actor's IP address.
	IP netip.Addr `json:"ip"`

	// Source identifies the intelligence feed or blocklist origin.
	// Examples: "abuse.ch", "spamhaus", "local", "honeypot"
	Source string `json:"source"`

	// Confidence is the threat attribution confidence (0.0-1.0).
	// Higher values indicate stronger evidence of malicious activity.
	Confidence float64 `json:"confidence"`

	// Categories classifies the threat type(s) associated with this IP.
	// Examples: ["botnet", "scanner"], ["tor_exit"], ["bruteforcer"]
	Categories []string `json:"categories"`

	// LastUpdated records when this intelligence was last refreshed.
	LastUpdated time.Time `json:"last_updated"`
}

// IPStats tracks per-IP request statistics for behavioral threat detection.
// Uses atomic operations for lock-free counter updates in hot path.
//
// Thread Safety:
//   - Counters use atomic operations (safe for concurrent updates)
//   - StatusCodes map uses mutex protection (less frequent access)
type IPStats struct {
	// IP is the client IP address being tracked.
	IP netip.Addr

	// TotalRequests counts all requests from this IP (atomic).
	TotalRequests atomic.Int64

	// FailedLogins counts 401/403 responses for brute force detection (atomic).
	FailedLogins atomic.Int64

	// AlertCount tracks alerts generated for this IP (atomic).
	AlertCount atomic.Int64

	// LastSeen stores the Unix timestamp of the most recent request (atomic).
	LastSeen atomic.Int64

	// FirstSeen records when this IP was first observed.
	FirstSeen time.Time

	// StatusCodes maps HTTP status codes to occurrence counts.
	// Protected by mutex for thread-safe updates.
	StatusCodes map[int]int
	mu          sync.RWMutex
}

// NewIPStats creates a new IPStats tracker for the given IP address.
//
// Parameters:
//   - ip: Client IP address to track
//
// Returns:
//   - Initialized IPStats with current time as FirstSeen/LastSeen
func NewIPStats(ip netip.Addr) *IPStats {
	now := time.Now()
	stats := &IPStats{
		IP:          ip,
		FirstSeen:   now,
		StatusCodes: make(map[int]int),
	}
	stats.LastSeen.Store(now.Unix())
	return stats
}

// RecordRequest updates statistics for a new request from this IP.
// Thread-safe via atomic operations and mutex.
//
// Parameters:
//   - statusCode: HTTP response status code (100-599)
//
// Side effects:
//   - Increments TotalRequests counter
//   - Updates LastSeen timestamp
//   - Increments StatusCodes map for the given code
//   - Increments FailedLogins for 401/403 responses
func (s *IPStats) RecordRequest(statusCode int) {
	s.TotalRequests.Add(1)
	s.LastSeen.Store(time.Now().Unix())

	s.mu.Lock()
	s.StatusCodes[statusCode]++
	s.mu.Unlock()

	if statusCode == 401 || statusCode == 403 {
		s.FailedLogins.Add(1)
	}
}

// IncrementAlerts atomically increments the alert counter.
func (s *IPStats) IncrementAlerts() {
	s.AlertCount.Add(1)
}

// GetAlertCount returns the current alert count for this IP.
func (s *IPStats) GetAlertCount() int64 {
	return s.AlertCount.Load()
}

// GetTotalRequests returns the total request count for this IP.
func (s *IPStats) GetTotalRequests() int64 {
	return s.TotalRequests.Load()
}

// GetLastSeen returns the time of the most recent request.
func (s *IPStats) GetLastSeen() time.Time {
	return time.Unix(s.LastSeen.Load(), 0)
}

// DetectionResult represents the output from a ThreatDetector.
// Used to standardize detector responses across different detection engines.
type DetectionResult struct {
	// Detected indicates whether a threat was identified.
	Detected bool

	// ThreatType categorizes the detected attack vector.
	ThreatType ThreatType

	// Level indicates severity for incident prioritization.
	Level AlertLevel

	// RiskScore is a 1-10 severity rating (used if Detected is true).
	RiskScore int

	// Message provides human-readable threat description.
	Message string

	// Details contains detector-specific context for investigation.
	// Keys should be lowercase with underscores (e.g., "matched_pattern").
	Details map[string]interface{}
}

// NoDetection returns a DetectionResult indicating no threat was found.
// Use this helper instead of constructing zero-value results manually.
func NoDetection() DetectionResult {
	return DetectionResult{Detected: false}
}

// MetricsSnapshot represents a point-in-time snapshot of analysis metrics.
// Used for TUI display and Prometheus metric export.
type MetricsSnapshot struct {
	// TotalLinesProcessed is the cumulative count of parsed log entries.
	TotalLinesProcessed int64

	// MaliciousLines is the count of entries with at least one detection.
	MaliciousLines int64

	// TotalAlerts is the cumulative count of alerts generated.
	TotalAlerts int64

	// LinesPerSecond is the current processing throughput.
	LinesPerSecond float64

	// ActiveWorkers is the number of worker goroutines currently processing.
	ActiveWorkers int

	// MemoryUsageMB is the current heap allocation in megabytes.
	MemoryUsageMB float64

	// Uptime is the duration since analyzer start.
	Uptime time.Duration

	// StartTime is when the analyzer was started.
	StartTime time.Time
}

// AnalysisMetrics provides thread-safe runtime metrics collection.
//
// Design:
//   - Hot-path counters use atomic operations (no locks)
//   - Infrequently updated fields use mutex protection
//   - Snapshot method provides consistent point-in-time view
type AnalysisMetrics struct {
	// Atomic counters for hot-path updates
	totalLines     atomic.Int64
	maliciousLines atomic.Int64
	totalAlerts    atomic.Int64

	// Mutex-protected fields (less frequent updates)
	LinesPerSecond float64
	ActiveWorkers  int
	MemoryUsageMB  float64
	Uptime         time.Duration
	StartTime      time.Time

	mu sync.RWMutex
}

// NewAnalysisMetrics creates an initialized metrics collector.
//
// Returns:
//   - AnalysisMetrics with StartTime set to current time
func NewAnalysisMetrics() *AnalysisMetrics {
	return &AnalysisMetrics{
		StartTime: time.Now(),
	}
}

// IncrementLines atomically increments the processed line counter.
// Called once per successfully parsed log entry.
func (m *AnalysisMetrics) IncrementLines() {
	m.totalLines.Add(1)
}

// IncrementMaliciousLines atomically increments the malicious line counter.
// Called once per log entry with at least one detection.
func (m *AnalysisMetrics) IncrementMaliciousLines() {
	m.maliciousLines.Add(1)
}

// IncrementAlerts atomically increments the total alert counter.
// Called once per alert generated (may exceed malicious lines if
// multiple detectors trigger on the same entry).
func (m *AnalysisMetrics) IncrementAlerts() {
	m.totalAlerts.Add(1)
}

// GetSnapshot returns a consistent point-in-time view of all metrics.
//
// Thread Safety: Safe to call from any goroutine. Uses read lock for
// mutex-protected fields and atomic loads for counters.
//
// Returns:
//   - MetricsSnapshot with all current values
func (m *AnalysisMetrics) GetSnapshot() MetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return MetricsSnapshot{
		TotalLinesProcessed: m.totalLines.Load(),
		MaliciousLines:      m.maliciousLines.Load(),
		TotalAlerts:         m.totalAlerts.Load(),
		LinesPerSecond:      m.LinesPerSecond,
		ActiveWorkers:       m.ActiveWorkers,
		MemoryUsageMB:       m.MemoryUsageMB,
		Uptime:              time.Since(m.StartTime),
		StartTime:           m.StartTime,
	}
}

// UpdateLPS updates the lines-per-second throughput metric.
// Called periodically by the metrics update goroutine.
//
// Parameters:
//   - lps: Current throughput in lines per second
func (m *AnalysisMetrics) UpdateLPS(lps float64) {
	m.mu.Lock()
	m.LinesPerSecond = lps
	m.mu.Unlock()
}

// TotalLines returns the current total processed line count (atomic).
func (m *AnalysisMetrics) TotalLines() int64 {
	return m.totalLines.Load()
}

// SetActiveWorkers updates the active worker count.
// Called when worker pool starts/stops workers.
//
// Parameters:
//   - count: Number of active worker goroutines
func (m *AnalysisMetrics) SetActiveWorkers(count int) {
	m.mu.Lock()
	m.ActiveWorkers = count
	m.mu.Unlock()
}

// SetMemoryUsage updates the memory usage metric.
// Called periodically by the metrics update goroutine.
//
// Parameters:
//   - mb: Current heap allocation in megabytes
func (m *AnalysisMetrics) SetMemoryUsage(mb float64) {
	m.mu.Lock()
	m.MemoryUsageMB = mb
	m.mu.Unlock()
}
