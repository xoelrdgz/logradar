package domain

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type ThreatInfo struct {
	IP          netip.Addr `json:"ip"`
	Source      string     `json:"source"`
	Confidence  float64    `json:"confidence"`
	Categories  []string   `json:"categories"`
	LastUpdated time.Time  `json:"last_updated"`
}

type IPStats struct {
	IP            netip.Addr
	TotalRequests atomic.Int64
	FailedLogins  atomic.Int64
	AlertCount    atomic.Int64
	LastSeen      atomic.Int64
	FirstSeen     time.Time
	StatusCodes   map[int]int
	mu            sync.RWMutex
}

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

func (s *IPStats) IncrementAlerts() {
	s.AlertCount.Add(1)
}
func (s *IPStats) GetAlertCount() int64 {
	return s.AlertCount.Load()
}

func (s *IPStats) GetTotalRequests() int64 {
	return s.TotalRequests.Load()
}

func (s *IPStats) GetLastSeen() time.Time {
	return time.Unix(s.LastSeen.Load(), 0)
}

type DetectionResult struct {
	Detected   bool
	ThreatType ThreatType
	Level      AlertLevel
	RiskScore  int
	Message    string
	Details    map[string]interface{}
}

func NoDetection() DetectionResult {
	return DetectionResult{Detected: false}
}

type MetricsSnapshot struct {
	TotalLinesProcessed int64
	MaliciousLines      int64
	TotalAlerts         int64
	LinesPerSecond      float64
	ActiveWorkers       int
	MemoryUsageMB       float64
	Uptime              time.Duration
	StartTime           time.Time
}

type AnalysisMetrics struct {
	totalLines     atomic.Int64
	maliciousLines atomic.Int64
	totalAlerts    atomic.Int64
	LinesPerSecond float64
	ActiveWorkers  int
	MemoryUsageMB  float64
	Uptime         time.Duration
	StartTime      time.Time

	mu sync.RWMutex
}

func NewAnalysisMetrics() *AnalysisMetrics {
	return &AnalysisMetrics{
		StartTime: time.Now(),
	}
}

func (m *AnalysisMetrics) IncrementLines() {
	m.totalLines.Add(1)
}

func (m *AnalysisMetrics) IncrementMaliciousLines() {
	m.maliciousLines.Add(1)
}

func (m *AnalysisMetrics) IncrementAlerts() {
	m.totalAlerts.Add(1)
}

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

func (m *AnalysisMetrics) UpdateLPS(lps float64) {
	m.mu.Lock()
	m.LinesPerSecond = lps
	m.mu.Unlock()
}

func (m *AnalysisMetrics) TotalLines() int64 {
	return m.totalLines.Load()
}

func (m *AnalysisMetrics) SetActiveWorkers(count int) {
	m.mu.Lock()
	m.ActiveWorkers = count
	m.mu.Unlock()
}

func (m *AnalysisMetrics) SetMemoryUsage(mb float64) {
	m.mu.Lock()
	m.MemoryUsageMB = mb
	m.mu.Unlock()
}
