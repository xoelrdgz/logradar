package tui

import (
	"container/heap"
	"strings"
	"sync"

	"github.com/xoelrdgz/logradar/internal/domain"
)

type Model struct {
	Width  int
	Height int

	ActiveView int
	ScrollPos  int

	Alerts     []*domain.Alert
	TopIPs     []*IPEntry
	Metrics    domain.MetricsSnapshot
	Sparkline  []float64
	ipMap      map[string]*IPEntry
	ipHeap     *ipMaxHeap
	ipCounters map[string]int

	MaxAlerts       int
	MaxTopIPs       int
	MaxTrackedIPs   int
	SparklineWidth  int
	RefreshInterval int

	mu         sync.RWMutex
	alertCount int
	running    bool

	Paused         bool
	FilterSeverity domain.AlertLevel
	FilterType     domain.ThreatType
	FilterIP       string
	FilterRuleID   string
	SearchQuery    string
}

type IPEntry struct {
	IP          string
	AlertCount  int
	LastSeen    string
	ThreatTypes []string
	heapIndex   int
}

type ipMaxHeap []*IPEntry

func (h ipMaxHeap) Len() int           { return len(h) }
func (h ipMaxHeap) Less(i, j int) bool { return h[i].AlertCount > h[j].AlertCount }
func (h ipMaxHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIndex = i
	h[j].heapIndex = j
}

func (h *ipMaxHeap) Push(x any) {
	n := len(*h)
	item := x.(*IPEntry)
	item.heapIndex = n
	*h = append(*h, item)
}

func (h *ipMaxHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.heapIndex = -1
	*h = old[0 : n-1]
	return item
}

func NewModel() *Model {
	h := &ipMaxHeap{}
	heap.Init(h)

	return &Model{
		Width:           120,
		Height:          40,
		Alerts:          make([]*domain.Alert, 0, 100),
		TopIPs:          make([]*IPEntry, 0, 10),
		Sparkline:       make([]float64, 60),
		ipMap:           make(map[string]*IPEntry),
		ipHeap:          h,
		ipCounters:      make(map[string]int),
		MaxAlerts:       50,
		MaxTopIPs:       25,
		MaxTrackedIPs:   10000,
		SparklineWidth:  60,
		RefreshInterval: 100,
	}
}

func (m *Model) IncrementIPCounter(alert *domain.Alert) {
	if !alert.SourceIP.IsValid() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	ip := alert.SourceIP.String()
	m.ipCounters[ip]++
	m.alertCount++

	if entry, exists := m.ipMap[ip]; exists {
		entry.AlertCount = m.ipCounters[ip]
		entry.LastSeen = alert.Timestamp.Format("15:04:05")
		hasType := false
		for _, t := range entry.ThreatTypes {
			if t == string(alert.ThreatType) {
				hasType = true
				break
			}
		}
		if !hasType && len(entry.ThreatTypes) < 5 {
			entry.ThreatTypes = append(entry.ThreatTypes, string(alert.ThreatType))
		}
		heap.Fix(m.ipHeap, entry.heapIndex)
	} else {
		if len(m.ipMap) >= m.MaxTrackedIPs && m.ipHeap.Len() > 0 {
			minIdx := 0
			minCount := (*m.ipHeap)[0].AlertCount
			for i := 1; i < m.ipHeap.Len(); i++ {
				if (*m.ipHeap)[i].AlertCount < minCount {
					minCount = (*m.ipHeap)[i].AlertCount
					minIdx = i
				}
			}
			oldEntry := (*m.ipHeap)[minIdx]
			heap.Remove(m.ipHeap, minIdx)
			delete(m.ipMap, oldEntry.IP)
		}
		entry := &IPEntry{
			IP:          ip,
			AlertCount:  m.ipCounters[ip],
			LastSeen:    alert.Timestamp.Format("15:04:05"),
			ThreatTypes: []string{string(alert.ThreatType)},
		}
		m.ipMap[ip] = entry
		heap.Push(m.ipHeap, entry)
	}
}

func (m *Model) AddAlert(alert *domain.Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Alerts) >= m.MaxAlerts {
		copy(m.Alerts, m.Alerts[1:])
		m.Alerts = m.Alerts[:len(m.Alerts)-1]
	}
	m.Alerts = append(m.Alerts, alert)
}

func (m *Model) rebuildTopIPs() {
	n := m.MaxTopIPs
	if n > m.ipHeap.Len() {
		n = m.ipHeap.Len()
	}

	m.TopIPs = make([]*IPEntry, 0, n)
	for i := 0; i < n && i < len(*m.ipHeap); i++ {
		m.TopIPs = append(m.TopIPs, (*m.ipHeap)[i])
	}
	for i := 0; i < len(m.TopIPs)-1; i++ {
		for j := i + 1; j < len(m.TopIPs); j++ {
			if m.TopIPs[j].AlertCount > m.TopIPs[i].AlertCount {
				m.TopIPs[i], m.TopIPs[j] = m.TopIPs[j], m.TopIPs[i]
			}
		}
	}
}

func (m *Model) UpdateMetrics(metrics domain.MetricsSnapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Metrics = metrics
	m.Sparkline = append(m.Sparkline[1:], metrics.LinesPerSecond)
}

func (m *Model) GetAlerts() []*domain.Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*domain.Alert, 0, len(m.Alerts))
	for _, alert := range m.Alerts {
		if m.matchesFilters(alert) {
			result = append(result, alert)
		}
	}
	return result
}

func (m *Model) matchesFilters(alert *domain.Alert) bool {
	if alert == nil {
		return false
	}
	if m.FilterSeverity != "" && alert.Level != m.FilterSeverity {
		return false
	}
	if m.FilterType != "" && alert.ThreatType != m.FilterType {
		return false
	}
	if m.FilterIP != "" && alert.IPString() != m.FilterIP {
		return false
	}
	if m.FilterRuleID != "" && alert.RuleID != m.FilterRuleID {
		return false
	}
	if m.SearchQuery != "" {
		q := strings.ToLower(m.SearchQuery)
		haystack := strings.ToLower(alert.Message + " " + alert.RawLog + " " + string(alert.ThreatType) + " " + alert.RuleID)
		if !strings.Contains(haystack, q) {
			return false
		}
	}
	return true
}

func (m *Model) GetTopIPs() []*IPEntry {
	m.mu.Lock()
	m.rebuildTopIPs()
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*IPEntry, len(m.TopIPs))
	copy(result, m.TopIPs)
	return result
}

func (m *Model) GetSparkline() []float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]float64, len(m.Sparkline))
	copy(result, m.Sparkline)
	return result
}

func (m *Model) GetMetrics() domain.MetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Metrics
}

func (m *Model) TotalAlerts() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.alertCount
}

func (m *Model) TotalTrackedIPs() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.ipMap)
}

func (m *Model) OnAlert(alert *domain.Alert) {
	m.AddAlert(alert)
}

func (m *Model) SetDimensions(width, height int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Width = width
	m.Height = height
}

func (m *Model) NextView() {
	m.ActiveView = (m.ActiveView + 1) % 2
	m.ScrollPos = 0
}

func (m *Model) ScrollUp() {
	if m.ScrollPos > 0 {
		m.ScrollPos--
	}
}

func (m *Model) ScrollDown() {
	m.ScrollPos++
}

func (m *Model) TogglePause() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Paused = !m.Paused
}

func (m *Model) SetSearch(query string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SearchQuery = query
}

func (m *Model) CycleSeverityFilter() {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.FilterSeverity {
	case "":
		m.FilterSeverity = domain.AlertLevelCritical
	case domain.AlertLevelCritical:
		m.FilterSeverity = domain.AlertLevelWarning
	case domain.AlertLevelWarning:
		m.FilterSeverity = domain.AlertLevelInfo
	default:
		m.FilterSeverity = ""
	}
}

func (m *Model) ClearFilters() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FilterSeverity = ""
	m.FilterType = ""
	m.FilterIP = ""
	m.FilterRuleID = ""
	m.SearchQuery = ""
}

func (m *Model) FilterSummary() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	parts := []string{}
	if m.Paused {
		parts = append(parts, "PAUSED")
	}
	if m.FilterSeverity != "" {
		parts = append(parts, "LVL="+string(m.FilterSeverity))
	}
	if m.FilterType != "" {
		parts = append(parts, "TYPE="+string(m.FilterType))
	}
	if m.FilterIP != "" {
		parts = append(parts, "IP="+m.FilterIP)
	}
	if m.FilterRuleID != "" {
		parts = append(parts, "RULE="+m.FilterRuleID)
	}
	if m.SearchQuery != "" {
		parts = append(parts, "Q="+m.SearchQuery)
	}
	if len(parts) == 0 {
		return "ALL"
	}
	return strings.Join(parts, " ")
}
