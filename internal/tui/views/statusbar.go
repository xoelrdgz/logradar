package views

import (
	"fmt"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/xoelrdgz/logradar/internal/domain"
)

type Status struct {
	Width      int
	Metrics    domain.MetricsSnapshot
	StartTime  time.Time
	lastUpdate time.Time
	Dropped    int64
}

func NewStatus(width int) *Status {
	return &Status{Width: width, StartTime: time.Now()}
}

func (s *Status) Update(metrics domain.MetricsSnapshot) {
	s.Metrics = metrics
	s.lastUpdate = time.Now()
}

func (s *Status) Render() string {
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#8df7b2"))
	greenDim := lipgloss.NewStyle().Foreground(lipgloss.Color("#4da873"))
	amber := lipgloss.NewStyle().Foreground(lipgloss.Color("#f2c36b"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("#ff6b5f"))
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("#82908a"))
	border := lipgloss.NewStyle().Foreground(lipgloss.Color("#26322d"))

	hb := s.heartbeat(green, greenDim, amber, red)

	lps := green
	if s.Metrics.LinesPerSecond > 50000 {
		lps = lipgloss.NewStyle().Foreground(lipgloss.Color("#00b8ff")).Bold(true)
	}

	mal := green
	if s.Metrics.MaliciousLines > 500 {
		mal = red.Bold(true)
	} else if s.Metrics.MaliciousLines > 100 {
		mal = amber.Bold(true)
	}

	alrt := green
	if s.Metrics.TotalAlerts > 2000 {
		alrt = red.Bold(true)
	} else if s.Metrics.TotalAlerts > 500 {
		alrt = amber.Bold(true)
	}

	mem := green
	if s.Metrics.MemoryUsageMB > 1000 {
		mem = red.Bold(true)
	} else if s.Metrics.MemoryUsageMB > 500 {
		mem = amber.Bold(true)
	}

	uptime := time.Since(s.StartTime).Round(time.Second)
	sep := border.Render(" │ ")

	items := []string{
		hb,
		muted.Render("RATE:") + " " + lps.Render(fmtLarge(int64(s.Metrics.LinesPerSecond))+"/s"),
		muted.Render("PROC:") + " " + green.Render(fmtLarge(s.Metrics.TotalLinesProcessed)),
		muted.Render("HITS:") + " " + mal.Render(fmtLarge(s.Metrics.MaliciousLines)),
		muted.Render("ALRT:") + " " + alrt.Render(fmtLarge(s.Metrics.TotalAlerts)),
		muted.Render("DROP:") + " " + amber.Render(fmtLarge(s.Dropped)),
		muted.Render("MEM:") + " " + mem.Render(fmt.Sprintf("%.0fM", s.Metrics.MemoryUsageMB)),
		muted.Render("UP:") + " " + green.Render(fmtUptime(uptime)),
	}

	line := ""
	for i, item := range items {
		if i > 0 {
			line += sep
		}
		line += item
	}

	return lipgloss.NewStyle().
		Width(s.Width).
		Padding(0, 1).
		Background(lipgloss.Color("#111614")).
		Render(line)
}

func (s *Status) heartbeat(active, dim, warn, crit lipgloss.Style) string {
	elapsed := time.Since(s.lastUpdate)
	var icon string
	var style lipgloss.Style

	switch {
	case elapsed < 200*time.Millisecond:
		icon, style = "●", active.Bold(true)
	case elapsed < 500*time.Millisecond:
		icon, style = "●", dim
	case elapsed < 2*time.Second:
		icon, style = "○", warn
	default:
		icon, style = "○", crit
	}

	return lipgloss.NewStyle().Foreground(lipgloss.Color("#82908a")).Render("SYS") + " " + style.Render(icon)
}

func fmtLarge(n int64) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

func fmtUptime(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm", h, m)
	}
	return fmt.Sprintf("%dm%02ds", m, s)
}
