package views

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/pkg/sanitize"
)

type AlertList struct {
	Alerts        []*domain.Alert
	MaxAlerts     int
	VisibleCount  int
	ScrollPos     int
	Width         int
	SelectedIndex int
}

func NewAlertList(maxAlerts, visibleCount int) *AlertList {
	return &AlertList{
		Alerts:        make([]*domain.Alert, 0, maxAlerts),
		MaxAlerts:     maxAlerts,
		VisibleCount:  visibleCount,
		Width:         100,
		SelectedIndex: -1,
	}
}

func (a *AlertList) Update(alerts []*domain.Alert) { a.Alerts = alerts }

func (a *AlertList) ScrollUp() {
	maxIdx := len(a.Alerts) - 1
	if a.SelectedIndex < maxIdx {
		a.SelectedIndex++
	}
	a.ensureSelectionVisible()
}

func (a *AlertList) ScrollDown() {
	if a.SelectedIndex > 0 {
		a.SelectedIndex--
	}
	a.ensureSelectionVisible()
}

func (a *AlertList) ensureSelectionVisible() {
	if len(a.Alerts) <= a.VisibleCount {
		a.ScrollPos = 0
		return
	}

	startIdx := len(a.Alerts) - a.VisibleCount - a.ScrollPos
	if startIdx < 0 {
		startIdx = 0
	}
	endIdx := startIdx + a.VisibleCount
	if endIdx > len(a.Alerts) {
		endIdx = len(a.Alerts)
	}

	if a.SelectedIndex < startIdx {
		a.ScrollPos = len(a.Alerts) - a.VisibleCount - a.SelectedIndex
	}
	if a.SelectedIndex >= endIdx {
		a.ScrollPos = len(a.Alerts) - a.VisibleCount - (a.SelectedIndex - a.VisibleCount + 1)
	}

	maxScroll := len(a.Alerts) - a.VisibleCount
	if a.ScrollPos < 0 {
		a.ScrollPos = 0
	}
	if a.ScrollPos > maxScroll {
		a.ScrollPos = maxScroll
	}
}

func (a *AlertList) GetSelected() *domain.Alert {
	if a.SelectedIndex >= 0 && a.SelectedIndex < len(a.Alerts) {
		return a.Alerts[a.SelectedIndex]
	}
	return nil
}

func (a *AlertList) SelectLast() {
	if len(a.Alerts) > 0 {
		a.SelectedIndex = len(a.Alerts) - 1
	}
}

func (a *AlertList) Render() string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#404040"))
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("#707070"))
	text := lipgloss.NewStyle().Foreground(lipgloss.Color("#e5e5e5"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff41"))
	amber := lipgloss.NewStyle().Foreground(lipgloss.Color("#ffb000"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("#ff3333"))
	cyan := lipgloss.NewStyle().Foreground(lipgloss.Color("#00b8ff"))
	selected := lipgloss.NewStyle().Background(lipgloss.Color("#003300")).Foreground(lipgloss.Color("#00ff41"))

	if len(a.Alerts) == 0 {
		return dim.Italic(true).Render("  No alerts")
	}

	if a.SelectedIndex < 0 && len(a.Alerts) > 0 {
		a.SelectedIndex = len(a.Alerts) - 1
	}

	var lines []string

	lines = append(lines, muted.Bold(true).Render(
		fmt.Sprintf("  %-8s  %-3s  %-15s  %-14s  %-3s  %s",
			"TIME", "LVL", "IP", "TYPE", "RSK", "MESSAGE")))
	lines = append(lines, dim.Render("  "+strings.Repeat("─", a.Width-4)))

	startIdx := 0
	endIdx := len(a.Alerts)
	if len(a.Alerts) > a.VisibleCount {
		startIdx = len(a.Alerts) - a.VisibleCount - a.ScrollPos
		if startIdx < 0 {
			startIdx = 0
		}
		endIdx = startIdx + a.VisibleCount
		if endIdx > len(a.Alerts) {
			endIdx = len(a.Alerts)
		}
	}

	for i := endIdx - 1; i >= startIdx; i-- {
		al := a.Alerts[i]
		isSelected := (i == a.SelectedIndex)
		prefix := "  "
		if isSelected {
			prefix = "▶ "
		}

		timeStr := dim.Render(al.Timestamp.Format("15:04:05"))
		if isSelected {
			timeStr = selected.Render(al.Timestamp.Format("15:04:05"))
		}

		var lvl string
		var lvlStyle lipgloss.Style
		switch al.Level {
		case domain.AlertLevelCritical:
			lvl, lvlStyle = "CRT", red.Bold(true)
		case domain.AlertLevelWarning:
			lvl, lvlStyle = "WRN", amber.Bold(true)
		default:
			lvl, lvlStyle = "INF", cyan
		}

		ip := sanitize.SanitizeIP(al.IPString())
		if len(ip) > 15 {
			ip = ip[:12] + "..."
		}
		ipStyle := text
		if al.Level == domain.AlertLevelCritical {
			ipStyle = red.Bold(true)
		}
		if isSelected {
			ipStyle = selected.Bold(true)
		}

		threatType := sanitize.SanitizeForTerminal(string(al.ThreatType))
		if len(threatType) > 14 {
			threatType = threatType[:11] + "..."
		}
		riskStyle := green
		if al.RiskScore >= 8 {
			riskStyle = red.Bold(true)
		} else if al.RiskScore >= 5 {
			riskStyle = amber.Bold(true)
		}

		msg := sanitize.SanitizeForTerminal(al.Message)
		maxLen := a.Width - 55
		if maxLen < 10 {
			maxLen = 10
		}
		if len(msg) > maxLen {
			msg = msg[:maxLen-3] + "..."
		}

		line := fmt.Sprintf("%s%-8s  %s  %-15s  %-14s  %s   %s",
			prefix,
			timeStr,
			lvlStyle.Render(lvl),
			ipStyle.Render(fmt.Sprintf("%-15s", ip)),
			green.Render(fmt.Sprintf("%-14s", threatType)),
			riskStyle.Render(fmt.Sprintf("%2d", al.RiskScore)),
			muted.Render(msg),
		)
		lines = append(lines, line)
	}

	if len(a.Alerts) > a.VisibleCount {
		lines = append(lines, dim.Render(fmt.Sprintf("  [%d-%d of %d]",
			a.ScrollPos+1, min(a.ScrollPos+a.VisibleCount, len(a.Alerts)), len(a.Alerts))))
	}

	return strings.Join(lines, "\n")
}
