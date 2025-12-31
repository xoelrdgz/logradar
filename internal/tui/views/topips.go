package views

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/xoelrdgz/logradar/pkg/sanitize"
)

type IPEntry struct {
	IP          string
	AlertCount  int
	LastSeen    string
	ThreatTypes []string
}

type TopIPs struct {
	IPs          []*IPEntry
	Width        int
	Height       int
	VisibleCount int
	ScrollPos    int
}

func NewTopIPs(width int) *TopIPs {
	return &TopIPs{IPs: make([]*IPEntry, 0), Width: width, VisibleCount: 25}
}

func (v *TopIPs) Update(ips []*IPEntry) { v.IPs = ips }

func (v *TopIPs) Render() string {
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff41"))
	greenDim := lipgloss.NewStyle().Foreground(lipgloss.Color("#00aa2a"))
	amber := lipgloss.NewStyle().Foreground(lipgloss.Color("#ffb000"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("#ff3333"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#404040"))
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("#707070"))
	text := lipgloss.NewStyle().Foreground(lipgloss.Color("#e5e5e5"))

	if len(v.IPs) == 0 {
		return dim.Italic(true).Render("  No threats detected")
	}

	var lines []string
	lines = append(lines, muted.Bold(true).Render(fmt.Sprintf(" %-3s %-17s %-12s %-10s %s",
		"#", "IP", "HITS", "LAST", "TYPES")))
	lines = append(lines, dim.Render(strings.Repeat("─", v.Width)))

	maxAlerts := 0
	for _, ip := range v.IPs {
		if ip.AlertCount > maxAlerts {
			maxAlerts = ip.AlertCount
		}
	}

	visibleIPs := v.IPs
	if len(visibleIPs) > v.VisibleCount {
		visibleIPs = visibleIPs[:v.VisibleCount]
	}

	for i, ip := range visibleIPs {
		idx := muted.Render(fmt.Sprintf("%2d.", i+1))

		ipStr := sanitize.SanitizeIP(ip.IP)
		if len(ipStr) > 17 {
			ipStr = ipStr[:14] + "..."
		}
		ipStyle := greenDim
		if ip.AlertCount > 20 || (maxAlerts > 0 && float64(ip.AlertCount)/float64(maxAlerts) > 0.7) {
			ipStyle = red.Bold(true)
		} else if ip.AlertCount > 10 || (maxAlerts > 0 && float64(ip.AlertCount)/float64(maxAlerts) > 0.4) {
			ipStyle = amber.Bold(true)
		} else if ip.AlertCount > 5 {
			ipStyle = green
		}

		barWidth := 6
		fillWidth := 0
		if maxAlerts > 0 {
			fillWidth = int(float64(ip.AlertCount) / float64(maxAlerts) * float64(barWidth))
		}
		if fillWidth > barWidth {
			fillWidth = barWidth
		}
		bar := strings.Repeat("█", fillWidth) + strings.Repeat("░", barWidth-fillWidth)
		hitsStr := fmtLarge(int64(ip.AlertCount))
		hits := ipStyle.Render(fmt.Sprintf("%s %5s", bar, hitsStr))

		last := muted.Render(padRight(ip.LastSeen, 10))

		var types []string
		for _, t := range ip.ThreatTypes {
			types = append(types, sanitize.SanitizeForTerminal(t))
		}
		typesStr := strings.Join(types, ", ")
		maxLen := v.Width - 50
		if maxLen < 10 {
			maxLen = 10
		}
		if len(typesStr) > maxLen {
			typesStr = typesStr[:maxLen-3] + "..."
		}

		lines = append(lines, fmt.Sprintf(" %s %s %s %s %s",
			idx,
			ipStyle.Render(padRight(ipStr, 17)),
			hits,
			last,
			text.Render(typesStr),
		))
	}

	contentLines := len(lines)
	targetLines := v.VisibleCount + 2
	for i := contentLines; i < targetLines; i++ {
		lines = append(lines, "")
	}

	if len(v.IPs) > v.VisibleCount {
		lines = append(lines, dim.Render(fmt.Sprintf("  [showing %d of %d IPs]", v.VisibleCount, len(v.IPs))))
	}

	return strings.Join(lines, "\n")
}

func (v *TopIPs) GetMaxAlertCount() int {
	if len(v.IPs) == 0 {
		return 0
	}
	return v.IPs[0].AlertCount
}

func padRight(s string, length int) string {
	if len(s) >= length {
		return s[:length]
	}
	return s + strings.Repeat(" ", length-len(s))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
