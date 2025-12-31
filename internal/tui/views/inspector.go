package views

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/pkg/sanitize"
)

var (
	inspColorPrimary = lipgloss.Color("#00ff41")
	inspColorAmber   = lipgloss.Color("#ffb000")
	inspColorRed     = lipgloss.Color("#ff3333")
	inspColorCyan    = lipgloss.Color("#00b8ff")
	inspColorText    = lipgloss.Color("#e5e5e5")
	inspColorDim     = lipgloss.Color("#404040")
	inspColorBorder  = lipgloss.Color("#00ff41")
	inspColorBg      = lipgloss.Color("#0a1f0a")
)

func forLevel(level string) lipgloss.Style {
	switch level {
	case "critical", "CRT":
		return lipgloss.NewStyle().Foreground(inspColorRed).Bold(true)
	case "warning", "WRN":
		return lipgloss.NewStyle().Foreground(inspColorAmber).Bold(true)
	default:
		return lipgloss.NewStyle().Foreground(inspColorCyan)
	}
}

type PayloadInspector struct {
	Alert   *domain.Alert
	Width   int
	Height  int
	ScrollY int
	Visible bool
}

func NewPayloadInspector() *PayloadInspector {
	return &PayloadInspector{
		Width:  80,
		Height: 24,
	}
}

func (p *PayloadInspector) SetAlert(alert *domain.Alert) {
	p.Alert = alert
	p.ScrollY = 0
	p.Visible = alert != nil
}

func (p *PayloadInspector) SetDimensions(width, height int) {
	p.Width = width
	p.Height = height
}

func (p *PayloadInspector) ScrollUp() {
	if p.ScrollY > 0 {
		p.ScrollY--
	}
}

func (p *PayloadInspector) ScrollDown() {
	p.ScrollY++
}

func (p *PayloadInspector) Close() {
	p.Alert = nil
	p.Visible = false
}

func (p *PayloadInspector) Render() string {
	if p.Alert == nil {
		return ""
	}

	al := p.Alert
	contentWidth := p.Width - 4

	header := lipgloss.NewStyle().
		Foreground(inspColorPrimary).
		Bold(true)
	label := lipgloss.NewStyle().
		Foreground(inspColorAmber).
		Width(12)
	value := lipgloss.NewStyle().
		Foreground(inspColorText)
	dimText := lipgloss.NewStyle().
		Foreground(inspColorDim)
	codeBlock := lipgloss.NewStyle().
		Foreground(inspColorPrimary).
		Background(inspColorBg)
	critical := lipgloss.NewStyle().
		Foreground(inspColorRed).
		Bold(true)

	var lines []string

	title := "╔═══ PAYLOAD INSPECTOR ═══╗"
	lines = append(lines, header.Render(title))
	lines = append(lines, dimText.Render(strings.Repeat("─", contentWidth)))

	lines = append(lines, header.Render("▶ ALERT DETAILS"))
	lines = append(lines, fmt.Sprintf("%s %s",
		label.Render("Timestamp:"),
		value.Render(al.Timestamp.Format("2006-01-02 15:04:05.000"))))
	lines = append(lines, fmt.Sprintf("%s %s",
		label.Render("Source IP:"),
		critical.Render(al.SourceIP.String())))
	lines = append(lines, fmt.Sprintf("%s %s",
		label.Render("Threat:"),
		value.Render(string(al.ThreatType))))
	lines = append(lines, fmt.Sprintf("%s %s",
		label.Render("Level:"),
		forLevel(string(al.Level)).Render(string(al.Level))))
	lines = append(lines, fmt.Sprintf("%s %d/10",
		label.Render("Risk Score:"),
		al.RiskScore))
	lines = append(lines, fmt.Sprintf("%s %s",
		label.Render("Message:"),
		value.Render(sanitize.String(al.Message, 200))))

	if len(al.Metadata) > 0 {
		lines = append(lines, "")
		lines = append(lines, dimText.Render(strings.Repeat("─", contentWidth)))
		lines = append(lines, header.Render("▶ DETECTION DETAILS"))

		detailsJSON, err := json.MarshalIndent(al.Metadata, "", "  ")
		if err == nil {
			for _, line := range strings.Split(string(detailsJSON), "\n") {
				lines = append(lines, codeBlock.Render(sanitize.String(line, contentWidth)))
			}
		}
	}

	if body := al.Metadata["body"]; body != "" {
		lines = append(lines, "")
		lines = append(lines, dimText.Render(strings.Repeat("─", contentWidth)))
		lines = append(lines, header.Render("▶ REQUEST BODY"))

		var prettyJSON map[string]interface{}
		if err := json.Unmarshal([]byte(body), &prettyJSON); err == nil {
			formatted, _ := json.MarshalIndent(prettyJSON, "", "  ")
			for _, line := range strings.Split(string(formatted), "\n") {
				lines = append(lines, codeBlock.Render(sanitize.String(line, contentWidth)))
			}
		} else {
			for i := 0; i < len(body); i += contentWidth {
				end := i + contentWidth
				if end > len(body) {
					end = len(body)
				}
				lines = append(lines, codeBlock.Render(sanitize.String(body[i:end], contentWidth)))
			}
		}
	}

	for k, v := range al.Metadata {
		if strings.HasPrefix(k, "header_") || k == "user_agent" || k == "cookie" || k == "referer" {
			headerLine := fmt.Sprintf("%s: %s", strings.TrimPrefix(k, "header_"), v)
			if strings.Contains(strings.ToLower(headerLine), "jndi") ||
				strings.Contains(headerLine, "${") ||
				strings.Contains(headerLine, "() {") {
				lines = append(lines, critical.Render("⚠ "+sanitize.String(headerLine, contentWidth-2)))
			}
		}
	}

	if path := al.Metadata["path"]; path != "" {
		lines = append(lines, "")
		lines = append(lines, dimText.Render(strings.Repeat("─", contentWidth)))
		lines = append(lines, header.Render("▶ REQUEST PATH"))
		lines = append(lines, codeBlock.Render(sanitize.String(path, contentWidth)))
	}

	if al.RawLog != "" {
		lines = append(lines, "")
		lines = append(lines, dimText.Render(strings.Repeat("─", contentWidth)))
		lines = append(lines, header.Render("▶ RAW LOG"))
		rawLines := strings.Split(al.RawLog, "\n")
		for _, line := range rawLines {
			lines = append(lines, codeBlock.Render(sanitize.String(line, contentWidth)))
		}
	}

	lines = append(lines, "")
	lines = append(lines, dimText.Render(strings.Repeat("─", contentWidth)))
	lines = append(lines, dimText.Render("[ESC] Close   [↑/↓] Scroll   [C] Copy JSON"))
	if p.ScrollY > 0 && p.ScrollY < len(lines) {
		lines = lines[p.ScrollY:]
	}
	if len(lines) > p.Height-2 {
		lines = lines[:p.Height-2]
	}

	content := strings.Join(lines, "\n")

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(inspColorBorder).
		Padding(0, 1).
		Width(p.Width).
		Height(p.Height)

	box := boxStyle.Render(content)

	return box
}
