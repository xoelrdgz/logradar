package tui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/internal/tui/views"
)

const (
	maxAlertsPerTick = 50
	uiTickInterval   = 100 * time.Millisecond
)

type App struct {
	model      *Model
	throughput *views.Throughput
	alerts     *views.AlertList
	topIPs     *views.TopIPs
	status     *views.Status
	inspector  *views.PayloadInspector

	ready    bool
	quitting bool
	width    int
	height   int

	alertBuffer    []*domain.Alert
	alertBufferMu  sync.Mutex
	droppedAlerts  int64
	maxAlertBuffer int

	metricsChan chan domain.MetricsSnapshot
	lastMetrics domain.MetricsSnapshot

	logSource string
	startTime time.Time
}

func NewApp() *App {
	return &App{
		model:          NewModel(),
		throughput:     views.NewThroughput(80, ""),
		alerts:         views.NewAlertList(100, 15),
		topIPs:         views.NewTopIPs(100),
		status:         views.NewStatus(100),
		inspector:      views.NewPayloadInspector(),
		alertBuffer:    make([]*domain.Alert, 0, 100),
		maxAlertBuffer: 500,
		metricsChan:    make(chan domain.MetricsSnapshot, 10),
		logSource:      "DEMO",
		startTime:      time.Now(),
	}
}

func (a *App) SetLogSource(source string) { a.logSource = source }

type tickMsg time.Time
type metricsMsg domain.MetricsSnapshot

func (a *App) Init() tea.Cmd {
	return tea.Batch(tea.EnterAltScreen, a.tick(), a.listenForMetrics())
}

func (a *App) tick() tea.Cmd {
	return tea.Tick(uiTickInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (a *App) listenForMetrics() tea.Cmd {
	return func() tea.Msg { return metricsMsg(<-a.metricsChan) }
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if a.inspector.Visible {
			switch msg.String() {
			case "esc", "q":
				a.inspector.Close()
				return a, nil
			case "up", "k":
				a.inspector.ScrollUp()
			case "down", "j":
				a.inspector.ScrollDown()
			}
			return a, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			a.quitting = true
			return a, tea.Quit
		case "tab":
			a.model.NextView()
		case "up", "k":
			a.alerts.ScrollUp()
		case "down", "j":
			a.alerts.ScrollDown()
		case "enter":
			if selected := a.alerts.GetSelected(); selected != nil {
				a.inspector.SetAlert(selected)
			}
		}
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		a.ready = true
		a.model.SetDimensions(msg.Width, msg.Height)
		a.alerts.Width = msg.Width - 4
		a.topIPs.Width = msg.Width - 4
		a.status.Width = msg.Width
		a.throughput.SetWidth(msg.Width - 4)

		contentHeight := msg.Height - 12
		if contentHeight < 5 {
			contentHeight = 5
		}
		a.alerts.VisibleCount = contentHeight
		a.topIPs.VisibleCount = contentHeight
		a.topIPs.Height = contentHeight

		a.inspector.SetDimensions(msg.Width-4, msg.Height-2)
	case tickMsg:
		a.processBatchedAlerts()
		return a, a.tick()
	case metricsMsg:
		a.lastMetrics = domain.MetricsSnapshot(msg)
		a.model.UpdateMetrics(a.lastMetrics)
		a.throughput.Update(a.lastMetrics.LinesPerSecond)
		a.status.Update(a.lastMetrics)
		return a, a.listenForMetrics()
	}
	return a, nil
}

func (a *App) processBatchedAlerts() {
	a.topIPs.Update(convertIPEntries(a.model.GetTopIPs()))

	a.alertBufferMu.Lock()
	defer a.alertBufferMu.Unlock()
	if len(a.alertBuffer) == 0 {
		return
	}
	count := len(a.alertBuffer)
	if count > maxAlertsPerTick {
		count = maxAlertsPerTick
	}
	for i := 0; i < count; i++ {
		a.model.AddAlert(a.alertBuffer[i])
	}
	a.alertBuffer = a.alertBuffer[count:]
	a.alerts.Update(a.model.GetAlerts())
}

func convertIPEntries(entries []*IPEntry) []*views.IPEntry {
	result := make([]*views.IPEntry, len(entries))
	for i, e := range entries {
		result[i] = &views.IPEntry{IP: e.IP, AlertCount: e.AlertCount, LastSeen: e.LastSeen, ThreatTypes: e.ThreatTypes}
	}
	return result
}

func (a *App) View() string {
	if a.quitting {
		return "\n  Session terminated.\n\n"
	}
	if !a.ready {
		return "\n  Initializing...\n\n"
	}

	if a.inspector.Visible {
		return a.inspector.Render()
	}

	dim := lipgloss.NewStyle().Foreground(ColorDim)
	muted := lipgloss.NewStyle().Foreground(ColorMuted)

	var b strings.Builder

	b.WriteString(a.renderHeader())
	b.WriteString("\n")
	b.WriteString(dim.Render(strings.Repeat("─", a.width)))
	b.WriteString("\n")

	b.WriteString(a.throughput.Render())
	b.WriteString("\n\n")

	viewName := "ALERTS"
	content := a.alerts.Render()
	if a.model.ActiveView == 1 {
		viewName = "TOP IPs"
		content = a.topIPs.Render()
	}
	b.WriteString(muted.Render("  " + viewName))
	b.WriteString("\n")
	b.WriteString(content)

	b.WriteString("\n\n")
	b.WriteString(a.status.Render())
	b.WriteString("\n")
	b.WriteString(a.renderHelp())

	return b.String()
}

func (a *App) renderHeader() string {
	green := lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true)
	red := lipgloss.NewStyle().Foreground(ColorCritical)
	dim := lipgloss.NewStyle().Foreground(ColorDim)

	title := green.Render("LOGRADAR")

	status := green.Render("SCANNING")
	if a.lastMetrics.MaliciousLines > 0 {
		status = red.Render("ACTIVE THREATS")
	}

	return fmt.Sprintf("  %s  %s  %s %s",
		title, status,
		dim.Render("SRC:"), a.logSource)
}

func (a *App) renderHelp() string {
	dim := lipgloss.NewStyle().Foreground(ColorDim)
	key := lipgloss.NewStyle().Foreground(ColorPrimaryDim)
	views := []string{"ALERTS", "IPs"}
	return dim.Render(fmt.Sprintf("  %s [%s]  %s scroll  %s inspect  %s quit",
		key.Render("TAB"), views[a.model.ActiveView], key.Render("↑↓"), key.Render("ENTER"), key.Render("q")))
}

func (a *App) SendAlert(alert *domain.Alert) {
	a.model.IncrementIPCounter(alert)

	a.alertBufferMu.Lock()
	defer a.alertBufferMu.Unlock()
	if len(a.alertBuffer) >= a.maxAlertBuffer {
		a.droppedAlerts++
		a.alertBuffer = a.alertBuffer[a.maxAlertBuffer/10:]
	}
	a.alertBuffer = append(a.alertBuffer, alert)
}

func (a *App) SendMetrics(metrics domain.MetricsSnapshot) {
	select {
	case a.metricsChan <- metrics:
	default:
	}
}

func (a *App) OnAlert(alert *domain.Alert) { a.SendAlert(alert) }
func (a *App) GetModel() *Model            { return a.model }
func (a *App) DroppedAlerts() int64 {
	a.alertBufferMu.Lock()
	defer a.alertBufferMu.Unlock()
	return a.droppedAlerts
}
func (a *App) Run() error { p := tea.NewProgram(a, tea.WithAltScreen()); _, err := p.Run(); return err }
