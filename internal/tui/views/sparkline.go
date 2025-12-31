package views

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	sparkColorPrimary = lipgloss.Color("#00ff41")
	sparkColorAmber   = lipgloss.Color("#ffb000")
	sparkColorRed     = lipgloss.Color("#ff3333")
	sparkColorDim     = lipgloss.Color("#404040")
	sparkColorGhost   = lipgloss.Color("#252525")
)

var signalChars = []rune{'⎽', '⎼', '─', '⎻', '⎺'}

var barChars = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

type Throughput struct {
	Data        []float64
	Width       int
	maxSeen     float64
	OscilloMode bool
}

func NewThroughput(width int, _ string) *Throughput {
	if width <= 0 {
		width = 60
	}
	return &Throughput{
		Data:        make([]float64, width),
		Width:       width,
		OscilloMode: true,
	}
}

func (t *Throughput) Update(value float64) {
	t.Data = append(t.Data[1:], value)
}

func (t *Throughput) SetWidth(width int) {
	if width <= 0 || width == t.Width {
		return
	}
	old := t.Data
	t.Width = width
	t.Data = make([]float64, width)
	if len(old) > 0 {
		start := 0
		if len(old) > width {
			start = len(old) - width
		}
		copy(t.Data[width-len(old[start:]):], old[start:])
	}
}

func (t *Throughput) Render() string {
	if t.OscilloMode {
		return t.renderOscilloscope()
	}
	return t.renderBars()
}

func (t *Throughput) renderOscilloscope() string {
	green := lipgloss.NewStyle().Foreground(sparkColorPrimary)
	amber := lipgloss.NewStyle().Foreground(sparkColorAmber)
	red := lipgloss.NewStyle().Foreground(sparkColorRed)
	dim := lipgloss.NewStyle().Foreground(sparkColorDim)
	ghost := lipgloss.NewStyle().Foreground(sparkColorGhost)

	var current, maxVal float64
	for _, v := range t.Data {
		if v > maxVal {
			maxVal = v
		}
	}
	if len(t.Data) > 0 {
		current = t.Data[len(t.Data)-1]
	}
	if maxVal > t.maxSeen {
		t.maxSeen = maxVal
	}

	color := green
	if current > 80000 {
		color = red
	} else if current > 40000 {
		color = amber
	}

	data := t.Data
	if len(data) > t.Width {
		data = data[len(data)-t.Width:]
	}
	if maxVal < 100 {
		maxVal = 100
	}

	var trace strings.Builder
	trace.WriteString(" ")

	for i, v := range data {
		if i > 0 && i%10 == 0 {
			trace.WriteString(ghost.Render("│"))
			continue
		}
		level := 0
		if maxVal > 0 && v > 0 {
			level = int(v / maxVal * float64(len(signalChars)-1))
		}
		if level >= len(signalChars) {
			level = len(signalChars) - 1
		}

		if v == 0 {
			trace.WriteString(dim.Render(string(signalChars[0])))
		} else {
			trace.WriteString(color.Render(string(signalChars[level])))
		}
	}

	valueStr := fmt.Sprintf(" ▶ %.0f/s", current)
	if current >= 1000000 {
		valueStr = fmt.Sprintf(" ▶ %.1fM/s", current/1000000)
	} else if current >= 1000 {
		valueStr = fmt.Sprintf(" ▶ %.1fK/s", current/1000)
	}
	trace.WriteString(color.Bold(true).Render(valueStr))

	return trace.String()
}

func (t *Throughput) renderBars() string {
	green := lipgloss.NewStyle().Foreground(sparkColorPrimary)
	amber := lipgloss.NewStyle().Foreground(sparkColorAmber)
	red := lipgloss.NewStyle().Foreground(sparkColorRed)
	dim := lipgloss.NewStyle().Foreground(sparkColorDim)

	var current, maxVal float64
	for _, v := range t.Data {
		if v > maxVal {
			maxVal = v
		}
	}
	if len(t.Data) > 0 {
		current = t.Data[len(t.Data)-1]
	}
	if maxVal > t.maxSeen {
		t.maxSeen = maxVal
	}

	color := green
	if current > 50000 {
		color = red
	} else if current > 10000 {
		color = amber
	}

	data := t.Data
	if len(data) > t.Width {
		data = data[len(data)-t.Width:]
	}
	if maxVal < 100 {
		maxVal = 100
	}

	var bar strings.Builder
	bar.WriteString(" ")
	for _, v := range data {
		idx := 0
		if maxVal > 0 && v > 0 {
			idx = int(v / maxVal * float64(len(barChars)-1))
		}
		if idx >= len(barChars) {
			idx = len(barChars) - 1
		}
		if v == 0 {
			bar.WriteString(dim.Render(string(barChars[0])))
		} else {
			bar.WriteString(color.Render(string(barChars[idx])))
		}
	}

	return bar.String()
}
