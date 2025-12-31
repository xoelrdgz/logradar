package tui

import "github.com/charmbracelet/lipgloss"

var (
	ColorBg         = lipgloss.Color("#0a0a0a")
	ColorBgAlt      = lipgloss.Color("#0f0f0f")
	ColorBorder     = lipgloss.Color("#1a3a1a")
	ColorBorderHi   = lipgloss.Color("#00ff41")
	ColorPrimary    = lipgloss.Color("#00ff41")
	ColorPrimaryDim = lipgloss.Color("#00aa2a")
	ColorPrimaryBg  = lipgloss.Color("#0a1f0a")
	ColorAmber      = lipgloss.Color("#ffb000")
	ColorAmberDim   = lipgloss.Color("#997000")
	ColorRed        = lipgloss.Color("#ff3333")
	ColorRedDim     = lipgloss.Color("#992020")
	ColorCyan       = lipgloss.Color("#00b8ff")
	ColorCritical   = ColorRed
	ColorWarning    = ColorAmber
	ColorInfo       = ColorCyan
	ColorText       = lipgloss.Color("#e5e5e5")
	ColorMuted      = lipgloss.Color("#707070")
	ColorDim        = lipgloss.Color("#404040")
	ColorGhost      = lipgloss.Color("#252525")
	ColorSelect     = lipgloss.Color("#003300")
	ColorSelectFg   = lipgloss.Color("#00ff41")
)

var (
	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(ColorBorder).
			Padding(0, 1)

	BoxActiveStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(ColorPrimary).
			Padding(0, 1)
	BoxCriticalStyle = lipgloss.NewStyle().
				Border(lipgloss.DoubleBorder()).
				BorderForeground(ColorRed).
				Padding(0, 1)

	HeaderStyle = lipgloss.NewStyle().
			Background(ColorPrimaryBg).
			Foreground(ColorPrimary).
			Bold(true).
			Padding(0, 1)

	StatusBarStyle = lipgloss.NewStyle().
			Background(ColorBgAlt).
			Foreground(ColorMuted).
			Padding(0, 1)
)

var (
	TextPrimary  = lipgloss.NewStyle().Foreground(ColorPrimary)
	TextAmber    = lipgloss.NewStyle().Foreground(ColorAmber)
	TextRed      = lipgloss.NewStyle().Foreground(ColorRed)
	TextCyan     = lipgloss.NewStyle().Foreground(ColorCyan)
	TextMuted    = lipgloss.NewStyle().Foreground(ColorMuted)
	TextDim      = lipgloss.NewStyle().Foreground(ColorDim)
	TextBold     = lipgloss.NewStyle().Foreground(ColorText).Bold(true)
	TextSelected = lipgloss.NewStyle().
			Background(ColorSelect).
			Foreground(ColorSelectFg).
			Bold(true)
)

var (
	LevelCritical = lipgloss.NewStyle().
			Foreground(ColorRed).
			Bold(true)
	LevelWarning = lipgloss.NewStyle().
			Foreground(ColorAmber).
			Bold(true)
	LevelInfo = lipgloss.NewStyle().
			Foreground(ColorCyan)
)

var (
	OscilloChars = []rune{'⎽', '⎼', '─', '⎻', '⎺'}
	DotChars     = []rune{'·', '•', '○', '◉', '●'}
	BarChars     = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	WaveChars    = []rune{'⎽', '╲', '│', '╱', '⎺'}
)

const (
	HLine    = "─"
	VLine    = "│"
	TeeRight = "├"
	TeeLeft  = "┤"
	Cross    = "┼"
	Corner   = "└"
)

var LogoSmall = TextPrimary.Render(`▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
█  ╦  ╔═╗╔═╗╦═╗╔═╗╔╦╗╔═╗╦═╗  │ THREAT  █
█  ║  ║ ║║ ╦╠╦╝╠═╣ ║║╠═╣╠╦╝  │ MONITOR █
█  ╩═╝╚═╝╚═╝╩╚═╩ ╩═╩╝╩ ╩╩╚═  │ v1.0    █
▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀`)

func ForLevel(level string) lipgloss.Style {
	switch level {
	case "critical", "CRT":
		return LevelCritical
	case "warning", "WRN":
		return LevelWarning
	default:
		return LevelInfo
	}
}
