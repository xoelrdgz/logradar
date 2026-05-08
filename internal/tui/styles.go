package tui

import "github.com/charmbracelet/lipgloss"

var (
	ColorBg         = lipgloss.Color("#0b0e0d")
	ColorBgAlt      = lipgloss.Color("#111614")
	ColorBorder     = lipgloss.Color("#26322d")
	ColorBorderHi   = lipgloss.Color("#8df7b2")
	ColorPrimary    = lipgloss.Color("#8df7b2")
	ColorPrimaryDim = lipgloss.Color("#4da873")
	ColorPrimaryBg  = lipgloss.Color("#14251d")
	ColorAmber      = lipgloss.Color("#f2c36b")
	ColorAmberDim   = lipgloss.Color("#8d6e38")
	ColorRed        = lipgloss.Color("#ff6b5f")
	ColorRedDim     = lipgloss.Color("#9f4039")
	ColorCyan       = lipgloss.Color("#76c7e8")
	ColorCritical   = ColorRed
	ColorWarning    = ColorAmber
	ColorInfo       = ColorCyan
	ColorText       = lipgloss.Color("#dbe6df")
	ColorMuted      = lipgloss.Color("#82908a")
	ColorDim        = lipgloss.Color("#46524d")
	ColorGhost      = lipgloss.Color("#202724")
	ColorSelect     = lipgloss.Color("#1e382b")
	ColorSelectFg   = lipgloss.Color("#d5ffe3")
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
