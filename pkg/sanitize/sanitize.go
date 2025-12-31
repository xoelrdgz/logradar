package sanitize

import (
	"strings"
	"unicode"
)

const DefaultMaxDisplayLength = 256

func String(s string, maxLen int) string {
	sanitized := SanitizeForTerminal(s)

	if maxLen > 0 && len(sanitized) > maxLen {
		if maxLen > 3 {
			return sanitized[:maxLen-3] + "..."
		}
		return sanitized[:maxLen]
	}
	return sanitized
}

func SanitizeForTerminal(s string) string {
	if s == "" {
		return s
	}

	needsSanitization := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F || c == 0x1B {
			needsSanitization = true
			break
		}
	}

	if !needsSanitization {
		return s
	}

	var result strings.Builder
	result.Grow(len(s))

	i := 0
	for i < len(s) {
		c := s[i]

		if c == 0x1B && i+1 < len(s) {
			i++
			if i < len(s) && s[i] == '[' {
				i++
				for i < len(s) && !isCSITerminator(s[i]) {
					i++
				}
				if i < len(s) {
					i++
				}
			}
			result.WriteString("[ESC]")
			continue
		}

		switch {
		case c == '\t':
			result.WriteByte(' ')
		case c == '\n':
			result.WriteByte(' ')
		case c == '\r':
			result.WriteString("[CR]")
		case c < 0x20:
			result.WriteString("[CTRL]")
		case c == 0x7F:
			result.WriteString("[DEL]")
		default:
			result.WriteByte(c)
		}
		i++
	}

	return result.String()
}

func isCSITerminator(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '@' || c == '`'
}

func SanitizeJSON(s string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = DefaultMaxDisplayLength
	}

	var result strings.Builder
	result.Grow(min(len(s), maxLen))

	count := 0
	for _, r := range s {
		if count >= maxLen-3 {
			result.WriteString("...")
			break
		}
		if r >= 0x20 && r != 0x7F {
			result.WriteRune(r)
			count++
		} else if r == '\t' || r == '\n' {
			result.WriteByte(' ')
			count++
		}
	}

	return result.String()
}

func SanitizeIP(ip string) string {
	var result strings.Builder
	result.Grow(len(ip))

	for _, r := range ip {
		if unicode.IsDigit(r) || r == '.' || r == ':' ||
			(r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			result.WriteRune(r)
		}
	}

	sanitized := result.String()
	if sanitized == "" {
		return "[INVALID]"
	}
	return sanitized
}

func SanitizePath(path string, maxLen int) string {
	return String(path, maxLen)
}

func SanitizeUserAgent(ua string, maxLen int) string {
	return String(ua, maxLen)
}
