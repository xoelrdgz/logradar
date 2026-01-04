// Package sanitize provides input sanitization functions for secure display.
//
// These functions remove or replace potentially dangerous characters before
// displaying log data in terminal UIs or JSON output, preventing:
//   - Terminal escape sequence injection
//   - Log injection attacks
//   - XSS in downstream systems consuming JSON output
//
// Security Considerations:
//   - ANSI escape sequences are replaced with [ESC]
//   - Control characters are replaced with [CTRL], [CR], [DEL]
//   - All functions truncate to prevent DoS via long inputs
//
// Thread Safety: All functions are stateless and safe for concurrent use.
package sanitize

import (
	"strings"
	"unicode"
)

// DefaultMaxDisplayLength is the default maximum length for sanitized strings.
const DefaultMaxDisplayLength = 256

// String sanitizes a string for terminal display with length limit.
//
// Parameters:
//   - s: Input string to sanitize
//   - maxLen: Maximum output length (0 for no limit)
//
// Returns:
//   - Sanitized string with control chars replaced and length limited
//
// Processing:
//  1. Remove/replace terminal escape sequences and control chars
//  2. Truncate to maxLen with "..." suffix if needed
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

// SanitizeForTerminal removes all terminal escape sequences and control characters.
//
// Parameters:
//   - s: Input string to sanitize
//
// Returns:
//   - String safe for terminal display
//
// Replacements:
//   - ESC sequences -> [ESC]
//   - Tab (\t) -> space
//   - Newline (\n) -> space
//   - Carriage return (\r) -> [CR]
//   - Other control chars -> [CTRL]
//   - DEL (0x7F) -> [DEL]
//
// Security Note: Prevents terminal escape injection attacks where malicious
// log data could manipulate terminal state or inject fake output.
func SanitizeForTerminal(s string) string {
	if s == "" {
		return s
	}

	// Fast path: check if sanitization is needed
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

		// Handle ANSI escape sequences: ESC[...X
		if c == 0x1B && i+1 < len(s) {
			i++
			if i < len(s) && s[i] == '[' {
				i++
				// Skip CSI parameters until terminator
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

		// Handle other control characters
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

// isCSITerminator checks if a byte terminates a CSI escape sequence.
func isCSITerminator(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '@' || c == '`'
}

// SanitizeJSON sanitizes a string for safe JSON output.
//
// Parameters:
//   - s: Input string to sanitize
//   - maxLen: Maximum output length (default: 256 if <= 0)
//
// Returns:
//   - String safe for JSON embedding with control chars removed
//
// Note: Only removes non-printable chars. JSON encoding handles escaping.
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

// SanitizeIP sanitizes an IP address string.
//
// Parameters:
//   - ip: IP address string
//
// Returns:
//   - Sanitized IP with only valid characters (digits, dots, colons, hex)
//   - "[INVALID]" if result is empty
//
// Allowed Characters: 0-9, a-f, A-F, ., :
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

// SanitizePath sanitizes a URL path for display.
//
// Parameters:
//   - path: URL path to sanitize
//   - maxLen: Maximum output length
//
// Returns:
//   - Sanitized path safe for terminal display
func SanitizePath(path string, maxLen int) string {
	return String(path, maxLen)
}

// SanitizeUserAgent sanitizes a User-Agent string for display.
//
// Parameters:
//   - ua: User-Agent header value
//   - maxLen: Maximum output length
//
// Returns:
//   - Sanitized User-Agent safe for terminal display
func SanitizeUserAgent(ua string, maxLen int) string {
	return String(ua, maxLen)
}
