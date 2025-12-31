package sanitize

import (
	"testing"
)

func TestSanitizeForTerminal(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean string",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "ANSI escape sequence",
			input:    "\x1b[31mRed Text\x1b[0m",
			expected: "[ESC]Red Text[ESC]",
		},
		{
			name:     "tab character",
			input:    "Hello\tWorld",
			expected: "Hello World",
		},
		{
			name:     "newline character",
			input:    "Hello\nWorld",
			expected: "Hello World",
		},
		{
			name:     "carriage return",
			input:    "Hello\rWorld",
			expected: "Hello[CR]World",
		},
		{
			name:     "control character",
			input:    "Hello\x01World",
			expected: "Hello[CTRL]World",
		},
		{
			name:     "delete character",
			input:    "Hello\x7FWorld",
			expected: "Hello[DEL]World",
		},
		{
			name:     "complex attack payload",
			input:    "\x1b[2J\x1b[H\x1b[31mPWNED\x1b[0m",
			expected: "[ESC][ESC][ESC]PWNED[ESC]",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := SanitizeForTerminal(tc.input)
			if result != tc.expected {
				t.Errorf("SanitizeForTerminal(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "within limit",
			input:    "Hello World",
			maxLen:   20,
			expected: "Hello World",
		},
		{
			name:     "exceeds limit",
			input:    "This is a very long string that exceeds the limit",
			maxLen:   20,
			expected: "This is a very lo...",
		},
		{
			name:     "no limit",
			input:    "Hello World",
			maxLen:   0,
			expected: "Hello World",
		},
		{
			name:     "sanitize and truncate",
			input:    "\x1b[31mThis is malicious text\x1b[0m",
			maxLen:   20,
			expected: "[ESC]This is mali...",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := String(tc.input, tc.maxLen)
			if result != tc.expected {
				t.Errorf("String(%q, %d) = %q, want %q", tc.input, tc.maxLen, result, tc.expected)
			}
		})
	}
}

func TestSanitizeJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "clean string",
			input:    "Normal log message",
			maxLen:   100,
			expected: "Normal log message",
		},
		{
			name:     "control characters stripped silently",
			input:    "Hello\x00\x01\x02World",
			maxLen:   100,
			expected: "HelloWorld",
		},
		{
			name:     "ANSI sequences stripped",
			input:    "\x1b[31mRed\x1b[0m",
			maxLen:   100,
			expected: "[31mRed[0m",
		},
		{
			name:     "length limited",
			input:    "This is a long message that should be truncated",
			maxLen:   20,
			expected: "This is a long me...",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := SanitizeJSON(tc.input, tc.maxLen)
			if result != tc.expected {
				t.Errorf("SanitizeJSON(%q, %d) = %q, want %q", tc.input, tc.maxLen, result, tc.expected)
			}
		})
	}
}

func TestSanitizeIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid IPv4",
			input:    "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "valid IPv6",
			input:    "2001:db8::1",
			expected: "2001:db8::1",
		},
		{
			name:     "IP with trailing garbage",
			input:    "192.168.1.1<img>",
			expected: "192.168.1.1",
		},
		{
			name:     "only invalid characters",
			input:    "<img>|!@#$%^&*()",
			expected: "[INVALID]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := SanitizeIP(tc.input)
			if result != tc.expected {
				t.Errorf("SanitizeIP(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func BenchmarkSanitizeForTerminal(b *testing.B) {
	input := "Normal text without any control characters that needs no sanitization"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SanitizeForTerminal(input)
	}
}

func BenchmarkSanitizeForTerminal_WithEscape(b *testing.B) {
	input := "\x1b[31mMalicious \x1b[2J text\x1b[0m with control characters"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SanitizeForTerminal(input)
	}
}
