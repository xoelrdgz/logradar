package ahocorasick

import (
	"testing"
)

func TestMatcher_Basic(t *testing.T) {
	patterns := []string{"select", "union", "script"}
	m := New(patterns)

	if m.PatternCount() != 3 {
		t.Errorf("Expected 3 patterns, got %d", m.PatternCount())
	}
}

func TestMatcher_Match(t *testing.T) {
	patterns := []string{"select", "union", "drop"}
	m := New(patterns)

	tests := []struct {
		input    string
		expected bool
	}{
		{"SELECT * FROM users", true},
		{"UNION ALL SELECT", true},
		{"DROP TABLE users", true},
		{"normal query", false},
		{"hello world", false},
		{"", false},
	}

	for _, tc := range tests {
		result := m.Match(tc.input)
		if result != tc.expected {
			t.Errorf("Match(%q) = %v, expected %v", tc.input, result, tc.expected)
		}
	}
}

func TestMatcher_CaseInsensitive(t *testing.T) {
	patterns := []string{"script", "alert"}
	m := New(patterns)

	tests := []struct {
		input string
	}{
		{"<SCRIPT>"},
		{"<Script>"},
		{"<script>"},
		{"ALERT(1)"},
		{"Alert(1)"},
		{"alert(1)"},
	}

	for _, tc := range tests {
		if !m.Match(tc.input) {
			t.Errorf("Expected case-insensitive match for %q", tc.input)
		}
	}
}

func TestMatcher_MatchAll(t *testing.T) {
	patterns := []string{"select", "from", "where"}
	m := New(patterns)

	matches := m.MatchAll("SELECT * FROM users WHERE id=1")

	if len(matches) != 3 {
		t.Errorf("Expected 3 matches, got %d", len(matches))
	}

	found := make(map[int]bool)
	for _, idx := range matches {
		found[idx] = true
	}
	if !found[0] || !found[1] || !found[2] {
		t.Errorf("Expected all patterns to match, got indices: %v", matches)
	}
}

func TestMatcher_NoMatch(t *testing.T) {
	patterns := []string{"attack", "malware"}
	m := New(patterns)

	if m.Match("hello world") {
		t.Error("Expected no match")
	}

	matches := m.MatchAll("hello world")
	if matches != nil && len(matches) > 0 {
		t.Errorf("Expected no matches, got %v", matches)
	}
}

func TestMatcher_EmptyPatterns(t *testing.T) {
	m := New([]string{})

	if m.Match("anything") {
		t.Error("Empty matcher should not match anything")
	}
	if m.PatternCount() != 0 {
		t.Errorf("Expected 0 patterns, got %d", m.PatternCount())
	}
}

func TestMatcher_NilPatterns(t *testing.T) {
	m := New(nil)

	if m.Match("test") {
		t.Error("Nil matcher should not match anything")
	}
}

func TestMatcher_OverlappingPatterns(t *testing.T) {
	patterns := []string{"script", "scr", "ipt"}
	m := New(patterns)

	matches := m.MatchAll("<script>")
	if len(matches) != 3 {
		t.Errorf("Expected 3 matches for overlapping patterns, got %d", len(matches))
	}
}

func TestMatcher_SubstringPatterns(t *testing.T) {
	patterns := []string{"or", "for", "form"}
	m := New(patterns)

	matches := m.MatchAll("form")
	if len(matches) != 3 {
		t.Errorf("Expected 3 matches (or, for, form), got %d: %v", len(matches), matches)
	}
}

func TestMatcher_SQLKeywords(t *testing.T) {
	patterns := []string{
		"union", "select", "from", "where", "drop", "delete",
		"insert", "update", "sleep", "benchmark", "1=1",
	}
	m := New(patterns)

	sqliPayloads := []string{
		"' UNION SELECT * FROM users--",
		"1; DROP TABLE users;",
		"' OR 1=1--",
		"SLEEP(5)",
		"BENCHMARK(10000000,SHA1('test'))",
	}

	for _, payload := range sqliPayloads {
		if !m.Match(payload) {
			t.Errorf("Expected SQLi detection for: %s", payload)
		}
	}

	cleanInputs := []string{
		"/api/products",
		"/users/profile",
		"Hello World",
	}

	for _, input := range cleanInputs {
		if m.Match(input) {
			t.Errorf("False positive for clean input: %s", input)
		}
	}
}

func TestMatcher_XSSKeywords(t *testing.T) {
	patterns := []string{
		"script", "javascript", "onerror", "onload", "alert", "eval",
	}
	m := New(patterns)

	xssPayloads := []string{
		"<script>alert(1)</script>",
		"<img onerror=alert(1)>",
		"javascript:alert(1)",
		"<svg onload=eval(atob('..'))>",
	}

	for _, payload := range xssPayloads {
		if !m.Match(payload) {
			t.Errorf("Expected XSS detection for: %s", payload)
		}
	}
}

func TestMatcher_Unicode(t *testing.T) {
	patterns := []string{"script", "alert"}
	m := New(patterns)

	if !m.Match("SCRIPT") {
		t.Error("Expected match for ASCII SCRIPT")
	}
	if !m.Match("Script") {
		t.Error("Expected match for mixed case Script")
	}
}

func BenchmarkMatcher_Match(b *testing.B) {
	patterns := []string{
		"union", "select", "from", "where", "drop", "delete",
		"script", "javascript", "onerror", "onload", "alert",
		"../", "etc/passwd", "cmd.exe",
	}
	m := New(patterns)

	input := "GET /api/users?name=john HTTP/1.1"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match(input)
	}
}

func BenchmarkMatcher_MatchLongInput(b *testing.B) {
	patterns := []string{
		"union", "select", "from", "where", "drop", "delete",
		"script", "javascript", "onerror", "onload", "alert",
	}
	m := New(patterns)

	input := `192.168.1.1 - - [29/Dec/2024:12:00:00 +0000] "GET /api/v2/users/profile?include=settings,preferences HTTP/1.1" 200 4523 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match(input)
	}
}
