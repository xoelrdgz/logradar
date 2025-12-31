package detection

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xoelrdgz/logradar/internal/domain"
)

func TestSignatureDetector_SQLInjection(t *testing.T) {
	detector := NewSignatureDetector(nil)

	tests := []struct {
		name       string
		path       string
		wantDetect bool
		wantType   domain.ThreatType
	}{
		{
			name:       "UNION SELECT",
			path:       "/search?id=1 UNION SELECT username,password FROM users",
			wantDetect: true,
			wantType:   domain.ThreatTypeSQLInjection,
		},
		{
			name:       "OR 1=1",
			path:       "/login?user=admin' OR 1=1 --",
			wantDetect: true,
			wantType:   domain.ThreatTypeSQLInjection,
		},
		{
			name:       "SLEEP function",
			path:       "/api?id=1; SELECT SLEEP(5)--",
			wantDetect: true,
			wantType:   domain.ThreatTypeSQLInjection,
		},
		{
			name:       "DROP TABLE",
			path:       "/admin?cmd=DROP TABLE users",
			wantDetect: true,
			wantType:   domain.ThreatTypeSQLInjection,
		},
		{
			name:       "normal request",
			path:       "/api/users/123",
			wantDetect: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := &domain.LogEntry{
				IP:   netip.MustParseAddr("10.0.0.1"),
				Path: tc.path,
			}

			result := detector.Detect(context.Background(), entry)

			assert.Equal(t, tc.wantDetect, result.Detected)
			if tc.wantDetect {
				assert.Equal(t, tc.wantType, result.ThreatType)
				assert.Equal(t, domain.AlertLevelCritical, result.Level)
				assert.True(t, result.RiskScore >= 6)
			}
		})
	}
}

func TestSignatureDetector_XSS(t *testing.T) {
	detector := NewSignatureDetector(nil)

	tests := []struct {
		name       string
		path       string
		wantDetect bool
	}{
		{
			name:       "script tag",
			path:       "/comment?text=<script>alert('xss')</script>",
			wantDetect: true,
		},
		{
			name:       "javascript protocol",
			path:       "/link?url=javascript:alert(1)",
			wantDetect: true,
		},
		{
			name:       "event handler",
			path:       "/page?input=<img onerror=alert(1)>",
			wantDetect: true,
		},
		{
			name:       "normal text",
			path:       "/search?q=hello world",
			wantDetect: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := &domain.LogEntry{
				IP:   netip.MustParseAddr("10.0.0.1"),
				Path: tc.path,
			}

			result := detector.Detect(context.Background(), entry)
			assert.Equal(t, tc.wantDetect, result.Detected)
		})
	}
}

func TestSignatureDetector_PathTraversal(t *testing.T) {
	detector := NewSignatureDetector(nil)

	tests := []struct {
		name       string
		path       string
		wantDetect bool
	}{
		{
			name:       "etc passwd",
			path:       "/../../etc/passwd",
			wantDetect: true,
		},
		{
			name:       "multiple traversal",
			path:       "/files/../../../../etc/shadow",
			wantDetect: true,
		},
		{
			name:       "normal path",
			path:       "/files/document.pdf",
			wantDetect: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := &domain.LogEntry{
				IP:   netip.MustParseAddr("10.0.0.1"),
				Path: tc.path,
			}

			result := detector.Detect(context.Background(), entry)
			assert.Equal(t, tc.wantDetect, result.Detected)
		})
	}
}

func TestSignatureDetector_UserAgent(t *testing.T) {
	detector := NewSignatureDetector(nil)

	entry := &domain.LogEntry{
		IP:        netip.MustParseAddr("10.0.0.1"),
		Path:      "/normal/path",
		UserAgent: "<script>alert('xss')</script>",
	}

	result := detector.Detect(context.Background(), entry)
	assert.True(t, result.Detected)
	assert.Equal(t, domain.ThreatTypeXSS, result.ThreatType)
}

func TestSignatureDetector_NilEntry(t *testing.T) {
	detector := NewSignatureDetector(nil)
	result := detector.Detect(context.Background(), nil)
	assert.False(t, result.Detected)
}

func TestSignatureDetector_ContextCancelled(t *testing.T) {
	detector := NewSignatureDetector(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	entry := &domain.LogEntry{
		IP:   netip.MustParseAddr("10.0.0.1"),
		Path: "/search?id=1 UNION SELECT * FROM users",
	}

	result := detector.Detect(ctx, entry)
	assert.False(t, result.Detected)
}

func TestSignatureDetector_AddPattern(t *testing.T) {
	detector := NewSignatureDetector(nil)
	initialCount := detector.PatternCount()

	err := detector.AddPattern("Custom Pattern", "my_select_attack", domain.ThreatTypeUnknown, 5, domain.AlertLevelWarning)
	require.NoError(t, err)

	assert.Equal(t, initialCount+1, detector.PatternCount())

	entry := &domain.LogEntry{
		IP:   netip.MustParseAddr("10.0.0.1"),
		Path: "/test?param=my_select_attack",
	}
	result := detector.Detect(context.Background(), entry)
	assert.True(t, result.Detected)
}

func TestSignatureDetector_Name(t *testing.T) {
	detector := NewSignatureDetector(nil)
	assert.Equal(t, "signature", detector.Name())
}

func BenchmarkSignatureDetector(b *testing.B) {
	detector := NewSignatureDetector(nil)
	entry := &domain.LogEntry{
		IP:        netip.MustParseAddr("192.168.1.1"),
		Path:      "/api/users/123?filter=active",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect(ctx, entry)
	}
}

func BenchmarkSignatureDetector_Attack(b *testing.B) {
	detector := NewSignatureDetector(nil)
	entry := &domain.LogEntry{
		IP:        netip.MustParseAddr("192.168.1.1"),
		Path:      "/search?id=1 UNION SELECT username,password FROM users--",
		UserAgent: "sqlmap/1.2.3",
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect(ctx, entry)
	}
}
