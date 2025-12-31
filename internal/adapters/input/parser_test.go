package input

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCombinedLogParser(t *testing.T) {
	parser := NewCombinedLogParser()

	tests := []struct {
		name       string
		line       string
		wantErr    bool
		wantIP     string
		wantMethod string
		wantPath   string
		wantStatus int
	}{
		{
			name:       "valid GET request",
			line:       `192.168.1.10 - - [28/Dec/2025:10:00:00 +0000] "GET /admin/login.php HTTP/1.1" 401 1234 "-" "Mozilla/5.0"`,
			wantErr:    false,
			wantIP:     "192.168.1.10",
			wantMethod: "GET",
			wantPath:   "/admin/login.php",
			wantStatus: 401,
		},
		{
			name:       "valid POST request",
			line:       `10.0.0.1 - - [28/Dec/2025:12:30:45 +0100] "POST /api/users HTTP/1.1" 201 5678 "-" "curl/7.68.0"`,
			wantErr:    false,
			wantIP:     "10.0.0.1",
			wantMethod: "POST",
			wantPath:   "/api/users",
			wantStatus: 201,
		},
		{
			name:       "request with query string",
			line:       `172.16.0.1 - - [01/Jan/2025:00:00:00 +0000] "GET /search?q=test HTTP/1.1" 200 999 "-" "Mozilla/5.0"`,
			wantErr:    false,
			wantIP:     "172.16.0.1",
			wantMethod: "GET",
			wantPath:   "/search?q=test",
			wantStatus: 200,
		},
		{
			name:    "invalid format",
			line:    "this is not a valid log line",
			wantErr: true,
		},
		{
			name:    "empty line",
			line:    "",
			wantErr: true,
		},
		{
			name:    "invalid IP",
			line:    `not.an.ip.address - - [28/Dec/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "test"`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := parser.Parse(tc.line)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, entry)

			assert.Equal(t, tc.wantIP, entry.IP.String())
			assert.Equal(t, tc.wantMethod, entry.Method)
			assert.Equal(t, tc.wantPath, entry.Path)
			assert.Equal(t, tc.wantStatus, entry.StatusCode)
			assert.Equal(t, tc.line, entry.RawLine)
		})
	}
}

func TestCombinedLogParserFormat(t *testing.T) {
	parser := NewCombinedLogParser()
	assert.Equal(t, "combined", parser.Format())
}

func TestCombinedLogParserValidate(t *testing.T) {
	parser := NewCombinedLogParser()

	valid := `192.168.1.1 - - [28/Dec/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"`
	assert.True(t, parser.Validate(valid))

	invalid := "not a valid log line"
	assert.False(t, parser.Validate(invalid))
}

func BenchmarkCombinedLogParser(b *testing.B) {
	parser := NewCombinedLogParser()
	line := `192.168.1.10 - - [28/Dec/2025:10:00:00 +0000] "GET /admin/login.php HTTP/1.1" 401 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry, _ := parser.Parse(line)
		if entry != nil {
		}
	}
}

func BenchmarkCombinedLogParserParallel(b *testing.B) {
	parser := NewCombinedLogParser()
	line := `192.168.1.10 - - [28/Dec/2025:10:00:00 +0000] "GET /admin/login.php HTTP/1.1" 401 1234 "-" "Mozilla/5.0"`

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			parser.Parse(line)
		}
	})
}

func TestJSONParser(t *testing.T) {
	parser := NewJSONParser()

	tests := []struct {
		name         string
		line         string
		wantErr      bool
		wantIP       string
		wantMethod   string
		wantPath     string
		wantStatus   int
		wantProtocol string
		wantBody     string
		wantUA       string
	}{
		{
			name:       "valid JSON log",
			line:       `{"timestamp":"2025-12-30T10:00:00Z","remote_addr":"192.168.1.10","request_method":"POST","request_uri":"/api/login","status":200,"body_bytes_sent":1234,"http_user_agent":"Mozilla/5.0"}`,
			wantErr:    false,
			wantIP:     "192.168.1.10",
			wantMethod: "POST",
			wantPath:   "/api/login",
			wantStatus: 200,
			wantUA:     "Mozilla/5.0",
		},
		{
			name:         "JSON with protocol (server_protocol)",
			line:         `{"timestamp":"2025-12-30T10:00:00Z","remote_addr":"10.0.0.1","request_method":"GET","request_uri":"/","status":200,"body_bytes_sent":100,"http_user_agent":"curl/8.0","server_protocol":"HTTP/2"}`,
			wantErr:      false,
			wantIP:       "10.0.0.1",
			wantProtocol: "HTTP/2",
		},
		{
			name:         "JSON with protocol (protocol field)",
			line:         `{"timestamp":"2025-12-30T10:00:00Z","remote_addr":"10.0.0.1","request_method":"GET","request_uri":"/","status":200,"body_bytes_sent":100,"http_user_agent":"curl/8.0","protocol":"HTTP/1.0"}`,
			wantErr:      false,
			wantIP:       "10.0.0.1",
			wantProtocol: "HTTP/1.0",
		},
		{
			name:     "JSON with request body",
			line:     `{"timestamp":"2025-12-30T10:00:00Z","remote_addr":"192.168.1.1","request_method":"POST","request_uri":"/submit","status":200,"body_bytes_sent":50,"http_user_agent":"test","request_body":"user=admin&pass=secret"}`,
			wantErr:  false,
			wantBody: "user=admin&pass=secret",
		},
		{
			name:    "invalid JSON",
			line:    `{invalid json}`,
			wantErr: true,
		},
		{
			name:    "not JSON",
			line:    `192.168.1.1 - - [28/Dec/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 100`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := parser.Parse(tc.line)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, entry)

			if tc.wantIP != "" {
				assert.Equal(t, tc.wantIP, entry.IP.String())
			}
			if tc.wantMethod != "" {
				assert.Equal(t, tc.wantMethod, entry.Method)
			}
			if tc.wantPath != "" {
				assert.Equal(t, tc.wantPath, entry.Path)
			}
			if tc.wantStatus != 0 {
				assert.Equal(t, tc.wantStatus, entry.StatusCode)
			}
			if tc.wantProtocol != "" {
				assert.Equal(t, tc.wantProtocol, entry.Protocol)
			}
			if tc.wantBody != "" {
				assert.Equal(t, tc.wantBody, string(entry.Body))
			}
			if tc.wantUA != "" {
				assert.Equal(t, tc.wantUA, entry.UserAgent)
			}
		})
	}
}

func TestAutoDetectParser(t *testing.T) {
	parser := NewAutoDetectParser()

	assert.Equal(t, "auto", parser.Format())

	t.Run("detects JSON format", func(t *testing.T) {
		line := `{"timestamp":"2025-12-30T10:00:00Z","remote_addr":"192.168.1.10","request_method":"GET","request_uri":"/","status":200,"body_bytes_sent":100,"http_user_agent":"test"}`
		entry, err := parser.Parse(line)
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.10", entry.IP.String())
		assert.Equal(t, "GET", entry.Method)
	})

	t.Run("fallback to CLF format", func(t *testing.T) {
		line := `192.168.1.10 - - [28/Dec/2025:10:00:00 +0000] "GET /admin HTTP/1.1" 401 1234 "-" "Mozilla/5.0"`
		entry, err := parser.Parse(line)
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.10", entry.IP.String())
		assert.Equal(t, "GET", entry.Method)
		assert.Equal(t, "/admin", entry.Path)
	})

	t.Run("validates both formats", func(t *testing.T) {
		jsonLine := `{"timestamp":"2025-12-30T10:00:00Z","remote_addr":"1.1.1.1","request_method":"GET","request_uri":"/","status":200}`
		clfLine := `192.168.1.1 - - [28/Dec/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"`

		assert.True(t, parser.Validate(jsonLine))
		assert.True(t, parser.Validate(clfLine))
		assert.False(t, parser.Validate("invalid log line"))
	})
}
