// Package domain defines the core business entities and value objects for LogRadar.
//
// LogEntry represents parsed HTTP access log records with security-focused field
// extraction and resource limits to prevent denial-of-service through malformed logs.
package domain

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Resource limits to prevent denial-of-service through oversized log entries.
// These values are tuned for production HTTP log analysis while preventing
// memory exhaustion from malicious or malformed input.
const (
	// MaxLineLength limits raw log line size to prevent memory exhaustion.
	// Apache/Nginx default max line sizes are typically 8KB.
	MaxLineLength = 8192

	// MaxBodySize limits request body storage for POST/PUT analysis.
	// Prevents memory exhaustion from large file upload logs.
	MaxBodySize = 32768

	// MaxHeaderValueSize limits individual HTTP header value storage.
	// Prevents memory exhaustion from oversized headers (e.g., Cookie bombs).
	MaxHeaderValueSize = 4096

	// MaxHeaderCount limits total headers parsed per request.
	// Prevents CPU exhaustion from header flooding attacks.
	MaxHeaderCount = 50

	// MaxCookieCount limits cookies parsed per request.
	// Prevents CPU exhaustion from cookie bombing attacks.
	MaxCookieCount = 30
)

// LogEntry represents a parsed HTTP access log record with security-relevant fields.
//
// Design decisions:
//   - Uses netip.Addr for IP addresses (zero-allocation, memory-safe)
//   - Implements sync.Pool pattern for high-throughput scenarios
//   - All string fields use strings.Clone to prevent memory retention
//   - Truncation flags indicate potential evasion attempts
//
// Thread Safety:
//   - LogEntry instances should not be shared between goroutines
//   - Use Clone() to create a copy for cross-goroutine communication
//   - Release entries back to pool via ReleaseLogEntry after processing
type LogEntry struct {
	// IP is the validated client IP address (supports IPv4 and IPv6).
	// Uses netip.Addr for memory-efficient, allocation-free handling.
	IP netip.Addr `json:"ip"`

	// Timestamp is the request time from the log entry (not parse time).
	Timestamp time.Time `json:"timestamp"`

	// Method is the HTTP method (GET, POST, PUT, DELETE, etc.).
	// Validated to 3-10 characters to prevent injection in log output.
	Method string `json:"method"`

	// Path is the request URI including query string.
	// Primary target for signature-based attack detection.
	Path string `json:"path"`

	// StatusCode is the HTTP response status (100-599).
	// Used for behavioral analysis (401/403 patterns indicate brute force).
	StatusCode int `json:"status_code"`

	// UserAgent is the HTTP User-Agent header value.
	// Used for bot detection and scanner fingerprinting.
	UserAgent string `json:"user_agent"`

	// BytesSent is the response body size in bytes.
	// Anomalies may indicate data exfiltration or error conditions.
	BytesSent int `json:"bytes_sent"`

	// Protocol is the HTTP protocol version (HTTP/1.0, HTTP/1.1, HTTP/2).
	Protocol string `json:"protocol,omitempty"`

	// Headers contains normalized HTTP request headers (lowercase keys).
	// Used for Log4Shell, CRLF injection, and header-based attack detection.
	Headers map[string]string `json:"headers,omitempty"`

	// Body contains request body for POST/PUT requests.
	// Used for payload-based attack detection (SQLi, XSS in JSON/form data).
	Body []byte `json:"body,omitempty"`

	// Cookies contains parsed HTTP cookies.
	// Used for session-based attack detection and cookie injection.
	Cookies map[string]string `json:"cookies,omitempty"`

	// QueryParams contains parsed URL query parameters.
	// Primary vector for reflected attack payloads.
	QueryParams map[string]string `json:"query_params,omitempty"`

	// Truncated indicates if any field was truncated due to size limits.
	// When true, consider the entry as potential evasion attempt.
	Truncated bool `json:"truncated,omitempty"`

	// RawLine contains the original unparsed log line.
	// Preserved for alert generation and audit logging.
	RawLine string `json:"raw_line,omitempty"`
}

// logEntryPool provides object pooling for high-throughput log processing.
// Reduces GC pressure significantly at >10K entries/second.
//
// Security: Pool initialization pre-allocates maps to prevent nil pointer
// issues during field access.
var logEntryPool = sync.Pool{
	New: func() interface{} {
		return &LogEntry{
			Headers:     make(map[string]string, 8),
			Cookies:     make(map[string]string, 4),
			QueryParams: make(map[string]string, 4),
		}
	},
}

// AcquireLogEntry retrieves a LogEntry from the pool for reuse.
//
// Performance: ~10x faster than allocation at high throughput.
// IMPORTANT: Caller MUST call ReleaseLogEntry after processing completes.
//
// Returns:
//   - Zeroed LogEntry ready for population by parser
func AcquireLogEntry() *LogEntry {
	return logEntryPool.Get().(*LogEntry)
}

// ReleaseLogEntry returns a LogEntry to the pool after processing.
//
// Security: Clears all fields to prevent data leakage between requests.
// Safe to call with nil (no-op).
//
// Parameters:
//   - entry: LogEntry to return to pool (may be nil)
//
// Warning: Do NOT use the entry after calling this function.
func ReleaseLogEntry(entry *LogEntry) {
	if entry == nil {
		return
	}

	// Zero all fields to prevent data leakage
	entry.IP = netip.Addr{}
	entry.Timestamp = time.Time{}
	entry.Method = ""
	entry.Path = ""
	entry.StatusCode = 0
	entry.UserAgent = ""
	entry.BytesSent = 0
	entry.Protocol = ""
	entry.RawLine = ""
	entry.Truncated = false

	// Clear maps without reallocation
	for k := range entry.Headers {
		delete(entry.Headers, k)
	}
	for k := range entry.Cookies {
		delete(entry.Cookies, k)
	}
	for k := range entry.QueryParams {
		delete(entry.QueryParams, k)
	}

	// Truncate body slice (keeps underlying capacity)
	entry.Body = entry.Body[:0]

	logEntryPool.Put(entry)
}

// Clone creates a deep copy of the LogEntry for cross-goroutine use.
//
// Use cases:
//   - Sending entry to async alert handlers
//   - Storing entries in DLQ for retry
//   - Quarantine for later analysis
//
// Returns:
//   - New LogEntry with all fields copied (safe for concurrent use)
//
// Note: The clone is obtained from the pool and must be released separately.
func (e *LogEntry) Clone() *LogEntry {
	clone := AcquireLogEntry()
	clone.IP = e.IP
	clone.Timestamp = e.Timestamp
	clone.Method = strings.Clone(e.Method)
	clone.Path = strings.Clone(e.Path)
	clone.StatusCode = e.StatusCode
	clone.UserAgent = strings.Clone(e.UserAgent)
	clone.BytesSent = e.BytesSent
	clone.Protocol = strings.Clone(e.Protocol)
	clone.RawLine = strings.Clone(e.RawLine)
	clone.Truncated = e.Truncated

	for k, v := range e.Headers {
		clone.Headers[k] = v
	}
	for k, v := range e.Cookies {
		clone.Cookies[k] = v
	}
	for k, v := range e.QueryParams {
		clone.QueryParams[k] = v
	}

	if len(e.Body) > 0 {
		clone.Body = make([]byte, len(e.Body))
		copy(clone.Body, e.Body)
	}

	return clone
}

// IPString returns the string representation of the client IP.
// Returns empty string for invalid/zero IP addresses.
func (e *LogEntry) IPString() string {
	if !e.IP.IsValid() {
		return ""
	}
	return e.IP.String()
}

// GetHeader retrieves a header value by name (case-insensitive lookup).
//
// Parameters:
//   - name: Header name (will be lowercased for lookup)
//
// Returns:
//   - Header value if found, empty string otherwise
func (e *LogEntry) GetHeader(name string) string {
	if e.Headers == nil {
		return ""
	}
	return e.Headers[strings.ToLower(name)]
}

// SetHeader adds or updates a header with size limit enforcement.
//
// Security:
//   - Header name is normalized to lowercase
//   - Value is truncated to MaxHeaderValueSize if exceeded
//   - No-op if MaxHeaderCount is reached (prevents header flooding)
//
// Parameters:
//   - name: Header name (will be lowercased)
//   - value: Header value (may be truncated)
func (e *LogEntry) SetHeader(name, value string) {
	if e.Headers == nil {
		e.Headers = make(map[string]string, 8)
	}
	if len(e.Headers) >= MaxHeaderCount {
		return
	}
	if len(value) > MaxHeaderValueSize {
		value = value[:MaxHeaderValueSize]
		e.Truncated = true
	}
	e.Headers[strings.ToLower(name)] = value
}

// GetCookie retrieves a cookie value by name (case-sensitive).
//
// Parameters:
//   - name: Cookie name
//
// Returns:
//   - Cookie value if found, empty string otherwise
func (e *LogEntry) GetCookie(name string) string {
	if e.Cookies == nil {
		return ""
	}
	return e.Cookies[name]
}

// SetCookie adds or updates a cookie with count limit enforcement.
//
// Security:
//   - No-op if MaxCookieCount is reached (prevents cookie flooding)
//
// Parameters:
//   - name: Cookie name
//   - value: Cookie value
func (e *LogEntry) SetCookie(name, value string) {
	if e.Cookies == nil {
		e.Cookies = make(map[string]string, 4)
	}
	if len(e.Cookies) >= MaxCookieCount {
		return
	}
	e.Cookies[name] = value
}

// SetBody stores request body with size limit enforcement.
//
// Security:
//   - Body is truncated to MaxBodySize if exceeded
//   - Sets Truncated flag to indicate potential evasion
//
// Parameters:
//   - body: Request body bytes (may be truncated)
func (e *LogEntry) SetBody(body []byte) {
	if len(body) > MaxBodySize {
		e.Body = body[:MaxBodySize]
		e.Truncated = true
	} else {
		e.Body = body
	}
}

// HasBody returns true if the entry contains request body data.
func (e *LogEntry) HasBody() bool {
	return len(e.Body) > 0
}

// BodyString returns the request body as a string.
// Returns empty string if no body present.
func (e *LogEntry) BodyString() string {
	return string(e.Body)
}
