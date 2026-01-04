// Package input provides log parsing adapters for LogRadar.
//
// This file implements parsers for different log formats:
//   - CombinedLogParser: Apache/Nginx Combined Log Format
//   - JSONLogParser: Structured JSON logs
//   - AutoDetectParser: Auto-detects and delegates to appropriate parser
//
// Security Considerations:
//   - All parsers enforce MaxLineLength to prevent memory exhaustion
//   - Query parameters limited to 20 per request
//   - Cookies limited to 50 per request
//   - Input validation rejects malformed entries
//
// Thread Safety: Parsers are stateless and safe for concurrent Parse() calls.
package input

import (
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xoelrdgz/logradar/internal/domain"
)

// Package-level errors for parser validation.
var (
	// ErrInvalidLogFormat indicates the log line could not be parsed.
	ErrInvalidLogFormat = errors.New("invalid log format")
	// clfTimeLayout is the timestamp format for Apache/Nginx Combined Log Format.
	clfTimeLayout = "02/Jan/2006:15:04:05 -0700"
)

// CombinedLogParser parses Apache/Nginx Combined Log Format (CLF).
//
// Format: IP - - [timestamp] "METHOD /path HTTP/x.x" status bytes "referer" "user-agent"
//
// Example:
//
//	192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
//
// Thread Safety: Stateless and safe for concurrent Parse() calls.
type CombinedLogParser struct{}

// NewCombinedLogParser creates a CLF parser.
func NewCombinedLogParser() *CombinedLogParser {
	return &CombinedLogParser{}
}

// Parse extracts structured data from a CLF log line.
//
// Parameters:
//   - line: Raw log line to parse
//
// Returns:
//   - LogEntry acquired from pool (caller must release with ReleaseLogEntry)
//   - ErrInvalidLogFormat if parsing fails
//
// Security:
//   - Truncates lines exceeding MaxLineLength
//   - Sets Truncated flag on entry when truncation occurs
//   - Uses strings.Clone to prevent memory retention of large buffers
func (p *CombinedLogParser) Parse(line string) (*domain.LogEntry, error) {
	truncated := false
	if len(line) > domain.MaxLineLength {
		line = line[:domain.MaxLineLength]
		truncated = true
	}

	if len(line) < 50 {
		return nil, ErrInvalidLogFormat
	}

	entry := domain.AcquireLogEntry()
	entry.Truncated = truncated

	pos := 0
	lineLen := len(line)

	// Parse IP address
	ipEnd := skipUntil(line, pos, ' ')
	if ipEnd == -1 || ipEnd == pos {
		domain.ReleaseLogEntry(entry)
		return nil, ErrInvalidLogFormat
	}
	addr, err := netip.ParseAddr(line[pos:ipEnd])
	if err != nil {
		domain.ReleaseLogEntry(entry)
		return nil, errors.New("invalid IP address")
	}
	entry.IP = addr
	pos = ipEnd + 1

	// Skip ident and auth fields (- -)
	for i := 0; i < 2; i++ {
		end := skipUntil(line, pos, ' ')
		if end == -1 {
			domain.ReleaseLogEntry(entry)
			return nil, ErrInvalidLogFormat
		}
		pos = end + 1
	}

	// Parse timestamp [dd/Mon/yyyy:hh:mm:ss +zzzz]
	if pos >= lineLen || line[pos] != '[' {
		domain.ReleaseLogEntry(entry)
		return nil, ErrInvalidLogFormat
	}
	pos++
	tsEnd := skipUntil(line, pos, ']')
	if tsEnd == -1 {
		domain.ReleaseLogEntry(entry)
		return nil, ErrInvalidLogFormat
	}
	timestamp, err := time.Parse(clfTimeLayout, line[pos:tsEnd])
	if err != nil {
		domain.ReleaseLogEntry(entry)
		return nil, errors.New("invalid timestamp format")
	}
	entry.Timestamp = timestamp
	pos = tsEnd + 2

	// Parse request "METHOD /path HTTP/x.x"
	if pos >= lineLen || line[pos] != '"' {
		domain.ReleaseLogEntry(entry)
		return nil, ErrInvalidLogFormat
	}
	pos++
	reqEnd := findClosingQuote(line, pos)
	if reqEnd == -1 {
		domain.ReleaseLogEntry(entry)
		return nil, ErrInvalidLogFormat
	}
	request := line[pos:reqEnd]
	pos = reqEnd + 2

	method, path, err := parseRequest(request)
	if err != nil {
		domain.ReleaseLogEntry(entry)
		return nil, err
	}
	entry.Method = strings.Clone(method)
	entry.Path = strings.Clone(path)

	// Parse query parameters from path
	if idx := strings.Index(path, "?"); idx >= 0 {
		parseQueryParams(entry, path[idx+1:])
	}

	// Parse status code
	if pos >= lineLen {
		domain.ReleaseLogEntry(entry)
		return nil, ErrInvalidLogFormat
	}
	statusEnd := skipUntil(line, pos, ' ')
	if statusEnd == -1 {
		domain.ReleaseLogEntry(entry)
		return nil, ErrInvalidLogFormat
	}
	statusCode, err := strconv.Atoi(line[pos:statusEnd])
	if err != nil || statusCode < 100 || statusCode > 599 {
		domain.ReleaseLogEntry(entry)
		return nil, errors.New("invalid status code")
	}
	entry.StatusCode = statusCode
	pos = statusEnd + 1

	// Parse bytes sent
	if pos >= lineLen {
		domain.ReleaseLogEntry(entry)
		return nil, ErrInvalidLogFormat
	}
	bytesEnd := skipUntil(line, pos, ' ')
	if bytesEnd == -1 {
		bytesEnd = lineLen
	}
	bytesStr := line[pos:bytesEnd]
	if bytesStr == "-" {
		entry.BytesSent = 0
	} else {
		bytesSent, err := strconv.Atoi(bytesStr)
		if err != nil || bytesSent < 0 {
			entry.BytesSent = 0
		} else {
			entry.BytesSent = bytesSent
		}
	}
	pos = bytesEnd + 1

	// Skip referer field
	if pos < lineLen && line[pos] == '"' {
		pos++
		refEnd := findClosingQuote(line, pos)
		if refEnd != -1 {
			pos = refEnd + 2
		}
	}

	// Parse User-Agent
	if pos < lineLen && line[pos] == '"' {
		pos++
		uaEnd := findClosingQuote(line, pos)
		if uaEnd != -1 {
			entry.UserAgent = strings.Clone(unescapeQuotes(line[pos:uaEnd]))
		}
	}

	entry.RawLine = strings.Clone(line)
	return entry, nil
}

// Format returns the parser identifier.
func (p *CombinedLogParser) Format() string {
	return "combined"
}

// Validate checks if a line appears to be CLF format.
//
// Parameters:
//   - line: Raw log line to check
//
// Returns:
//   - true if line has CLF structure indicators
func (p *CombinedLogParser) Validate(line string) bool {
	return len(line) > 50 &&
		containsByte(line, '[') &&
		containsByte(line, ']') &&
		containsByte(line, '"')
}

// JSONLogEntry represents the expected structure of JSON log entries.
// Supports common Nginx JSON logging configurations.
type JSONLogEntry struct {
	Timestamp      string            `json:"timestamp"`                 // RFC3339 or ISO8601 format
	RemoteAddr     string            `json:"remote_addr"`               // Client IP address
	RequestMethod  string            `json:"request_method"`            // HTTP method
	RequestURI     string            `json:"request_uri"`               // Request path with query
	Status         int               `json:"status"`                    // HTTP status code
	BodyBytesSent  int               `json:"body_bytes_sent"`           // Response body size
	HTTPUserAgent  string            `json:"http_user_agent"`           // User-Agent header
	RequestBody    string            `json:"request_body,omitempty"`    // POST body (optional)
	HTTPHeaders    map[string]string `json:"http_headers,omitempty"`    // Request headers (optional)
	HTTPCookies    string            `json:"http_cookie,omitempty"`     // Cookie header (optional)
	ServerProtocol string            `json:"server_protocol,omitempty"` // HTTP/1.1, HTTP/2, etc.
	Protocol       string            `json:"protocol,omitempty"`        // Alternative protocol field
}

// JSONParser parses structured JSON log entries.
//
// Thread Safety: Stateless and safe for concurrent Parse() calls.
type JSONParser struct {
	maxLineLength int // Maximum line length before truncation
}

// NewJSONParser creates a JSON log parser.
func NewJSONParser() *JSONParser {
	return &JSONParser{
		maxLineLength: domain.MaxLineLength,
	}
}

// Parse extracts structured data from a JSON log line.
//
// Parameters:
//   - line: JSON log line to parse
//
// Returns:
//   - LogEntry acquired from pool (caller must release)
//   - ErrInvalidLogFormat if JSON parsing fails
//
// Supported timestamp formats:
//   - RFC3339 (2006-01-02T15:04:05Z07:00)
//   - Falls back to current time if parsing fails
func (p *JSONParser) Parse(line string) (*domain.LogEntry, error) {
	truncated := false
	if len(line) > p.maxLineLength {
		line = line[:p.maxLineLength]
		truncated = true
	}

	if len(line) < 10 || line[0] != '{' {
		return nil, ErrInvalidLogFormat
	}

	var jsonEntry JSONLogEntry
	if err := json.Unmarshal([]byte(line), &jsonEntry); err != nil {
		return nil, ErrInvalidLogFormat
	}

	entry := domain.AcquireLogEntry()
	entry.Truncated = truncated

	// Parse IP address
	if jsonEntry.RemoteAddr != "" {
		if addr, err := netip.ParseAddr(jsonEntry.RemoteAddr); err == nil {
			entry.IP = addr
		}
	}

	// Parse timestamp with fallback formats
	if jsonEntry.Timestamp != "" {
		if ts, err := time.Parse(time.RFC3339, jsonEntry.Timestamp); err == nil {
			entry.Timestamp = ts
		} else if ts, err := time.Parse("2006-01-02T15:04:05Z07:00", jsonEntry.Timestamp); err == nil {
			entry.Timestamp = ts
		}
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	entry.Method = jsonEntry.RequestMethod
	entry.Path = jsonEntry.RequestURI
	entry.StatusCode = jsonEntry.Status
	entry.BytesSent = jsonEntry.BodyBytesSent
	entry.UserAgent = jsonEntry.HTTPUserAgent

	// Extract query parameters
	if idx := strings.Index(entry.Path, "?"); idx >= 0 {
		parseQueryParams(entry, entry.Path[idx+1:])
	}

	// Copy headers
	for k, v := range jsonEntry.HTTPHeaders {
		entry.SetHeader(k, v)
	}

	// Parse cookies
	if jsonEntry.HTTPCookies != "" {
		parseCookies(entry, jsonEntry.HTTPCookies)
	}

	// Set body if present
	if jsonEntry.RequestBody != "" {
		entry.SetBody([]byte(jsonEntry.RequestBody))
	}

	// Set protocol
	if jsonEntry.ServerProtocol != "" {
		entry.Protocol = jsonEntry.ServerProtocol
	} else if jsonEntry.Protocol != "" {
		entry.Protocol = jsonEntry.Protocol
	}

	return entry, nil
}

// Format returns the parser identifier.
func (p *JSONParser) Format() string {
	return "json"
}

// Validate checks if a line appears to be JSON format.
func (p *JSONParser) Validate(line string) bool {
	return len(line) > 10 && line[0] == '{' && line[len(line)-1] == '}'
}

// parseQueryParams extracts query parameters into the entry.
// Limits to 20 parameters to prevent DoS via parameter pollution.
func parseQueryParams(entry *domain.LogEntry, query string) {
	if entry.QueryParams == nil {
		entry.QueryParams = make(map[string]string, 4)
	}

	values, err := url.ParseQuery(query)
	if err != nil {
		return
	}

	count := 0
	for k, v := range values {
		if count >= 20 {
			break
		}
		if len(v) > 0 {
			entry.QueryParams[k] = v[0]
		}
		count++
	}
}

// parseCookies extracts cookies from the Cookie header.
// Limits to 50 cookies to prevent memory exhaustion.
func parseCookies(entry *domain.LogEntry, cookieHeader string) {
	remaining := cookieHeader
	count := 0
	const maxCookies = 50

	for remaining != "" && count < maxCookies {
		var pair string
		var found bool

		pair, remaining, found = strings.Cut(remaining, ";")
		if !found {
			pair = remaining
			remaining = ""
		}

		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		name, value, hasEquals := strings.Cut(pair, "=")
		if hasEquals && name != "" {
			entry.SetCookie(strings.TrimSpace(name), strings.TrimSpace(value))
			count++
		}
	}
}

// findClosingQuote finds the position of the closing quote, handling escapes.
// Returns -1 if no closing quote is found.
func findClosingQuote(s string, start int) int {
	i := start
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == '"' {
			return i
		}
		i++
	}
	return -1
}

// skipUntil finds the position of the first occurrence of char after pos.
// Returns -1 if char is not found.
func skipUntil(s string, pos int, char byte) int {
	for i := pos; i < len(s); i++ {
		if s[i] == char {
			return i
		}
	}
	return -1
}

// parseRequest extracts method and path from "METHOD /path HTTP/x.x" string.
func parseRequest(s string) (method, path string, err error) {
	firstSpace := skipUntil(s, 0, ' ')
	if firstSpace == -1 || firstSpace == 0 {
		return "", "", ErrInvalidLogFormat
	}
	method = s[:firstSpace]

	// Find last space (HTTP version)
	lastSpace := -1
	for i := len(s) - 1; i > firstSpace; i-- {
		if s[i] == ' ' {
			lastSpace = i
			break
		}
	}

	if lastSpace == -1 || lastSpace <= firstSpace+1 {
		path = s[firstSpace+1:]
	} else {
		path = s[firstSpace+1 : lastSpace]
	}

	// Validate method length
	if len(method) < 3 || len(method) > 10 {
		return "", "", ErrInvalidLogFormat
	}

	return method, path, nil
}

// unescapeQuotes replaces \" with " in quoted strings.
func unescapeQuotes(s string) string {
	hasEscape := false
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '\\' && s[i+1] == '"' {
			hasEscape = true
			break
		}
	}
	if !hasEscape {
		return s
	}

	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '"' {
			result = append(result, '"')
			i++
		} else {
			result = append(result, s[i])
		}
	}
	return string(result)
}

// containsByte returns true if c appears in s.
func containsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

// AutoDetectParser automatically detects log format and delegates to appropriate parser.
//
// Detection Strategy:
//  1. If line starts with '{', try JSON parser
//  2. Fall back to CLF parser
//
// Thread Safety: Stateless and safe for concurrent Parse() calls.
type AutoDetectParser struct {
	jsonParser *JSONParser        // Delegate for JSON logs
	clfParser  *CombinedLogParser // Delegate for CLF logs
}

// NewAutoDetectParser creates an auto-detecting parser.
func NewAutoDetectParser() *AutoDetectParser {
	return &AutoDetectParser{
		jsonParser: NewJSONParser(),
		clfParser:  NewCombinedLogParser(),
	}
}

// Parse automatically detects format and parses the log line.
//
// Parameters:
//   - line: Raw log line in any supported format
//
// Returns:
//   - LogEntry from pool (caller must release)
//   - Error if all parsers fail
func (p *AutoDetectParser) Parse(line string) (*domain.LogEntry, error) {
	if len(line) > 0 && line[0] == '{' {
		entry, err := p.jsonParser.Parse(line)
		if err == nil {
			return entry, nil
		}
	}
	return p.clfParser.Parse(line)
}

// Format returns the parser identifier.
func (p *AutoDetectParser) Format() string {
	return "auto"
}

// Validate checks if a line is parseable by any supported format.
func (p *AutoDetectParser) Validate(line string) bool {
	return p.jsonParser.Validate(line) || p.clfParser.Validate(line)
}
