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

var (
	ErrInvalidLogFormat = errors.New("invalid log format")
	clfTimeLayout       = "02/Jan/2006:15:04:05 -0700"
)

type CombinedLogParser struct{}

func NewCombinedLogParser() *CombinedLogParser {
	return &CombinedLogParser{}
}

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

	for i := 0; i < 2; i++ {
		end := skipUntil(line, pos, ' ')
		if end == -1 {
			domain.ReleaseLogEntry(entry)
			return nil, ErrInvalidLogFormat
		}
		pos = end + 1
	}

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

	if idx := strings.Index(path, "?"); idx >= 0 {
		parseQueryParams(entry, path[idx+1:])
	}
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

	if pos < lineLen && line[pos] == '"' {
		pos++
		refEnd := findClosingQuote(line, pos)
		if refEnd != -1 {
			pos = refEnd + 2
		}
	}

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

func (p *CombinedLogParser) Format() string {
	return "combined"
}

func (p *CombinedLogParser) Validate(line string) bool {
	return len(line) > 50 &&
		containsByte(line, '[') &&
		containsByte(line, ']') &&
		containsByte(line, '"')
}

type JSONLogEntry struct {
	Timestamp      string            `json:"timestamp"`
	RemoteAddr     string            `json:"remote_addr"`
	RequestMethod  string            `json:"request_method"`
	RequestURI     string            `json:"request_uri"`
	Status         int               `json:"status"`
	BodyBytesSent  int               `json:"body_bytes_sent"`
	HTTPUserAgent  string            `json:"http_user_agent"`
	RequestBody    string            `json:"request_body,omitempty"`
	HTTPHeaders    map[string]string `json:"http_headers,omitempty"`
	HTTPCookies    string            `json:"http_cookie,omitempty"`
	ServerProtocol string            `json:"server_protocol,omitempty"`
	Protocol       string            `json:"protocol,omitempty"`
}

type JSONParser struct {
	maxLineLength int
}

func NewJSONParser() *JSONParser {
	return &JSONParser{
		maxLineLength: domain.MaxLineLength,
	}
}

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

	if jsonEntry.RemoteAddr != "" {
		if addr, err := netip.ParseAddr(jsonEntry.RemoteAddr); err == nil {
			entry.IP = addr
		}
	}

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

	if idx := strings.Index(entry.Path, "?"); idx >= 0 {
		parseQueryParams(entry, entry.Path[idx+1:])
	}
	for k, v := range jsonEntry.HTTPHeaders {
		entry.SetHeader(k, v)
	}

	if jsonEntry.HTTPCookies != "" {
		parseCookies(entry, jsonEntry.HTTPCookies)
	}
	if jsonEntry.RequestBody != "" {
		entry.SetBody([]byte(jsonEntry.RequestBody))
	}

	if jsonEntry.ServerProtocol != "" {
		entry.Protocol = jsonEntry.ServerProtocol
	} else if jsonEntry.Protocol != "" {
		entry.Protocol = jsonEntry.Protocol
	}

	return entry, nil
}

func (p *JSONParser) Format() string {
	return "json"
}
func (p *JSONParser) Validate(line string) bool {
	return len(line) > 10 && line[0] == '{' && line[len(line)-1] == '}'
}

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

func skipUntil(s string, pos int, char byte) int {
	for i := pos; i < len(s); i++ {
		if s[i] == char {
			return i
		}
	}
	return -1
}

func parseRequest(s string) (method, path string, err error) {
	firstSpace := skipUntil(s, 0, ' ')
	if firstSpace == -1 || firstSpace == 0 {
		return "", "", ErrInvalidLogFormat
	}
	method = s[:firstSpace]

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

	if len(method) < 3 || len(method) > 10 {
		return "", "", ErrInvalidLogFormat
	}

	return method, path, nil
}

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

func containsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

type AutoDetectParser struct {
	jsonParser *JSONParser
	clfParser  *CombinedLogParser
}

func NewAutoDetectParser() *AutoDetectParser {
	return &AutoDetectParser{
		jsonParser: NewJSONParser(),
		clfParser:  NewCombinedLogParser(),
	}
}

func (p *AutoDetectParser) Parse(line string) (*domain.LogEntry, error) {
	if len(line) > 0 && line[0] == '{' {
		entry, err := p.jsonParser.Parse(line)
		if err == nil {
			return entry, nil
		}
	}
	return p.clfParser.Parse(line)
}

func (p *AutoDetectParser) Format() string {
	return "auto"
}

func (p *AutoDetectParser) Validate(line string) bool {
	return p.jsonParser.Validate(line) || p.clfParser.Validate(line)
}
