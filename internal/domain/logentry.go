package domain

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	MaxLineLength      = 8192
	MaxBodySize        = 32768
	MaxHeaderValueSize = 4096
	MaxHeaderCount     = 50
	MaxCookieCount     = 30
)

type LogEntry struct {
	IP         netip.Addr `json:"ip"`
	Timestamp  time.Time  `json:"timestamp"`
	Method     string     `json:"method"`
	Path       string     `json:"path"`
	StatusCode int        `json:"status_code"`
	UserAgent  string     `json:"user_agent"`
	BytesSent  int        `json:"bytes_sent"`
	Protocol   string     `json:"protocol,omitempty"`

	Headers     map[string]string `json:"headers,omitempty"`
	Body        []byte            `json:"body,omitempty"`
	Cookies     map[string]string `json:"cookies,omitempty"`
	QueryParams map[string]string `json:"query_params,omitempty"`
	Truncated   bool              `json:"truncated,omitempty"`
	RawLine     string            `json:"raw_line,omitempty"`
}

var logEntryPool = sync.Pool{
	New: func() interface{} {
		return &LogEntry{
			Headers:     make(map[string]string, 8),
			Cookies:     make(map[string]string, 4),
			QueryParams: make(map[string]string, 4),
		}
	},
}

func AcquireLogEntry() *LogEntry {
	return logEntryPool.Get().(*LogEntry)
}

func ReleaseLogEntry(entry *LogEntry) {
	if entry == nil {
		return
	}

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

	for k := range entry.Headers {
		delete(entry.Headers, k)
	}
	for k := range entry.Cookies {
		delete(entry.Cookies, k)
	}
	for k := range entry.QueryParams {
		delete(entry.QueryParams, k)
	}

	entry.Body = entry.Body[:0]

	logEntryPool.Put(entry)
}

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

func (e *LogEntry) IPString() string {
	if !e.IP.IsValid() {
		return ""
	}
	return e.IP.String()
}

func (e *LogEntry) GetHeader(name string) string {
	if e.Headers == nil {
		return ""
	}
	return e.Headers[strings.ToLower(name)]
}

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

func (e *LogEntry) GetCookie(name string) string {
	if e.Cookies == nil {
		return ""
	}
	return e.Cookies[name]
}

func (e *LogEntry) SetCookie(name, value string) {
	if e.Cookies == nil {
		e.Cookies = make(map[string]string, 4)
	}
	if len(e.Cookies) >= MaxCookieCount {
		return
	}
	e.Cookies[name] = value
}

func (e *LogEntry) SetBody(body []byte) {
	if len(body) > MaxBodySize {
		e.Body = body[:MaxBodySize]
		e.Truncated = true
	} else {
		e.Body = body
	}
}

func (e *LogEntry) HasBody() bool {
	return len(e.Body) > 0
}

func (e *LogEntry) BodyString() string {
	return string(e.Body)
}
