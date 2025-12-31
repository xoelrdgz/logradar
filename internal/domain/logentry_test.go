package domain

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogEntryPool(t *testing.T) {
	entry := AcquireLogEntry()
	require.NotNil(t, entry)

	entry.IP = netip.MustParseAddr("192.168.1.1")
	entry.Method = "GET"
	entry.Path = "/test"
	entry.StatusCode = 200

	ReleaseLogEntry(entry)

	entry2 := AcquireLogEntry()
	require.NotNil(t, entry2)
	assert.False(t, entry2.IP.IsValid())
	assert.Empty(t, entry2.Method)
	assert.Empty(t, entry2.Path)
	assert.Zero(t, entry2.StatusCode)

	ReleaseLogEntry(entry2)
}

func TestLogEntryClone(t *testing.T) {
	original := AcquireLogEntry()
	original.IP = netip.MustParseAddr("192.168.1.1")
	original.Timestamp = time.Now()
	original.Method = "POST"
	original.Path = "/api/users"
	original.StatusCode = 201
	original.UserAgent = "Mozilla/5.0"
	original.BytesSent = 1234
	original.RawLine = "test line"

	clone := original.Clone()

	assert.Equal(t, original.IP.String(), clone.IP.String())
	assert.Equal(t, original.Timestamp, clone.Timestamp)
	assert.Equal(t, original.Method, clone.Method)
	assert.Equal(t, original.Path, clone.Path)
	assert.Equal(t, original.StatusCode, clone.StatusCode)
	assert.Equal(t, original.UserAgent, clone.UserAgent)
	assert.Equal(t, original.BytesSent, clone.BytesSent)
	assert.Equal(t, original.RawLine, clone.RawLine)

	clone.Method = "PUT"
	assert.NotEqual(t, original.Method, clone.Method)

	ReleaseLogEntry(original)
	ReleaseLogEntry(clone)
}

func TestReleaseNilLogEntry(t *testing.T) {
	ReleaseLogEntry(nil)
}

func BenchmarkLogEntryPool(b *testing.B) {
	ip := netip.MustParseAddr("192.168.1.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry := AcquireLogEntry()
		entry.IP = ip
		entry.Method = "GET"
		entry.Path = "/test"
		entry.StatusCode = 200
		ReleaseLogEntry(entry)
	}
}

func BenchmarkLogEntryWithoutPool(b *testing.B) {
	ip := netip.MustParseAddr("192.168.1.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry := &LogEntry{
			IP:         ip,
			Method:     "GET",
			Path:       "/test",
			StatusCode: 200,
		}
		_ = entry
	}
}
