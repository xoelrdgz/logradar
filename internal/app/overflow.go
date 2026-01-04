// Package app provides resilience mechanisms for the LogRadar worker pipeline.
//
// This file implements overflow and quarantine writers that ensure data durability
// when the processing pipeline experiences backpressure or worker panics.
//
// Resilience Strategy:
//   - Overflow: Persists entries/alerts to disk when channels are full
//   - Quarantine: Isolates "toxic" messages that cause worker panics for analysis
package app

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/xoelrdgz/logradar/internal/domain"
)

// OverflowWriter provides durable storage for entries/alerts when pipeline is saturated.
//
// When the worker pool's input or output channels reach capacity, entries are
// written to this overflow file instead of being dropped. This prevents data
// loss during traffic spikes while maintaining pipeline throughput.
//
// Thread Safety: All methods are safe for concurrent access via mutex.
//
// File Format: NDJSON (newline-delimited JSON) for easy replay processing.
type OverflowWriter struct {
	file    *os.File      // Underlying file handle
	writer  *bufio.Writer // Buffered writer (64KB buffer)
	mu      sync.Mutex    // Protects write operations
	count   atomic.Int64  // Total entries written
	enabled bool          // False if path was empty
	path    string        // File path for logging
}

// OverflowEntry wraps log entries and alerts with metadata for replay.
type OverflowEntry struct {
	Type      string          `json:"type"`      // "entry" or "alert"
	Timestamp time.Time       `json:"timestamp"` // When overflow occurred
	Data      json.RawMessage `json:"data"`      // Original entry/alert JSON
}

// NewOverflowWriter creates an overflow file writer.
//
// Parameters:
//   - path: File path for overflow storage (empty disables overflow)
//
// Returns:
//   - Configured OverflowWriter
//   - Error if file creation fails
//
// Note: Returns disabled writer (no-op) if path is empty.
func NewOverflowWriter(path string) (*OverflowWriter, error) {
	if path == "" {
		return &OverflowWriter{enabled: false}, nil
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	log.Info().Str("path", path).Msg("Overflow writer initialized")

	return &OverflowWriter{
		file:    file,
		writer:  bufio.NewWriterSize(file, 64*1024),
		enabled: true,
		path:    path,
	}, nil
}

// WriteEntry persists a log entry to the overflow file.
//
// Parameters:
//   - entry: LogEntry to persist
//
// Returns:
//   - nil on success
//   - Error if serialization or write fails
func (w *OverflowWriter) WriteEntry(entry *domain.LogEntry) error {
	if !w.enabled {
		return nil
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return w.write("entry", data)
}

// WriteAlert persists an alert to the overflow file.
//
// Parameters:
//   - alert: Alert to persist
//
// Returns:
//   - nil on success
//   - Error if serialization or write fails
func (w *OverflowWriter) WriteAlert(alert *domain.Alert) error {
	if !w.enabled {
		return nil
	}

	data, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	return w.write("alert", data)
}

// write is the internal method that performs the actual file write.
// Flushes and syncs every 100 entries for durability/performance balance.
func (w *OverflowWriter) write(entryType string, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	entry := OverflowEntry{
		Type:      entryType,
		Timestamp: time.Now(),
		Data:      data,
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	if _, err := w.writer.Write(line); err != nil {
		return err
	}
	if err := w.writer.WriteByte('\n'); err != nil {
		return err
	}

	w.count.Add(1)

	// Periodic flush for durability
	if w.count.Load()%100 == 0 {
		if err := w.writer.Flush(); err != nil {
			return err
		}
		if err := w.file.Sync(); err != nil {
			return err
		}
	}

	return nil
}

// Flush forces buffered data to disk.
func (w *OverflowWriter) Flush() error {
	if !w.enabled {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writer.Flush(); err != nil {
		return err
	}
	return w.file.Sync()
}

// Close flushes and closes the overflow file.
// Logs a warning if unprocessed entries remain.
func (w *OverflowWriter) Close() error {
	if !w.enabled {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writer.Flush(); err != nil {
		return err
	}

	count := w.count.Load()
	if count > 0 {
		log.Warn().
			Int64("overflow_count", count).
			Str("path", w.path).
			Msg("Overflow file contains unprocessed entries")
	}

	return w.file.Close()
}

// Count returns the number of entries written to overflow.
func (w *OverflowWriter) Count() int64 {
	return w.count.Load()
}

// Enabled returns true if overflow writing is active.
func (w *OverflowWriter) Enabled() bool {
	return w.enabled
}

// QuarantineWriter isolates toxic messages that cause worker panics.
//
// When a worker goroutine panics while processing an entry, the entry is
// considered "toxic" and written to this quarantine file for later analysis.
// This allows the pipeline to continue processing while preserving evidence
// of problematic inputs (potential attack payloads or parser bugs).
//
// Security Value:
//   - Preserves attack payloads that bypass parser validation
//   - Captures edge cases for fuzzing improvement
//   - Provides forensic evidence for post-incident analysis
//
// Thread Safety: All methods are safe for concurrent access via mutex.
type QuarantineWriter struct {
	file    *os.File      // Underlying file handle
	writer  *bufio.Writer // Buffered writer (16KB buffer)
	mu      sync.Mutex    // Protects write operations
	count   atomic.Int64  // Total toxic messages quarantined
	enabled bool          // False if path was empty
	path    string        // File path for logging
}

// QuarantineEntry captures full context of a toxic message.
type QuarantineEntry struct {
	Timestamp  time.Time       `json:"timestamp"`             // When panic occurred
	WorkerID   int             `json:"worker_id"`             // Which worker panicked
	PanicError string          `json:"panic_error"`           // Panic message
	StackTrace string          `json:"stack_trace,omitempty"` // Stack trace if available
	Entry      json.RawMessage `json:"entry"`                 // Original entry JSON
	RawLine    string          `json:"raw_line,omitempty"`    // Original log line
}

// NewQuarantineWriter creates a quarantine file writer.
//
// Parameters:
//   - path: File path for quarantine storage (empty disables)
//
// Returns:
//   - Configured QuarantineWriter
//   - Error if file creation fails
func NewQuarantineWriter(path string) (*QuarantineWriter, error) {
	if path == "" {
		return &QuarantineWriter{enabled: false}, nil
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	log.Info().Str("path", path).Msg("Quarantine writer initialized for toxic messages")

	return &QuarantineWriter{
		file:    file,
		writer:  bufio.NewWriterSize(file, 16*1024),
		enabled: true,
		path:    path,
	}, nil
}

// WriteToxicMessage persists a toxic message with full panic context.
//
// Parameters:
//   - workerID: ID of the worker that panicked
//   - panicErr: The panic value (error, string, or any)
//   - entry: The entry being processed when panic occurred (may be nil)
//
// Returns:
//   - nil on success
//   - Error if write fails
//
// Note: Always flushes immediately to ensure toxic messages are persisted
// even if the process crashes shortly after.
func (w *QuarantineWriter) WriteToxicMessage(workerID int, panicErr interface{}, entry *domain.LogEntry) error {
	if !w.enabled {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	var entryData json.RawMessage
	var rawLine string
	if entry != nil {
		data, err := json.Marshal(entry)
		if err != nil {
			entryData = []byte(`{"error": "failed to serialize entry"}`)
		} else {
			entryData = data
		}
		rawLine = entry.RawLine
	} else {
		entryData = []byte(`null`)
	}

	panicStr := "unknown panic"
	if panicErr != nil {
		switch v := panicErr.(type) {
		case error:
			panicStr = v.Error()
		case string:
			panicStr = v
		default:
			panicStr = fmt.Sprintf("%v", v)
		}
	}

	qe := QuarantineEntry{
		Timestamp:  time.Now(),
		WorkerID:   workerID,
		PanicError: panicStr,
		Entry:      entryData,
		RawLine:    rawLine,
	}

	line, err := json.Marshal(qe)
	if err != nil {
		return err
	}

	if _, err := w.writer.Write(line); err != nil {
		return err
	}
	if err := w.writer.WriteByte('\n'); err != nil {
		return err
	}

	// Immediate flush for toxic messages
	if err := w.writer.Flush(); err != nil {
		return err
	}
	if err := w.file.Sync(); err != nil {
		return err
	}

	w.count.Add(1)

	log.Warn().
		Int("worker_id", workerID).
		Str("panic", panicStr).
		Int64("quarantine_count", w.count.Load()).
		Msg("Toxic message quarantined")

	return nil
}

// Close flushes and closes the quarantine file.
// Logs a warning if toxic messages were captured.
func (w *QuarantineWriter) Close() error {
	if !w.enabled {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writer.Flush(); err != nil {
		return err
	}

	count := w.count.Load()
	if count > 0 {
		log.Warn().
			Int64("toxic_count", count).
			Str("path", w.path).
			Msg("Quarantine file contains toxic messages requiring analysis")
	}

	return w.file.Close()
}

// Count returns the number of toxic messages quarantined.
func (w *QuarantineWriter) Count() int64 {
	return w.count.Load()
}

// Enabled returns true if quarantine writing is active.
func (w *QuarantineWriter) Enabled() bool {
	return w.enabled
}
