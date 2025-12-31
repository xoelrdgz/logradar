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

type OverflowWriter struct {
	file    *os.File
	writer  *bufio.Writer
	mu      sync.Mutex
	count   atomic.Int64
	enabled bool
	path    string
}

type OverflowEntry struct {
	Type      string          `json:"type"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

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

func (w *OverflowWriter) Count() int64 {
	return w.count.Load()
}

func (w *OverflowWriter) Enabled() bool {
	return w.enabled
}

type QuarantineWriter struct {
	file    *os.File
	writer  *bufio.Writer
	mu      sync.Mutex
	count   atomic.Int64
	enabled bool
	path    string
}

type QuarantineEntry struct {
	Timestamp  time.Time       `json:"timestamp"`
	WorkerID   int             `json:"worker_id"`
	PanicError string          `json:"panic_error"`
	StackTrace string          `json:"stack_trace,omitempty"`
	Entry      json.RawMessage `json:"entry"`
	RawLine    string          `json:"raw_line,omitempty"`
}

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

func (w *QuarantineWriter) Count() int64 {
	return w.count.Load()
}

func (w *QuarantineWriter) Enabled() bool {
	return w.enabled
}
