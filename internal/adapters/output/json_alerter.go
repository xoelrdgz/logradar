// Package output provides alert output adapters for LogRadar.
//
// This file implements alert destinations:
//   - JSONAlerter: Buffered JSON output to file or stdout
//   - MemoryAlerter: In-memory ring buffer for TUI display
//
// Features:
//   - Buffered I/O for high throughput (64KB buffer)
//   - Periodic automatic flushing (1 second)
//   - File sync on flush for durability
//   - Ring buffer for memory-bounded storage
//
// Thread Safety: All implementations are safe for concurrent Send() calls.
package output

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"

	"github.com/xoelrdgz/logradar/internal/domain"
)

// JSONAlerter writes alerts as JSON to file or stdout.
//
// Features:
//   - Buffered writes for high throughput
//   - Periodic flush every second
//   - Optional pretty-printing
//   - File sync on flush for durability
type JSONAlerter struct {
	writer    io.Writer     // Output destination
	bufWriter *bufio.Writer // Buffered writer (64KB)
	file      *os.File      // File handle (nil for stdout)
	pretty    bool          // Pretty-print JSON flag
	mu        sync.Mutex    // Protects writes
	encoder   *json.Encoder // Reused encoder
	stopFlush chan struct{} // Stop periodic flush
}

// JSONAlerterConfig configures JSON alert output.
type JSONAlerterConfig struct {
	FilePath string // Output file path (empty for discard)
	Stdout   bool   // Write to stdout
	Pretty   bool   // Pretty-print JSON
}

// NewJSONAlerter creates a JSON alert output.
//
// Parameters:
//   - config: Output destination and format settings
//
// Returns:
//   - Configured JSONAlerter
//   - Error if file creation fails
//
// Output Priority:
//  1. Stdout if config.Stdout is true
//  2. File if config.FilePath is set
//  3. io.Discard otherwise
//
// File Permissions: 0600 (owner read/write only)
func NewJSONAlerter(config JSONAlerterConfig) (*JSONAlerter, error) {
	var writer io.Writer
	var file *os.File

	if config.Stdout {
		writer = os.Stdout
	} else if config.FilePath != "" {
		var err error
		file, err = os.OpenFile(config.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, err
		}
		writer = file
	} else {
		writer = io.Discard
	}

	const bufferSize = 64 * 1024
	bufWriter := bufio.NewWriterSize(writer, bufferSize)

	alerter := &JSONAlerter{
		writer:    writer,
		bufWriter: bufWriter,
		file:      file,
		pretty:    config.Pretty,
		stopFlush: make(chan struct{}),
	}

	alerter.encoder = json.NewEncoder(bufWriter)
	if config.Pretty {
		alerter.encoder.SetIndent("", "  ")
	}

	// Start periodic flush goroutine
	go alerter.periodicFlush()

	return alerter, nil
}

// periodicFlush flushes the buffer every second.
// Runs in background until Close() is called.
func (a *JSONAlerter) periodicFlush() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.Flush()
		case <-a.stopFlush:
			return
		}
	}
}

// Send writes an alert as JSON to the output.
//
// Parameters:
//   - ctx: Context (not used, for interface compliance)
//   - alert: Alert to serialize and write
//
// Returns:
//   - nil on success
//   - Error if JSON encoding or write fails
//
// Thread Safety: Safe for concurrent calls via mutex.
func (a *JSONAlerter) Send(ctx context.Context, alert *domain.Alert) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.encoder.Encode(alert)
}

// Flush forces buffered data to disk.
//
// Returns:
//   - nil on success
//   - Error if flush or sync fails
//
// Thread Safety: Safe for concurrent calls.
func (a *JSONAlerter) Flush() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.bufWriter != nil {
		if err := a.bufWriter.Flush(); err != nil {
			return err
		}
	}

	if a.file != nil {
		return a.file.Sync()
	}
	return nil
}

// Close stops periodic flushing and closes the file.
//
// Returns:
//   - nil on success
//   - Error if flush or close fails
//
// Behavior:
//   - Stops periodic flush goroutine
//   - Flushes remaining buffer
//   - Syncs and closes file
func (a *JSONAlerter) Close() error {
	close(a.stopFlush)

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.bufWriter != nil {
		if err := a.bufWriter.Flush(); err != nil {
			return err
		}
	}

	if a.file != nil {
		if err := a.file.Sync(); err != nil {
			return err
		}
		return a.file.Close()
	}
	return nil
}

// MemoryAlerter stores alerts in a fixed-size ring buffer.
//
// Used for TUI display to maintain bounded memory while providing
// access to recent alerts.
//
// Thread Safety: Safe for concurrent access via RWMutex.
type MemoryAlerter struct {
	alerts    []*domain.Alert // Ring buffer storage
	head      int             // Next write position
	count     int             // Current alert count
	maxAlerts int             // Buffer capacity
	mu        sync.RWMutex    // Protects all fields
}

// NewMemoryAlerter creates an in-memory alert buffer.
//
// Parameters:
//   - maxAlerts: Maximum alerts to store (default: 1000 if <= 0)
//
// Returns:
//   - Configured MemoryAlerter ready for Send()
func NewMemoryAlerter(maxAlerts int) *MemoryAlerter {
	if maxAlerts <= 0 {
		maxAlerts = 1000
	}
	return &MemoryAlerter{
		alerts:    make([]*domain.Alert, maxAlerts),
		maxAlerts: maxAlerts,
	}
}

// Send stores an alert in the ring buffer.
//
// Parameters:
//   - ctx: Context (not used, for interface compliance)
//   - alert: Alert to store
//
// Returns:
//   - Always nil (memory operations don't fail)
//
// Behavior: Overwrites oldest alert when buffer is full.
func (a *MemoryAlerter) Send(ctx context.Context, alert *domain.Alert) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.alerts[a.head] = alert
	a.head = (a.head + 1) % a.maxAlerts
	if a.count < a.maxAlerts {
		a.count++
	}

	return nil
}

// Flush is a no-op for memory alerter (required by interface).
func (a *MemoryAlerter) Flush() error {
	return nil
}

// Close is a no-op for memory alerter (required by interface).
func (a *MemoryAlerter) Close() error {
	return nil
}

// GetAlerts returns all stored alerts in chronological order.
//
// Returns:
//   - Copy of all alerts (oldest first)
//
// Thread Safety: Safe for concurrent access.
func (a *MemoryAlerter) GetAlerts() []*domain.Alert {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]*domain.Alert, a.count)
	if a.count == 0 {
		return result
	}

	start := 0
	if a.count == a.maxAlerts {
		start = a.head
	}

	for i := 0; i < a.count; i++ {
		idx := (start + i) % a.maxAlerts
		result[i] = a.alerts[idx]
	}
	return result
}

// GetLatestAlerts returns the N most recent alerts.
//
// Parameters:
//   - n: Number of alerts to return (capped at count)
//
// Returns:
//   - Copy of most recent alerts (oldest first within slice)
//
// Thread Safety: Safe for concurrent access.
func (a *MemoryAlerter) GetLatestAlerts(n int) []*domain.Alert {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if n <= 0 || n > a.count {
		n = a.count
	}
	if n == 0 {
		return []*domain.Alert{}
	}

	result := make([]*domain.Alert, n)

	for i := 0; i < n; i++ {
		idx := (a.head - n + i + a.maxAlerts) % a.maxAlerts
		result[i] = a.alerts[idx]
	}
	return result
}

// Count returns the current number of stored alerts.
func (a *MemoryAlerter) Count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.count
}

// Clear removes all stored alerts.
func (a *MemoryAlerter) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.head = 0
	a.count = 0
	for i := range a.alerts {
		a.alerts[i] = nil
	}
}

// OnAlert implements ports.AlertSubscriber interface.
// Delegates to Send() for TUI integration.
func (a *MemoryAlerter) OnAlert(alert *domain.Alert) {
	_ = a.Send(context.Background(), alert)
}
