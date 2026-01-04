// Package ports defines input source interfaces.
//
// LogReader and LogParser define the contract for log ingestion.
// Implementations handle various log sources and formats.
package ports

import (
	"context"

	"github.com/xoelrdgz/logradar/internal/domain"
)

// LogReader defines the interface for log entry sources.
//
// Implementations:
//   - FileTailer: Real-time file tailing (production)
//   - DemoGenerator: Synthetic traffic generation (testing/demo)
//   - (External: Kafka consumer, Syslog receiver, etc.)
//
// Thread Safety: Start() returns channels that are written by an internal
// goroutine. Safe for single consumer on returned channels.
type LogReader interface {
	// Start begins reading log entries and returns output channels.
	//
	// Parameters:
	//   - ctx: Context for cancellation (stops reading when cancelled)
	//
	// Returns:
	//   - Entry channel: Parsed log entries (closed when reading stops)
	//   - Error channel: Parse errors and I/O errors (closed when reading stops)
	//
	// Contract:
	//   - Channels are closed when context is cancelled or Stop() is called
	//   - Entry channel is buffered (implementation-defined size)
	//   - Errors are non-fatal; reading continues after errors
	Start(ctx context.Context) (<-chan *domain.LogEntry, <-chan error)

	// Stop terminates log reading and closes output channels.
	//
	// Returns:
	//   - nil on success
	//   - Error if stop fails (resources may leak)
	//
	// Contract:
	//   - Idempotent (safe to call multiple times)
	//   - Blocks until internal goroutines terminate
	Stop() error
}

// LogParser defines the interface for parsing raw log lines into LogEntry.
//
// Implementations:
//   - CombinedLogParser: Apache/Nginx Combined Log Format
//   - JSONParser: Structured JSON log format
//   - AutoDetectParser: Auto-detects format and delegates
//
// Thread Safety: Implementations MUST be safe for concurrent Parse() calls.
// The same parser instance may be used across multiple reader goroutines.
type LogParser interface {
	// Parse converts a raw log line into a structured LogEntry.
	//
	// Parameters:
	//   - line: Raw log line (may be truncated to MaxLineLength)
	//
	// Returns:
	//   - LogEntry acquired from pool (caller must release)
	//   - Error if parsing fails
	//
	// Contract:
	//   - Thread-safe
	//   - Returns pooled LogEntry (use domain.ReleaseLogEntry after processing)
	//   - Sets Truncated flag if line exceeded MaxLineLength
	Parse(line string) (*domain.LogEntry, error)

	// Format returns the parser's format identifier for logging.
	// Examples: "combined", "json", "auto"
	Format() string
}
