// Package input provides file tailing for LogRadar.
//
// FileTailer implements real-time log file tailing using nxadm/tail.
// Supports reading from end of file (default) or beginning for replay.
//
// Features:
//   - Real-time following with inotify (Linux) or polling (other OS)
//   - Automatic file reopening on rotation
//   - Line truncation for oversized entries (DoS protection)
//   - Graceful shutdown with context cancellation
//
// Thread Safety: Safe for concurrent Start/Stop calls via mutex protection.
package input

import (
	"context"
	"sync"

	"github.com/nxadm/tail"
	"github.com/rs/zerolog/log"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/internal/ports"
)

// FileTailer implements ports.LogReader for file-based log sources.
//
// Wraps the nxadm/tail library to provide:
//   - Real-time log following
//   - Log rotation handling
//   - Integration with LogRadar's parser interface
type FileTailer struct {
	filepath      string          // Path to log file
	parser        ports.LogParser // Parser for log format
	tail          *tail.Tail      // Underlying tail implementation
	bufferSize    int             // Output channel buffer size
	fromBeginning bool            // Start from beginning vs end
	mu            sync.Mutex      // Protects running state
	running       bool            // Active tailing flag
	stopChan      chan struct{}   // Shutdown signal
}

// NewFileTailer creates a file tailer starting from end of file.
//
// Parameters:
//   - filepath: Path to log file to tail
//   - parser: Parser for the log format (CLF, JSON, or Auto)
//   - bufferSize: Output channel buffer (default: 1000 if <= 0)
//
// Returns:
//   - Configured FileTailer ready for Start()
//
// Note: Starts from end of file. Use NewFileTailerFull for beginning.
func NewFileTailer(filepath string, parser ports.LogParser, bufferSize int) *FileTailer {
	if bufferSize <= 0 {
		bufferSize = 1000
	}
	return &FileTailer{
		filepath:      filepath,
		parser:        parser,
		bufferSize:    bufferSize,
		fromBeginning: false,
		stopChan:      make(chan struct{}),
	}
}

// NewFileTailerFull creates a file tailer starting from beginning of file.
//
// Parameters:
//   - filepath: Path to log file to tail
//   - parser: Parser for the log format
//   - bufferSize: Output channel buffer
//
// Returns:
//   - Configured FileTailer that reads entire file history
//
// Use Case: Historical log analysis or replay scenarios.
func NewFileTailerFull(filepath string, parser ports.LogParser, bufferSize int) *FileTailer {
	t := NewFileTailer(filepath, parser, bufferSize)
	t.fromBeginning = true
	return t
}

// SetFromBeginning configures whether to start from file beginning.
//
// Parameters:
//   - fromBeginning: true to read from start, false for end
//
// Note: Must be called before Start().
func (t *FileTailer) SetFromBeginning(fromBeginning bool) {
	t.fromBeginning = fromBeginning
}

// Start begins tailing the log file and returns output channels.
//
// Parameters:
//   - ctx: Context for lifecycle management
//
// Returns:
//   - Entry channel: Parsed log entries (closed on stop)
//   - Error channel: Parse and I/O errors (closed on stop)
//
// Behavior:
//   - Spawns background goroutine for tailing
//   - Truncates lines exceeding MaxLineLength (DoS protection)
//   - Continues on parse errors (logs debug message)
//   - Idempotent: returns closed channels if already running
//
// Stop Conditions:
//   - Context cancellation
//   - Stop() called
//   - File descriptor error
func (t *FileTailer) Start(ctx context.Context) (<-chan *domain.LogEntry, <-chan error) {
	entryChan := make(chan *domain.LogEntry, t.bufferSize)
	errChan := make(chan error, 10)

	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		close(entryChan)
		return entryChan, errChan
	}
	t.running = true
	t.stopChan = make(chan struct{})
	t.mu.Unlock()

	go func() {
		defer close(entryChan)
		defer close(errChan)

		// Configure seek position
		whence := 2 // End of file
		if t.fromBeginning {
			whence = 0 // Beginning of file
		}

		config := tail.Config{
			Follow:    true,  // Follow file changes
			ReOpen:    true,  // Reopen on rotation
			MustExist: false, // Create if not exists
			Poll:      false, // Use inotify when available
			Location:  &tail.SeekInfo{Offset: 0, Whence: whence},
		}

		var err error
		t.tail, err = tail.TailFile(t.filepath, config)
		if err != nil {
			log.Error().Err(err).Str("file", t.filepath).Msg("Failed to tail file")
			errChan <- err
			return
		}

		log.Info().Str("file", t.filepath).Msg("Started tailing log file")

		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("Context cancelled, stopping tailer")
				return
			case <-t.stopChan:
				log.Info().Msg("Stop signal received, stopping tailer")
				return
			case line, ok := <-t.tail.Lines:
				if !ok {
					log.Info().Msg("Tail channel closed")
					return
				}
				if line.Err != nil {
					log.Warn().Err(line.Err).Msg("Error reading line")
					errChan <- line.Err
					continue
				}
				if line.Text == "" {
					continue
				}

				// Truncate oversized lines (DoS protection)
				lineText := line.Text
				wasTruncated := false
				if len(lineText) > domain.MaxLineLength {
					lineText = lineText[:domain.MaxLineLength]
					wasTruncated = true
					log.Warn().
						Int("original_size", len(line.Text)).
						Int("truncated_to", domain.MaxLineLength).
						Msg("Truncated oversized log entry (potential DoS payload)")
				}

				// Parse the line
				entry, err := t.parser.Parse(lineText)
				if err != nil {
					log.Debug().Err(err).Str("line", lineText).Msg("Failed to parse log line")
					continue
				}

				if wasTruncated {
					entry.Truncated = true
				}

				// Send to output channel
				select {
				case entryChan <- entry:
				case <-ctx.Done():
					return
				case <-t.stopChan:
					return
				}
			}
		}
	}()

	return entryChan, errChan
}

// Stop terminates log tailing and closes output channels.
//
// Returns:
//   - nil on success
//   - Error from underlying tail library if cleanup fails
//
// Thread Safety: Safe to call concurrently or multiple times (idempotent).
func (t *FileTailer) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return nil
	}

	close(t.stopChan)
	t.running = false

	if t.tail != nil {
		return t.tail.Stop()
	}
	return nil
}

// IsRunning returns true if the tailer is actively reading.
func (t *FileTailer) IsRunning() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}
