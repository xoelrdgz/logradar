package input

import (
	"context"
	"io"
	"sync"

	"github.com/nxadm/tail"
	"github.com/rs/zerolog/log"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/internal/ports"
)

type FileTailer struct {
	filepath      string
	parser        ports.LogParser
	tail          *tail.Tail
	bufferSize    int
	fromBeginning bool
	checkpoint    CheckpointConfig
	mu            sync.Mutex
	running       bool
	stopChan      chan struct{}
}

type CheckpointConfig struct {
	Enabled bool
	Path    string
}

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

func NewFileTailerFull(filepath string, parser ports.LogParser, bufferSize int) *FileTailer {
	t := NewFileTailer(filepath, parser, bufferSize)
	t.fromBeginning = true
	return t
}

func (t *FileTailer) SetFromBeginning(fromBeginning bool) {
	t.fromBeginning = fromBeginning
}

func (t *FileTailer) SetCheckpoint(config CheckpointConfig) {
	t.checkpoint = config
}

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

		location := &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd}
		if t.fromBeginning {
			location = &tail.SeekInfo{Offset: 0, Whence: io.SeekStart}
		} else if t.checkpoint.Enabled && t.checkpoint.Path != "" {
			state, err := loadCheckpoint(t.checkpoint.Path)
			if err != nil {
				log.Warn().Err(err).Str("path", t.checkpoint.Path).Msg("Failed to load tailer checkpoint")
			} else if offset, ok := checkpointOffsetForFile(t.filepath, state); ok {
				location = &tail.SeekInfo{Offset: offset, Whence: io.SeekStart}
				log.Info().
					Str("file", t.filepath).
					Str("checkpoint", t.checkpoint.Path).
					Int64("offset", offset).
					Msg("Resuming log tailer from checkpoint")
			}
		}

		config := tail.Config{
			Follow:    true,
			ReOpen:    true,
			MustExist: false,
			Poll:      false,
			Location:  location,
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

				entry, err := t.parser.Parse(lineText)
				if err != nil {
					log.Debug().Err(err).Str("line", lineText).Msg("Failed to parse log line")
					continue
				}

				if wasTruncated {
					entry.Truncated = true
				}

				select {
				case entryChan <- entry:
					t.saveCheckpoint(line.SeekInfo.Offset, lineText)
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

func (t *FileTailer) saveCheckpoint(lineOffset int64, lineText string) {
	if !t.checkpoint.Enabled || t.checkpoint.Path == "" || lineOffset < 0 {
		return
	}

	nextOffset := lineOffset + int64(len(lineText)) + 1
	state, err := checkpointForFile(t.filepath, nextOffset)
	if err != nil {
		log.Debug().Err(err).Str("file", t.filepath).Msg("Unable to build tailer checkpoint")
		return
	}
	if err := saveCheckpoint(t.checkpoint.Path, state); err != nil {
		log.Warn().Err(err).Str("path", t.checkpoint.Path).Msg("Failed to save tailer checkpoint")
	}
}

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

func (t *FileTailer) IsRunning() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}
