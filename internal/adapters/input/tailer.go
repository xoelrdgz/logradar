package input

import (
	"context"
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
	mu            sync.Mutex
	running       bool
	stopChan      chan struct{}
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

		whence := 2
		if t.fromBeginning {
			whence = 0
		}

		config := tail.Config{
			Follow:    true,
			ReOpen:    true,
			MustExist: false,
			Poll:      false,
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
