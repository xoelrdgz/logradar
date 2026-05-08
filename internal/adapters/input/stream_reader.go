package input

import (
	"bufio"
	"context"
	"io"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/internal/ports"
)

type StreamReader struct {
	name       string
	reader     io.Reader
	parser     ports.LogParser
	bufferSize int

	mu       sync.Mutex
	running  bool
	stopChan chan struct{}
}

func NewStreamReader(name string, reader io.Reader, parser ports.LogParser, bufferSize int) *StreamReader {
	if bufferSize <= 0 {
		bufferSize = 1000
	}
	return &StreamReader{
		name:       name,
		reader:     reader,
		parser:     parser,
		bufferSize: bufferSize,
		stopChan:   make(chan struct{}),
	}
}

func (r *StreamReader) ExpectedEOF() bool {
	return true
}

func (r *StreamReader) Start(ctx context.Context) (<-chan *domain.LogEntry, <-chan error) {
	entryChan := make(chan *domain.LogEntry, r.bufferSize)
	errChan := make(chan error, 10)

	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		close(entryChan)
		close(errChan)
		return entryChan, errChan
	}
	r.running = true
	r.stopChan = make(chan struct{})
	r.mu.Unlock()

	go func() {
		defer close(entryChan)
		defer close(errChan)
		defer func() {
			r.mu.Lock()
			r.running = false
			r.mu.Unlock()
		}()

		scanner := bufio.NewScanner(r.reader)
		scanner.Buffer(make([]byte, 0, 64*1024), domain.MaxLineLength*2)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			case <-r.stopChan:
				return
			default:
			}

			lineText := scanner.Text()
			if lineText == "" {
				continue
			}
			wasTruncated := false
			if len(lineText) > domain.MaxLineLength {
				lineText = lineText[:domain.MaxLineLength]
				wasTruncated = true
				log.Warn().
					Str("source", r.name).
					Int("truncated_to", domain.MaxLineLength).
					Msg("Truncated oversized log entry from stream")
			}

			entry, err := r.parser.Parse(lineText)
			if err != nil {
				errChan <- err
				continue
			}
			if wasTruncated {
				entry.Truncated = true
			}

			select {
			case entryChan <- entry:
			case <-ctx.Done():
				return
			case <-r.stopChan:
				return
			}
		}
		if err := scanner.Err(); err != nil {
			errChan <- err
		}
	}()

	return entryChan, errChan
}

func (r *StreamReader) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		return nil
	}
	close(r.stopChan)
	r.running = false
	return nil
}
