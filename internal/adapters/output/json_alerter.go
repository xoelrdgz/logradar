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

type JSONAlerter struct {
	writer    io.Writer
	bufWriter *bufio.Writer
	file      *os.File
	pretty    bool
	mu        sync.Mutex
	encoder   *json.Encoder
	stopFlush chan struct{}
}

type JSONAlerterConfig struct {
	FilePath string
	Stdout   bool
	Pretty   bool
}

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

	go alerter.periodicFlush()

	return alerter, nil
}

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

func (a *JSONAlerter) Send(ctx context.Context, alert *domain.Alert) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.encoder.Encode(alert)
}

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

type MemoryAlerter struct {
	alerts    []*domain.Alert
	head      int
	count     int
	maxAlerts int
	mu        sync.RWMutex
}

func NewMemoryAlerter(maxAlerts int) *MemoryAlerter {
	if maxAlerts <= 0 {
		maxAlerts = 1000
	}
	return &MemoryAlerter{
		alerts:    make([]*domain.Alert, maxAlerts),
		maxAlerts: maxAlerts,
	}
}

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

func (a *MemoryAlerter) Flush() error {
	return nil
}

func (a *MemoryAlerter) Close() error {
	return nil
}

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

func (a *MemoryAlerter) Count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.count
}

func (a *MemoryAlerter) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.head = 0
	a.count = 0
	for i := range a.alerts {
		a.alerts[i] = nil
	}
}

func (a *MemoryAlerter) OnAlert(alert *domain.Alert) {
	_ = a.Send(context.Background(), alert)
}
