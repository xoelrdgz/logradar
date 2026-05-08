package output

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/pkg/sanitize"
)

type JSONAlerter struct {
	writer        io.Writer
	bufWriter     *bufio.Writer
	file          *os.File
	pretty        bool
	redact        bool
	includeRawLog bool
	maxAlertBytes int
	mu            sync.Mutex
	encoder       *json.Encoder
	stopFlush     chan struct{}
	closeOnce     sync.Once
	closeErr      error
}

type JSONAlerterConfig struct {
	FilePath      string
	Stdout        bool
	Pretty        bool
	Redact        bool
	IncludeRawLog bool
	MaxAlertBytes int
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
		writer:        writer,
		bufWriter:     bufWriter,
		file:          file,
		pretty:        config.Pretty,
		redact:        config.Redact,
		includeRawLog: config.IncludeRawLog,
		maxAlertBytes: config.MaxAlertBytes,
		stopFlush:     make(chan struct{}),
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

	if a.redact {
		alert = redactAlert(alert)
	}
	if !a.includeRawLog {
		alert = stripRawLog(alert)
	}
	if a.maxAlertBytes > 0 {
		payload, err := marshalAlert(alert, a.pretty)
		if err != nil {
			return err
		}
		if len(payload) > a.maxAlertBytes {
			return fmt.Errorf("encoded alert size %d exceeds output.json.max_alert_bytes %d", len(payload), a.maxAlertBytes)
		}
		_, err = a.bufWriter.Write(append(payload, '\n'))
		return err
	}

	return a.encoder.Encode(alert)
}

func marshalAlert(alert *domain.Alert, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(alert, "", "  ")
	}
	return json.Marshal(alert)
}

func redactAlert(alert *domain.Alert) *domain.Alert {
	if alert == nil {
		return nil
	}

	redacted := *alert
	redacted.RawLog = sanitize.RedactSensitive(redacted.RawLog)
	redacted.Evidence.Fragment = sanitize.RedactSensitive(redacted.Evidence.Fragment)
	if alert.Metadata != nil {
		redacted.Metadata = make(map[string]string, len(alert.Metadata))
		for key, value := range alert.Metadata {
			redacted.Metadata[key] = sanitize.RedactSensitive(value)
		}
	}
	return &redacted
}

func stripRawLog(alert *domain.Alert) *domain.Alert {
	if alert == nil {
		return nil
	}
	stripped := *alert
	stripped.RawLog = ""
	return &stripped
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
	a.closeOnce.Do(func() {
		close(a.stopFlush)

		a.mu.Lock()
		defer a.mu.Unlock()

		if a.bufWriter != nil {
			if err := a.bufWriter.Flush(); err != nil {
				a.closeErr = err
				return
			}
		}

		if a.file != nil {
			if err := a.file.Sync(); err != nil {
				a.closeErr = err
				return
			}
			a.closeErr = a.file.Close()
		}
	})
	return a.closeErr
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
