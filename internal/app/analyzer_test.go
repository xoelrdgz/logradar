package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/internal/ports"
)

type closingReader struct {
	entries     chan *domain.LogEntry
	errs        chan error
	expectedEOF bool
}

func newClosingReader() *closingReader {
	return &closingReader{
		entries: make(chan *domain.LogEntry),
		errs:    make(chan error),
	}
}

func (r *closingReader) Start(ctx context.Context) (<-chan *domain.LogEntry, <-chan error) {
	return r.entries, r.errs
}

func (r *closingReader) Stop() error {
	closeIfOpen(r.entries)
	closeIfOpen(r.errs)
	return nil
}

func (r *closingReader) ExpectedEOF() bool {
	return r.expectedEOF
}

func closeIfOpen[T any](ch chan T) {
	defer func() { _ = recover() }()
	close(ch)
}

func TestAnalyzerReportsUnexpectedReaderStop(t *testing.T) {
	reader := newClosingReader()
	analyzer := NewAnalyzer(reader, []ports.ThreatDetector{&mockDetector{}}, []ports.Alerter{&mockAlerter{}})

	if err := analyzer.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	close(reader.entries)

	select {
	case <-analyzer.Done():
	case <-time.After(time.Second):
		t.Fatal("analyzer did not report completion")
	}

	err := analyzer.Err()
	if err == nil {
		t.Fatal("Err() = nil, want fatal reader error")
	}
	if !strings.Contains(err.Error(), "log reader stopped unexpectedly") {
		t.Fatalf("Err() = %q, want unexpected reader stop", err)
	}
	analyzer.Stop()
}

func TestAnalyzerAllowsExpectedReaderEOF(t *testing.T) {
	reader := newClosingReader()
	reader.expectedEOF = true
	analyzer := NewAnalyzer(reader, []ports.ThreatDetector{&mockDetector{}}, []ports.Alerter{&mockAlerter{}})

	if err := analyzer.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	close(reader.entries)

	select {
	case <-analyzer.Done():
	case <-time.After(time.Second):
		t.Fatal("analyzer did not report completion")
	}
	if err := analyzer.Err(); err != nil {
		t.Fatalf("Err() = %v, want nil for expected EOF", err)
	}
	analyzer.Stop()
}
