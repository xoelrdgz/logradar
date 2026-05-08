package input

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStreamReaderReadsUntilEOF(t *testing.T) {
	parser := NewCombinedLogParser()
	source := strings.NewReader(`192.0.2.10 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "Mozilla/5.0"` + "\n")
	reader := NewStreamReader("test", source, parser, 2)

	entries, errs := reader.Start(context.Background())

	select {
	case entry, ok := <-entries:
		if !ok {
			t.Fatal("entries closed before entry")
		}
		if entry.Path != "/" {
			t.Fatalf("Path = %q, want /", entry.Path)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for entry")
	}
	if err, ok := <-errs; ok {
		t.Fatalf("unexpected error from stream reader: %v", err)
	}
	if _, ok := <-entries; ok {
		t.Fatal("entries still open after EOF")
	}
	if !reader.ExpectedEOF() {
		t.Fatal("ExpectedEOF = false, want true")
	}
}

func TestStreamReaderReportsParseErrors(t *testing.T) {
	parser := NewCombinedLogParser()
	reader := NewStreamReader("test", strings.NewReader("not a combined log\n"), parser, 2)

	_, errs := reader.Start(context.Background())

	select {
	case err, ok := <-errs:
		if !ok {
			t.Fatal("errs closed before parse error")
		}
		if err == nil {
			t.Fatal("err = nil, want parse error")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for parse error")
	}
}
