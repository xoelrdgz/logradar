package output

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/xoelrdgz/logradar/internal/domain"
)

type recordingAlerter struct {
	alerts []*domain.Alert
}

func (r *recordingAlerter) Send(_ context.Context, alert *domain.Alert) error {
	r.alerts = append(r.alerts, alert)
	return nil
}
func (r *recordingAlerter) Flush() error { return nil }
func (r *recordingAlerter) Close() error { return nil }

func TestDeduplicatingAlerterSuppressesDuplicatesUntilFlush(t *testing.T) {
	next := &recordingAlerter{}
	alerter := NewDeduplicatingAlerter(next, DedupConfig{Window: time.Minute})

	alert := domain.NewAlert(
		netip.MustParseAddr("192.0.2.10"),
		domain.ThreatTypeSQLInjection,
		domain.AlertLevelCritical,
		"GET /?id=1 HTTP/1.1",
		9,
		"same alert",
	)
	for i := 0; i < 3; i++ {
		if err := alerter.Send(context.Background(), alert); err != nil {
			t.Fatalf("Send() error = %v", err)
		}
	}

	if len(next.alerts) != 1 {
		t.Fatalf("sent alerts before flush = %d, want 1", len(next.alerts))
	}
	if err := alerter.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if len(next.alerts) != 2 {
		t.Fatalf("sent alerts after flush = %d, want first alert plus summary", len(next.alerts))
	}
	if got := next.alerts[1].Metadata["duplicate_count"]; got != "2" {
		t.Fatalf("duplicate_count = %q, want 2", got)
	}
	if next.alerts[0].Metadata["duplicate_count"] != "" {
		t.Fatal("original alert was mutated with dedup metadata")
	}
}

func TestDeduplicatingAlerterDoesNotGroupDifferentThreats(t *testing.T) {
	next := &recordingAlerter{}
	alerter := NewDeduplicatingAlerter(next, DedupConfig{Window: time.Minute})

	first := domain.NewAlert(netip.MustParseAddr("192.0.2.10"), domain.ThreatTypeSQLInjection, domain.AlertLevelCritical, "raw", 9, "alert")
	second := domain.NewAlert(netip.MustParseAddr("192.0.2.10"), domain.ThreatTypeXSS, domain.AlertLevelCritical, "raw", 9, "alert")

	if err := alerter.Send(context.Background(), first); err != nil {
		t.Fatalf("first Send() error = %v", err)
	}
	if err := alerter.Send(context.Background(), second); err != nil {
		t.Fatalf("second Send() error = %v", err)
	}
	if len(next.alerts) != 2 {
		t.Fatalf("sent alerts = %d, want 2", len(next.alerts))
	}
}

func TestDeduplicatingAlerterExpiresWindow(t *testing.T) {
	next := &recordingAlerter{}
	alerter := NewDeduplicatingAlerter(next, DedupConfig{Window: 5 * time.Millisecond})

	alert := domain.NewAlert(netip.MustParseAddr("192.0.2.10"), domain.ThreatTypeSQLInjection, domain.AlertLevelCritical, "raw", 9, "alert")
	if err := alerter.Send(context.Background(), alert); err != nil {
		t.Fatalf("first Send() error = %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := alerter.Send(context.Background(), alert); err != nil {
		t.Fatalf("second Send() error = %v", err)
	}

	if len(next.alerts) != 2 {
		t.Fatalf("sent alerts = %d, want 2 after dedup window expires", len(next.alerts))
	}
}
