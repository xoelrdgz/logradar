package output

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/xoelrdgz/logradar/internal/domain"
)

type DedupConfig struct {
	Enabled bool
	Window  time.Duration
}

type DeduplicatingAlerter struct {
	next   AlerterLike
	window time.Duration

	mu      sync.Mutex
	pending map[string]*dedupGroup
}

type AlerterLike interface {
	Send(context.Context, *domain.Alert) error
	Flush() error
	Close() error
}

type dedupGroup struct {
	alert     *domain.Alert
	count     int
	firstSeen time.Time
	lastSeen  time.Time
}

func NewDeduplicatingAlerter(next AlerterLike, config DedupConfig) *DeduplicatingAlerter {
	window := config.Window
	if window <= 0 {
		window = time.Minute
	}
	return &DeduplicatingAlerter{
		next:    next,
		window:  window,
		pending: make(map[string]*dedupGroup),
	}
}

func (a *DeduplicatingAlerter) Send(ctx context.Context, alert *domain.Alert) error {
	if alert == nil {
		return nil
	}

	now := time.Now()
	key := dedupKey(alert)

	a.mu.Lock()
	group, exists := a.pending[key]
	if !exists {
		a.pending[key] = &dedupGroup{
			alert:     cloneAlert(alert),
			count:     1,
			firstSeen: now,
			lastSeen:  now,
		}
		a.mu.Unlock()
		return a.next.Send(ctx, alert)
	}

	if now.Sub(group.firstSeen) <= a.window {
		group.count++
		group.lastSeen = now
		a.mu.Unlock()
		return nil
	}

	summary := group.summary()
	a.pending[key] = &dedupGroup{
		alert:     cloneAlert(alert),
		count:     1,
		firstSeen: now,
		lastSeen:  now,
	}
	a.mu.Unlock()

	if summary != nil {
		if err := a.next.Send(ctx, summary); err != nil {
			return err
		}
	}
	return a.next.Send(ctx, alert)
}

func (a *DeduplicatingAlerter) Flush() error {
	if err := a.flushSummaries(context.Background()); err != nil {
		return err
	}
	return a.next.Flush()
}

func (a *DeduplicatingAlerter) Close() error {
	if err := a.flushSummaries(context.Background()); err != nil {
		return err
	}
	return a.next.Close()
}

func (a *DeduplicatingAlerter) flushSummaries(ctx context.Context) error {
	a.mu.Lock()
	var summaries []*domain.Alert
	for key, group := range a.pending {
		if summary := group.summary(); summary != nil {
			summaries = append(summaries, summary)
		}
		delete(a.pending, key)
	}
	a.mu.Unlock()

	for _, summary := range summaries {
		if err := a.next.Send(ctx, summary); err != nil {
			return err
		}
	}
	return nil
}

func (g *dedupGroup) summary() *domain.Alert {
	if g == nil || g.count <= 1 {
		return nil
	}
	alert := cloneAlert(g.alert)
	alert.AddMetadata("duplicate_count", fmt.Sprintf("%d", g.count-1))
	alert.AddMetadata("aggregate_count", fmt.Sprintf("%d", g.count))
	alert.AddMetadata("aggregate_first_seen", g.firstSeen.UTC().Format(time.RFC3339Nano))
	alert.AddMetadata("aggregate_last_seen", g.lastSeen.UTC().Format(time.RFC3339Nano))
	alert.Message = fmt.Sprintf("%s (suppressed %d duplicate alerts)", alert.Message, g.count-1)
	return alert
}

func dedupKey(alert *domain.Alert) string {
	return fmt.Sprintf("%s|%s|%s|%s", alert.IPString(), alert.ThreatType, alert.Level, alert.Message)
}

func cloneAlert(alert *domain.Alert) *domain.Alert {
	if alert == nil {
		return nil
	}
	clone := *alert
	if alert.Metadata != nil {
		clone.Metadata = make(map[string]string, len(alert.Metadata))
		for key, value := range alert.Metadata {
			clone.Metadata[key] = value
		}
	}
	return &clone
}
