package tui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xoelrdgz/logradar/internal/domain"
)

func TestAppProcessesBatchedAlertsInChunks(t *testing.T) {
	app := NewApp()
	app.model.MaxAlerts = 100

	for i := 0; i < maxAlertsPerTick+10; i++ {
		app.OnAlert(makeAlert(t, "192.0.2.10", domain.ThreatTypeXSS))
	}

	app.processBatchedAlerts()
	if got := len(app.model.GetAlerts()); got != maxAlertsPerTick {
		t.Fatalf("processed alerts = %d, want %d", got, maxAlertsPerTick)
	}
	if got := len(app.alertBuffer); got != 10 {
		t.Fatalf("remaining buffered alerts = %d, want 10", got)
	}

	app.processBatchedAlerts()
	if got := len(app.model.GetAlerts()); got != maxAlertsPerTick+10 {
		t.Fatalf("processed alerts after second tick = %d, want %d", got, maxAlertsPerTick+10)
	}
}

func TestAppPauseDefersBufferedAlerts(t *testing.T) {
	app := NewApp()
	app.OnAlert(makeAlert(t, "192.0.2.10", domain.ThreatTypeXSS))
	app.model.TogglePause()

	app.processBatchedAlerts()
	if got := len(app.model.GetAlerts()); got != 0 {
		t.Fatalf("processed alerts while paused = %d, want 0", got)
	}
	app.model.TogglePause()
	app.processBatchedAlerts()
	if got := len(app.model.GetAlerts()); got != 1 {
		t.Fatalf("processed alerts after resume = %d, want 1", got)
	}
}

func TestAppExportsSelectedAlert(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}

	app := NewApp()
	alert := makeAlert(t, "192.0.2.10", domain.ThreatTypeXSS)
	app.model.AddAlert(alert)
	app.alerts.Update(app.model.GetAlerts())
	app.alerts.SelectLast()
	app.exportSelectedAlert()

	if _, err := os.Stat(filepath.Join(dir, "output", "selected-alert.json")); err != nil {
		t.Fatalf("exported alert not found: %v", err)
	}
}

func TestAppDropsOldestBufferedAlertsWhenBufferIsFull(t *testing.T) {
	app := NewApp()
	app.maxAlertBuffer = 10

	for i := 0; i < 12; i++ {
		app.OnAlert(makeAlert(t, "192.0.2.10", domain.ThreatTypeXSS))
	}

	if got := app.DroppedAlerts(); got != 2 {
		t.Fatalf("DroppedAlerts() = %d, want 2", got)
	}
	if got := len(app.alertBuffer); got != 10 {
		t.Fatalf("len(alertBuffer) = %d, want 10", got)
	}
}
