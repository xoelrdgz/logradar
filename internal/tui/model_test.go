package tui

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/xoelrdgz/logradar/internal/domain"
)

func makeAlert(t *testing.T, ip string, threat domain.ThreatType) *domain.Alert {
	t.Helper()
	return domain.NewAlert(
		netip.MustParseAddr(ip),
		threat,
		domain.AlertLevelWarning,
		"GET / HTTP/1.1",
		5,
		"test alert",
	)
}

func TestModelAddAlertKeepsNewestWithinLimit(t *testing.T) {
	model := NewModel()
	model.MaxAlerts = 3

	for i := 0; i < 5; i++ {
		alert := makeAlert(t, fmt.Sprintf("192.0.2.%d", i+1), domain.ThreatTypeXSS)
		alert.Message = fmt.Sprintf("alert-%d", i+1)
		model.AddAlert(alert)
	}

	alerts := model.GetAlerts()
	if len(alerts) != 3 {
		t.Fatalf("len(alerts) = %d, want 3", len(alerts))
	}
	if alerts[0].Message != "alert-3" || alerts[2].Message != "alert-5" {
		t.Fatalf("alerts = [%s, %s, %s], want newest three in order", alerts[0].Message, alerts[1].Message, alerts[2].Message)
	}
}

func TestModelTopIPsAreSortedAndThreatTypesAreBounded(t *testing.T) {
	model := NewModel()
	model.MaxTopIPs = 2

	for i := 0; i < 3; i++ {
		model.IncrementIPCounter(makeAlert(t, "192.0.2.10", domain.ThreatTypeSQLInjection))
	}
	for i := 0; i < 2; i++ {
		model.IncrementIPCounter(makeAlert(t, "192.0.2.20", domain.ThreatTypeXSS))
	}
	model.IncrementIPCounter(makeAlert(t, "192.0.2.30", domain.ThreatTypeRCE))

	for _, threat := range []domain.ThreatType{
		domain.ThreatTypeXSS,
		domain.ThreatTypePathTraversal,
		domain.ThreatTypeRCE,
		domain.ThreatTypeLFI,
		domain.ThreatTypeLog4Shell,
		domain.ThreatTypeMaliciousIP,
	} {
		model.IncrementIPCounter(makeAlert(t, "192.0.2.10", threat))
	}

	top := model.GetTopIPs()
	if len(top) != 2 {
		t.Fatalf("len(top) = %d, want 2", len(top))
	}
	if top[0].IP != "192.0.2.10" || top[0].AlertCount != 9 {
		t.Fatalf("top[0] = %+v, want 192.0.2.10 with 9 alerts", top[0])
	}
	if top[1].IP != "192.0.2.20" || top[1].AlertCount != 2 {
		t.Fatalf("top[1] = %+v, want 192.0.2.20 with 2 alerts", top[1])
	}
	if len(top[0].ThreatTypes) != 5 {
		t.Fatalf("len(top[0].ThreatTypes) = %d, want capped at 5", len(top[0].ThreatTypes))
	}
}

func TestModelUpdateMetricsShiftsSparkline(t *testing.T) {
	model := NewModel()
	initialLen := len(model.GetSparkline())

	model.UpdateMetrics(domain.MetricsSnapshot{LinesPerSecond: 42})

	sparkline := model.GetSparkline()
	if len(sparkline) != initialLen {
		t.Fatalf("len(sparkline) = %d, want %d", len(sparkline), initialLen)
	}
	if got := sparkline[len(sparkline)-1]; got != 42 {
		t.Fatalf("last sparkline value = %v, want 42", got)
	}
}

func TestModelFiltersAlerts(t *testing.T) {
	model := NewModel()
	critical := makeAlert(t, "192.0.2.10", domain.ThreatTypeSQLInjection)
	critical.Level = domain.AlertLevelCritical
	critical.RuleID = "signature.sqli.union"
	warning := makeAlert(t, "192.0.2.20", domain.ThreatTypeXSS)
	warning.Level = domain.AlertLevelWarning
	warning.RuleID = "signature.xss"
	model.AddAlert(critical)
	model.AddAlert(warning)

	model.CycleSeverityFilter()
	alerts := model.GetAlerts()
	if len(alerts) != 1 || alerts[0].RuleID != "signature.sqli.union" {
		t.Fatalf("severity filtered alerts = %#v, want critical only", alerts)
	}

	model.ClearFilters()
	model.SetSearch("xss")
	alerts = model.GetAlerts()
	if len(alerts) != 1 || alerts[0].RuleID != "signature.xss" {
		t.Fatalf("search filtered alerts = %#v, want xss only", alerts)
	}
}
