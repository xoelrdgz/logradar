package domain

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAlert(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.1")
	alert := NewAlert(ip, ThreatTypeSQLInjection, AlertLevelCritical, "test log", 9, "SQL Injection detected")

	assert.NotEmpty(t, alert.ID)
	assert.Equal(t, ip.String(), alert.SourceIP.String())
	assert.Equal(t, ThreatTypeSQLInjection, alert.ThreatType)
	assert.Equal(t, AlertLevelCritical, alert.Level)
	assert.Equal(t, "test log", alert.RawLog)
	assert.Equal(t, 9, alert.RiskScore)
	assert.Equal(t, "SQL Injection detected", alert.Message)
	assert.NotNil(t, alert.Metadata)
}

func TestAlertRiskScoreClamping(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{-5, 1},
		{0, 1},
		{1, 1},
		{5, 5},
		{10, 10},
		{15, 10},
		{100, 10},
	}

	for _, tc := range tests {
		alert := NewAlert(netip.Addr{}, ThreatTypeXSS, AlertLevelWarning, "", tc.input, "")
		assert.Equal(t, tc.expected, alert.RiskScore)
	}
}

func TestAlertToJSON(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	alert := NewAlert(ip, ThreatTypePathTraversal, AlertLevelWarning, "GET /../../../etc/passwd", 7, "Path traversal attempt")
	alert.AddMetadata("detector", "signature")

	jsonBytes, err := alert.ToJSON()
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(jsonBytes, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "PATH_TRAVERSAL", parsed["threat_type"])
	assert.Equal(t, "WARNING", parsed["level"])
	assert.Equal(t, float64(7), parsed["risk_score"])
}

func TestAlertToJSONPretty(t *testing.T) {
	alert := NewAlert(netip.Addr{}, ThreatTypeBruteForce, AlertLevelCritical, "", 8, "Brute force detected")

	jsonBytes, err := alert.ToJSONPretty()
	require.NoError(t, err)

	assert.Contains(t, string(jsonBytes), "\n")
}

func TestAlertAddMetadata(t *testing.T) {
	alert := NewAlert(netip.Addr{}, ThreatTypeMaliciousIP, AlertLevelInfo, "", 5, "")

	alert.AddMetadata("source", "abuse_ipdb")
	alert.AddMetadata("confidence", "0.95")

	assert.Equal(t, "abuse_ipdb", alert.Metadata["source"])
	assert.Equal(t, "0.95", alert.Metadata["confidence"])
}

func TestAlertLevelColor(t *testing.T) {
	tests := []struct {
		level    AlertLevel
		expected string
	}{
		{AlertLevelCritical, "\033[31m"},
		{AlertLevelWarning, "\033[33m"},
		{AlertLevelInfo, "\033[36m"},
		{AlertLevel("UNKNOWN"), "\033[0m"},
	}

	for _, tc := range tests {
		alert := &Alert{Level: tc.level}
		assert.Equal(t, tc.expected, alert.LevelColor())
	}
}

func TestAlertIPString(t *testing.T) {
	alert := NewAlert(netip.MustParseAddr("192.168.1.1"), ThreatTypeXSS, AlertLevelWarning, "", 5, "")
	assert.Equal(t, "192.168.1.1", alert.IPString())

	alert2 := NewAlert(netip.Addr{}, ThreatTypeXSS, AlertLevelWarning, "", 5, "")
	assert.Equal(t, "unknown", alert2.IPString())
}
