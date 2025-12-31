package domain

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"
)

type AlertLevel string

const (
	AlertLevelInfo     AlertLevel = "INFO"
	AlertLevelWarning  AlertLevel = "WARNING"
	AlertLevelCritical AlertLevel = "CRITICAL"
)

type ThreatType string

const (
	ThreatTypeSQLInjection  ThreatType = "SQL_INJECTION"
	ThreatTypeXSS           ThreatType = "XSS"
	ThreatTypePathTraversal ThreatType = "PATH_TRAVERSAL"
	ThreatTypeRCE           ThreatType = "RCE"
	ThreatTypeLFI           ThreatType = "LFI"
	ThreatTypeLog4Shell     ThreatType = "LOG4SHELL"
	ThreatTypeBruteForce    ThreatType = "BRUTE_FORCE"
	ThreatTypeRateLimitDoS  ThreatType = "RATE_LIMIT_DOS"
	ThreatTypeMaliciousIP   ThreatType = "MALICIOUS_IP"
	ThreatTypeBotDetection  ThreatType = "BOT_DETECTION"
	ThreatTypeUnknown       ThreatType = "UNKNOWN"
)

type Alert struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	SourceIP   netip.Addr        `json:"source_ip"`
	ThreatType ThreatType        `json:"threat_type"`
	Level      AlertLevel        `json:"level"`
	RawLog     string            `json:"raw_log"`
	RiskScore  int               `json:"risk_score"`
	Message    string            `json:"message"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

func NewAlert(sourceIP netip.Addr, threatType ThreatType, level AlertLevel, rawLog string, riskScore int, message string) *Alert {
	return &Alert{
		ID:         generateAlertID(),
		Timestamp:  time.Now().UTC(),
		SourceIP:   sourceIP,
		ThreatType: threatType,
		Level:      level,
		RawLog:     rawLog,
		RiskScore:  clampRiskScore(riskScore),
		Message:    message,
		Metadata:   make(map[string]string),
	}
}

func (a *Alert) ToJSON() ([]byte, error) {
	return json.Marshal(a)
}
func (a *Alert) ToJSONPretty() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

func (a *Alert) AddMetadata(key, value string) {
	if a.Metadata == nil {
		a.Metadata = make(map[string]string)
	}
	a.Metadata[key] = value
}

var alertCounter atomic.Uint64

func generateAlertID() string {
	var randBytes [4]byte
	if _, err := crypto_rand.Read(randBytes[:]); err != nil {
		return fmt.Sprintf("%s-%d-00000000",
			time.Now().UTC().Format("20060102150405"),
			alertCounter.Add(1))
	}
	return fmt.Sprintf("%s-%d-%08x",
		time.Now().UTC().Format("20060102150405"),
		alertCounter.Add(1),
		binary.BigEndian.Uint32(randBytes[:]))
}

func clampRiskScore(score int) int {
	if score < 1 {
		return 1
	}
	if score > 10 {
		return 10
	}
	return score
}

func (a *Alert) LevelColor() string {
	switch a.Level {
	case AlertLevelCritical:
		return "\033[31m"
	case AlertLevelWarning:
		return "\033[33m"
	case AlertLevelInfo:
		return "\033[36m"
	default:
		return "\033[0m"
	}
}

func (a *Alert) IPString() string {
	if !a.SourceIP.IsValid() {
		return "unknown"
	}
	return a.SourceIP.String()
}
