// Package domain defines the core business entities and value objects for the LogRadar
// threat detection system. This package follows Domain-Driven Design principles and
// contains no external dependencies on infrastructure concerns.
//
// Security Considerations:
//   - All IP addresses use netip.Addr for memory-safe parsing and validation
//   - Alert IDs are generated using crypto/rand to prevent ID prediction attacks
//   - Risk scores are clamped to prevent integer overflow exploitation
//
// Thread Safety:
//   - Alert struct is immutable after creation (safe for concurrent read)
//   - Metadata map requires external synchronization if modified post-creation
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

// AlertLevel represents the severity classification of a security alert.
// Severity levels follow industry standards (SIEM integration compatible).
type AlertLevel string

const (
	// AlertLevelInfo indicates low-severity events that may warrant monitoring
	// but do not represent immediate threats (e.g., reconnaissance activity).
	AlertLevelInfo AlertLevel = "INFO"

	// AlertLevelWarning indicates medium-severity events that could escalate
	// to attacks if not addressed (e.g., repeated failed authentication).
	AlertLevelWarning AlertLevel = "WARNING"

	// AlertLevelCritical indicates high-severity events requiring immediate
	// incident response (e.g., active exploitation attempts).
	AlertLevelCritical AlertLevel = "CRITICAL"
)

// ThreatType categorizes the attack vector or malicious behavior detected.
// These categories align with MITRE ATT&CK web application attack patterns.
type ThreatType string

const (
	// ThreatTypeSQLInjection indicates SQL injection attack patterns detected
	// in query parameters, path segments, or request body (CWE-89).
	ThreatTypeSQLInjection ThreatType = "SQL_INJECTION"

	// ThreatTypeXSS indicates Cross-Site Scripting attack patterns including
	// reflected, stored, and DOM-based XSS vectors (CWE-79).
	ThreatTypeXSS ThreatType = "XSS"

	// ThreatTypePathTraversal indicates directory traversal attempts to access
	// files outside the web root (CWE-22).
	ThreatTypePathTraversal ThreatType = "PATH_TRAVERSAL"

	// ThreatTypeRCE indicates Remote Code Execution attempts through command
	// injection, deserialization, or template injection (CWE-78, CWE-94).
	ThreatTypeRCE ThreatType = "RCE"

	// ThreatTypeLFI indicates Local File Inclusion attacks attempting to read
	// server-side files through include mechanisms (CWE-98).
	ThreatTypeLFI ThreatType = "LFI"

	// ThreatTypeLog4Shell indicates CVE-2021-44228 JNDI injection patterns
	// targeting Apache Log4j 2.x vulnerability.
	ThreatTypeLog4Shell ThreatType = "LOG4SHELL"

	// ThreatTypeBruteForce indicates credential stuffing or password spraying
	// attacks based on repeated authentication failures from same source.
	ThreatTypeBruteForce ThreatType = "BRUTE_FORCE"

	// ThreatTypeRateLimitDoS indicates potential Layer 7 Denial of Service
	// based on excessive request rate from single source.
	ThreatTypeRateLimitDoS ThreatType = "RATE_LIMIT_DOS"

	// ThreatTypeMaliciousIP indicates connection from known malicious IP
	// address based on threat intelligence feeds.
	ThreatTypeMaliciousIP ThreatType = "MALICIOUS_IP"

	// ThreatTypeBotDetection indicates automated scanner or bot behavior
	// based on User-Agent rotation, request patterns, or fingerprinting.
	ThreatTypeBotDetection ThreatType = "BOT_DETECTION"

	// ThreatTypeUnknown indicates suspicious activity that doesn't match
	// known attack categories but warrants investigation.
	ThreatTypeUnknown ThreatType = "UNKNOWN"
)

// Alert represents a security event generated when malicious activity is detected.
// Alerts are immutable after creation to ensure thread-safe propagation through
// the detection pipeline.
//
// JSON serialization is optimized for SIEM ingestion with standard field naming.
type Alert struct {
	// ID is a globally unique identifier for correlation and deduplication.
	// Format: YYYYMMDDHHMMSS-counter-random (e.g., "20260103115536-42-a1b2c3d4")
	ID string `json:"id"`

	// Timestamp records when the alert was generated (UTC).
	Timestamp time.Time `json:"timestamp"`

	// SourceIP is the validated IP address of the request originator.
	// Uses netip.Addr for memory-efficient, allocation-free IP handling.
	SourceIP netip.Addr `json:"source_ip"`

	// ThreatType categorizes the detected attack vector.
	ThreatType ThreatType `json:"threat_type"`

	// Level indicates the severity for triage prioritization.
	Level AlertLevel `json:"level"`

	// RawLog contains the original log line that triggered detection.
	// Truncated to MaxLineLength to prevent memory exhaustion.
	RawLog string `json:"raw_log"`

	// RiskScore is a 1-10 severity rating for prioritization.
	// Higher scores indicate greater confidence or impact.
	RiskScore int `json:"risk_score"`

	// Message provides human-readable description of the detected threat.
	Message string `json:"message"`

	// Metadata contains detector-specific context (matched pattern, thresholds, etc).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// NewAlert creates an immutable Alert with cryptographically secure ID generation.
//
// Parameters:
//   - sourceIP: Validated source IP address (use netip.Addr{} for invalid)
//   - threatType: Attack category classification
//   - level: Severity for incident prioritization
//   - rawLog: Original log line (will be stored as-is)
//   - riskScore: 1-10 severity rating (values outside range are clamped)
//   - message: Human-readable threat description
//
// Returns:
//   - Pointer to fully initialized Alert ready for pipeline propagation
//
// Security:
//   - Uses crypto/rand for ID generation to prevent prediction attacks
//   - Clamps risk score to valid range to prevent integer issues
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

// ToJSON serializes the alert to compact JSON for high-throughput logging.
//
// Returns:
//   - JSON byte slice suitable for file/stdout output
//   - Error if serialization fails (should not occur with valid Alert)
func (a *Alert) ToJSON() ([]byte, error) {
	return json.Marshal(a)
}

// ToJSONPretty serializes the alert to indented JSON for human review.
//
// Returns:
//   - Formatted JSON byte slice with 2-space indentation
//   - Error if serialization fails
func (a *Alert) ToJSONPretty() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

// AddMetadata appends key-value context to the alert's metadata map.
// Thread-safe only if called before the alert enters the pipeline.
//
// Parameters:
//   - key: Metadata field name (e.g., "matched_pattern", "detector")
//   - value: Metadata field value
//
// Note: This method is intended for detector-side enrichment only.
// Do not call on alerts already dispatched to subscribers.
func (a *Alert) AddMetadata(key, value string) {
	if a.Metadata == nil {
		a.Metadata = make(map[string]string)
	}
	a.Metadata[key] = value
}

// alertCounter provides monotonically increasing sequence numbers for alert IDs.
// Uses atomic operations for lock-free thread safety.
var alertCounter atomic.Uint64

// generateAlertID creates a unique alert identifier combining:
//   - Timestamp (YYYYMMDDHHMMSS) for temporal ordering
//   - Atomic counter for uniqueness within the same second
//   - Random suffix (4 bytes) for unpredictability
//
// Security: Uses crypto/rand to prevent ID prediction/enumeration attacks.
// Falls back to zeroed random suffix if crypto/rand fails (extremely rare).
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

// clampRiskScore ensures risk score stays within valid 1-10 range.
// Prevents integer overflow exploitation and ensures consistent severity handling.
func clampRiskScore(score int) int {
	if score < 1 {
		return 1
	}
	if score > 10 {
		return 10
	}
	return score
}

// LevelColor returns ANSI escape code for terminal colorization.
// Used by TUI and console output for visual severity indication.
//
// Returns:
//   - Red (\033[31m) for CRITICAL
//   - Yellow (\033[33m) for WARNING
//   - Cyan (\033[36m) for INFO
//   - Reset (\033[0m) for unknown levels
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

// IPString returns string representation of the source IP.
// Returns "unknown" for invalid/zero IP addresses.
func (a *Alert) IPString() string {
	if !a.SourceIP.IsValid() {
		return "unknown"
	}
	return a.SourceIP.String()
}
