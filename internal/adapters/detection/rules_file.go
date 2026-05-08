package detection

import (
	"fmt"
	"os"
	"regexp"

	"go.yaml.in/yaml/v3"

	"github.com/xoelrdgz/logradar/internal/domain"
)

type SignatureRulesFile struct {
	Version string          `yaml:"version"`
	Rules   []SignatureRule `yaml:"rules"`
}

type SignatureRule struct {
	ID                  string   `yaml:"id"`
	Version             string   `yaml:"version"`
	Name                string   `yaml:"name"`
	Pattern             string   `yaml:"pattern"`
	ThreatType          string   `yaml:"threat_type"`
	Level               string   `yaml:"level"`
	RiskScore           int      `yaml:"risk_score"`
	Confidence          float64  `yaml:"confidence"`
	Audit               bool     `yaml:"audit"`
	Keywords            []string `yaml:"keywords"`
	RequiresQueryString bool     `yaml:"requires_query_string"`
}

func LoadSignatureRulesFile(path string) ([]*Pattern, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var file SignatureRulesFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.Version == "" {
		return nil, fmt.Errorf("rules file %q missing version", path)
	}

	patterns := make([]*Pattern, 0, len(file.Rules))
	for _, rule := range file.Rules {
		pattern, err := compileSignatureRule(rule)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}

func compileSignatureRule(rule SignatureRule) (*Pattern, error) {
	if rule.Name == "" {
		return nil, fmt.Errorf("signature rule %q missing name", rule.ID)
	}
	if rule.Pattern == "" {
		return nil, fmt.Errorf("signature rule %q missing pattern", rule.Name)
	}

	regex, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return nil, fmt.Errorf("signature rule %q invalid regex: %w", rule.Name, err)
	}

	risk := rule.RiskScore
	if risk <= 0 {
		risk = 5
	}

	return &Pattern{
		ID:                  rule.ID,
		Version:             rule.Version,
		Name:                rule.Name,
		Regex:               regex,
		ThreatType:          parseThreatType(rule.ThreatType),
		RiskScore:           risk,
		Level:               parseAlertLevel(rule.Level),
		Confidence:          rule.Confidence,
		Audit:               rule.Audit,
		Keywords:            rule.Keywords,
		RequiresQueryString: rule.RequiresQueryString,
	}, nil
}

func parseThreatType(value string) domain.ThreatType {
	switch value {
	case string(domain.ThreatTypeSQLInjection), "sql_injection", "sqli":
		return domain.ThreatTypeSQLInjection
	case string(domain.ThreatTypeXSS), "xss":
		return domain.ThreatTypeXSS
	case string(domain.ThreatTypePathTraversal), "path_traversal", "traversal":
		return domain.ThreatTypePathTraversal
	case string(domain.ThreatTypeRCE), "rce":
		return domain.ThreatTypeRCE
	case string(domain.ThreatTypeLFI), "lfi":
		return domain.ThreatTypeLFI
	case string(domain.ThreatTypeLog4Shell), "log4shell":
		return domain.ThreatTypeLog4Shell
	case string(domain.ThreatTypeMaliciousIP), "malicious_ip":
		return domain.ThreatTypeMaliciousIP
	case string(domain.ThreatTypeBotDetection), "bot_detection":
		return domain.ThreatTypeBotDetection
	default:
		return domain.ThreatTypeUnknown
	}
}

func parseAlertLevel(value string) domain.AlertLevel {
	switch value {
	case string(domain.AlertLevelCritical), "critical":
		return domain.AlertLevelCritical
	case string(domain.AlertLevelInfo), "info":
		return domain.AlertLevelInfo
	default:
		return domain.AlertLevelWarning
	}
}
