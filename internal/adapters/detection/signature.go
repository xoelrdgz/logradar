package detection

import (
	"context"
	"regexp"
	"strings"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/pkg/ahocorasick"
)

type Pattern struct {
	Name                string
	Regex               *regexp.Regexp
	ThreatType          domain.ThreatType
	RiskScore           int
	Level               domain.AlertLevel
	Keywords            []string
	RequiresQueryString bool
}

type SignatureDetector struct {
	patterns  []*Pattern
	preFilter *ahocorasick.Matcher
}

func DefaultPatterns() []*Pattern {
	return []*Pattern{
		{
			Name:                "SQL Injection - UNION",
			Regex:               regexp.MustCompile(`(?i)(union\s+(all\s+)?select)`),
			ThreatType:          domain.ThreatTypeSQLInjection,
			RiskScore:           9,
			Level:               domain.AlertLevelCritical,
			RequiresQueryString: true,
		},
		{
			Name:                "SQL Injection - SELECT/SLEEP",
			Regex:               regexp.MustCompile(`(?i)(select\s+.+\s+from|sleep\s*\(|benchmark\s*\()`),
			ThreatType:          domain.ThreatTypeSQLInjection,
			RiskScore:           8,
			Level:               domain.AlertLevelCritical,
			RequiresQueryString: true,
		},
		{
			Name:                "SQL Injection - OR 1=1",
			Regex:               regexp.MustCompile(`(?i)(\bor\b\s+\d+\s*=\s*\d+|\bor\b\s*'[^']*'\s*=\s*'[^']*')`),
			ThreatType:          domain.ThreatTypeSQLInjection,
			RiskScore:           8,
			Level:               domain.AlertLevelCritical,
			RequiresQueryString: true,
		},
		{
			Name:                "SQL Injection - DROP/DELETE",
			Regex:               regexp.MustCompile(`(?i)(drop\s+table|delete\s+from|truncate\s+table)`),
			ThreatType:          domain.ThreatTypeSQLInjection,
			RiskScore:           10,
			Level:               domain.AlertLevelCritical,
			RequiresQueryString: true,
		},
		{
			Name:                "SQL Injection - Comment",
			Regex:               regexp.MustCompile(`(?i)(\-\-\s*$|/\*.*\*/|#\s*$)`),
			ThreatType:          domain.ThreatTypeSQLInjection,
			RiskScore:           6,
			Level:               domain.AlertLevelWarning,
			RequiresQueryString: true,
		},
		{
			Name:       "XSS - Script Tag",
			Regex:      regexp.MustCompile(`(?i)(<script[^>]*>|</script>)`),
			ThreatType: domain.ThreatTypeXSS,
			RiskScore:  9,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "XSS - JavaScript Protocol",
			Regex:      regexp.MustCompile(`(?i)(javascript\s*:|vbscript\s*:)`),
			ThreatType: domain.ThreatTypeXSS,
			RiskScore:  8,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "XSS - Event Handler",
			Regex:      regexp.MustCompile(`(?i)(on(error|load|click|mouse|key|focus|blur|change|submit)\s*=)`),
			ThreatType: domain.ThreatTypeXSS,
			RiskScore:  8,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "XSS - Alert/Eval",
			Regex:      regexp.MustCompile(`(?i)(alert\s*\(|eval\s*\(|document\.cookie)`),
			ThreatType: domain.ThreatTypeXSS,
			RiskScore:  8,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "Path Traversal - Dot-Dot-Slash",
			Regex:      regexp.MustCompile(`(\.\./){2,}|\.\.\\`),
			ThreatType: domain.ThreatTypePathTraversal,
			RiskScore:  8,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "Path Traversal - etc/passwd",
			Regex:      regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|/etc/hosts)`),
			ThreatType: domain.ThreatTypePathTraversal,
			RiskScore:  9,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "Path Traversal - Windows Paths",
			Regex:      regexp.MustCompile(`(?i)(c:\\windows|c:\\boot\.ini|c:\\inetpub)`),
			ThreatType: domain.ThreatTypePathTraversal,
			RiskScore:  9,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "Scanner - Admin Paths",
			Regex:      regexp.MustCompile(`(?i)(/admin|/wp-admin|/phpmyadmin|/manager|/administrator)`),
			ThreatType: domain.ThreatTypeUnknown,
			RiskScore:  4,
			Level:      domain.AlertLevelInfo,
		},
		{
			Name:       "Scanner - Config Files",
			Regex:      regexp.MustCompile(`(?i)(\.env|\.git|\.svn|config\.php|wp-config\.php)`),
			ThreatType: domain.ThreatTypePathTraversal,
			RiskScore:  7,
			Level:      domain.AlertLevelWarning,
		},
		{
			Name:                "SQL Injection - Path Parameter Semicolon",
			Regex:               regexp.MustCompile(`/[^?]*;[\s]*(DROP|DELETE|UPDATE|INSERT|SELECT|TRUNCATE|ALTER)`),
			ThreatType:          domain.ThreatTypeSQLInjection,
			RiskScore:           9,
			Level:               domain.AlertLevelCritical,
			RequiresQueryString: false,
		},
		{
			Name:                "SQL Injection - Path Parameter Quote",
			Regex:               regexp.MustCompile(`/[^?]*'[\s]*(OR|AND|UNION|SELECT)`),
			ThreatType:          domain.ThreatTypeSQLInjection,
			RiskScore:           9,
			Level:               domain.AlertLevelCritical,
			RequiresQueryString: false,
		},
		{
			Name:       "RCE - Command Chaining",
			Regex:      regexp.MustCompile(`(?i)(;|\||\|\||&&)\s*(cat|ls|id|whoami|uname|pwd|curl|wget|nc|netcat|bash|sh|python|perl|ruby|php)\b`),
			ThreatType: domain.ThreatTypeRCE,
			RiskScore:  10,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "RCE - Backticks/Subshell",
			Regex:      regexp.MustCompile("`[^`]+`|\\$\\([^)]+\\)"),
			ThreatType: domain.ThreatTypeRCE,
			RiskScore:  9,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "RCE - Shellshock",
			Regex:      regexp.MustCompile(`\(\)\s*\{`),
			ThreatType: domain.ThreatTypeRCE,
			RiskScore:  10,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "LFI - PHP Wrappers",
			Regex:      regexp.MustCompile(`(?i)(php://|file://|data://|expect://|zip://|phar://)`),
			ThreatType: domain.ThreatTypeLFI,
			RiskScore:  9,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "LFI - Null Byte Injection",
			Regex:      regexp.MustCompile(`%00|\\x00`),
			ThreatType: domain.ThreatTypeLFI,
			RiskScore:  8,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "Log4Shell - JNDI Injection",
			Regex:      regexp.MustCompile(`(?i)\$\{jndi:(ldap|rmi|dns|iiop|corba|nds|http)s?://`),
			ThreatType: domain.ThreatTypeLog4Shell,
			RiskScore:  10,
			Level:      domain.AlertLevelCritical,
		},
		{
			Name:       "Log4Shell - Obfuscated",
			Regex:      regexp.MustCompile(`(?i)\$\{[^}]*\$\{|\$\{(lower|upper|env|sys|java):`),
			ThreatType: domain.ThreatTypeLog4Shell,
			RiskScore:  10,
			Level:      domain.AlertLevelCritical,
		},
	}
}

func NewSignatureDetector(patterns []*Pattern) *SignatureDetector {
	if len(patterns) == 0 {
		patterns = DefaultPatterns()
	}

	attackKeywords := []string{
		"union", "select", "from", "where", "drop", "delete", "truncate",
		"insert", "update", "sleep", "benchmark", "waitfor", "1=1", "or 1",
		"--", "/*", "*/",
		"script", "javascript", "vbscript", "onerror", "onload", "onclick",
		"onmouse", "onfocus", "onblur", "onchange", "onsubmit", "onkey",
		"alert", "eval", "document.", "cookie",
		"../", "..\\", "/etc/", "passwd", "shadow", "boot.ini", "windows",
		"inetpub", ".git", ".env", ".svn", "config.php", "wp-config",
		"admin", "wp-admin", "phpmyadmin", "manager", "administrator",
	}

	preFilter := ahocorasick.New(attackKeywords)

	return &SignatureDetector{
		patterns:  patterns,
		preFilter: preFilter,
	}
}

func (d *SignatureDetector) Detect(ctx context.Context, entry *domain.LogEntry) domain.DetectionResult {
	if entry == nil {
		return domain.NoDetection()
	}

	targets := []string{entry.Path, entry.UserAgent}

	if len(entry.Body) > 0 {
		targets = append(targets, string(entry.Body))
	}

	for _, val := range entry.Headers {
		if val != "" {
			targets = append(targets, val)
		}
	}

	for _, val := range entry.Cookies {
		if val != "" {
			targets = append(targets, val)
		}
	}

	for i, target := range targets {
		if target == "" {
			continue
		}

		hasQueryString := i == 0 && strings.Contains(target, "?")

		normalizedTarget := normalizeForDetection(target, hasQueryString)

		if d.preFilter != nil && !d.preFilter.Match(normalizedTarget) {
			continue
		}

		queryStringPart := ""
		if idx := strings.Index(normalizedTarget, "?"); idx >= 0 {
			queryStringPart = normalizedTarget[idx:]
		}
		for _, pattern := range d.patterns {
			select {
			case <-ctx.Done():
				return domain.NoDetection()
			default:
			}

			matchTarget := normalizedTarget
			if pattern.RequiresQueryString {
				if i == 0 && !hasQueryString {
					continue
				}
				if i == 0 && queryStringPart != "" {
					matchTarget = queryStringPart
				}
			}

			if pattern.Regex.MatchString(matchTarget) {
				return domain.DetectionResult{
					Detected:   true,
					ThreatType: pattern.ThreatType,
					Level:      pattern.Level,
					RiskScore:  pattern.RiskScore,
					Message:    pattern.Name,
					Details: map[string]interface{}{
						"pattern": pattern.Regex.String(),
						"target":  target,
					},
				}
			}
		}
	}

	return domain.NoDetection()
}

func (d *SignatureDetector) Name() string {
	return "signature"
}
func (d *SignatureDetector) Type() domain.ThreatType {
	return domain.ThreatTypeUnknown
}

func (d *SignatureDetector) AddPattern(name, pattern string, threatType domain.ThreatType, riskScore int, level domain.AlertLevel) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	d.patterns = append(d.patterns, &Pattern{
		Name:       name,
		Regex:      regex,
		ThreatType: threatType,
		RiskScore:  riskScore,
		Level:      level,
	})

	return nil
}

func (d *SignatureDetector) PatternCount() int {
	return len(d.patterns)
}

func normalizeForDetection(s string, isQueryString bool) string {
	if s == "" {
		return s
	}

	s = removeNullBytes(s)

	s = urlDecodeMultiPass(s, 5)

	if isQueryString && strings.Contains(s, "+") {
		s = strings.ReplaceAll(s, "+", " ")
	}

	s = normalizeUnicode(s)

	return s
}

func removeNullBytes(s string) string {
	if !strings.ContainsAny(s, "\x00") {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

func urlDecodeMultiPass(s string, maxPasses int) string {
	decoded := s

	for i := 0; i < maxPasses; i++ {
		if !strings.Contains(decoded, "%") {
			break
		}

		newDecoded := percentDecode(decoded)
		if newDecoded == decoded {
			break
		}
		decoded = newDecoded
	}

	return decoded
}

func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}

	var result strings.Builder
	result.Grow(len(s))

	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			high := hexVal(s[i+1])
			low := hexVal(s[i+2])
			if high >= 0 && low >= 0 {
				decoded := byte(high<<4 | low)
				if decoded != 0 {
					result.WriteByte(decoded)
				}
				i += 3
				continue
			}
		}
		result.WriteByte(s[i])
		i++
	}

	return result.String()
}

var unicodeReplacer = strings.NewReplacer(
	"＜", "<", "＞", ">", "＆", "&", "＂", "\"", "＇", "'",
	"（", "(", "）", ")", "／", "/", "＼", "\\",
	"ｕ", "u", "ｎ", "n", "ｉ", "i", "ｏ", "o", "ｓ", "s",
	"ｅ", "e", "ｌ", "l", "ｃ", "c", "ｔ", "t",
	"Ｕ", "U", "Ｎ", "N", "Ｉ", "I", "Ｏ", "O", "Ｓ", "S",
	"Ｅ", "E", "Ｌ", "L", "Ｃ", "C", "Ｔ", "T",
	"ʼ", "'", "ʻ", "'", "′", "'", "‵", "'",
	"‹", "<", "›", ">",
	"«", "<", "»", ">",
)

func normalizeUnicode(s string) string {
	hasUnicode := false
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			hasUnicode = true
			break
		}
	}
	if !hasUnicode {
		return s
	}

	return unicodeReplacer.Replace(s)
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}
