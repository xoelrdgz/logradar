package detection

import (
	"context"
	"strings"
	"unicode"

	"github.com/xoelrdgz/logradar/internal/domain"
)

type TokenType int

const (
	TokenUnknown TokenType = iota
	TokenString
	TokenNumber
	TokenKeyword
	TokenOperator
	TokenComment
	TokenFunction
	TokenDelimiter
	TokenIdentifier
)

type Token struct {
	Type  TokenType
	Value string
}

var SQLKeywords = map[string]bool{
	"select": true, "union": true, "insert": true, "update": true,
	"delete": true, "drop": true, "truncate": true, "alter": true,
	"create": true, "from": true, "where": true, "and": true,
	"or": true, "not": true, "null": true, "like": true,
	"in": true, "between": true, "having": true, "group": true,
	"order": true, "by": true, "limit": true, "offset": true,
	"exec": true, "execute": true, "xp_": true, "sp_": true,
	"into": true, "values": true, "set": true, "waitfor": true,
	"delay": true, "sleep": true, "benchmark": true, "load_file": true,
	"outfile": true, "dumpfile": true, "information_schema": true,
}

var DangerousFunctions = map[string]bool{
	"sleep": true, "benchmark": true, "waitfor": true,
	"load_file": true, "into outfile": true, "into dumpfile": true,
	"user": true, "current_user": true, "system_user": true,
	"database": true, "version": true, "@@version": true,
	"char": true, "concat": true, "group_concat": true,
	"substring": true, "substr": true, "ascii": true,
	"hex": true, "unhex": true, "conv": true,
}

type TokenPattern struct {
	Pattern     []TokenType
	Description string
	RiskScore   int
}

var tokenToChar = map[TokenType]byte{
	TokenString:     's',
	TokenNumber:     'n',
	TokenKeyword:    'k',
	TokenOperator:   'o',
	TokenComment:    'c',
	TokenFunction:   'f',
	TokenDelimiter:  'd',
	TokenIdentifier: 'i',
	TokenUnknown:    'u',
}

var sqliFingerprints = map[string]string{
	"soksos": "String OR tautology (s=s)",
	"soknon": "String OR tautology (n=n)",
	"sonos":  "String OR number comparison",
	"sosos":  "String OR string comparison",
	"sokso":  "String OR string partial",
	"sokon":  "String OR number partial",
	"kk":     "UNION SELECT",
	"kkk":    "UNION SELECT FROM",
	"dkk":    "Statement chain UNION SELECT",
	"ckk":    "Comment bypass UNION SELECT",
	"dk":     "Statement chaining (;SELECT)",
	"dkki":   "Statement chain with table",
	"fd":     "Time-based function call",
	"fdn":    "Function with numeric arg",
	"fds":    "Function with string arg",
	"kfd":    "Keyword + function delay",
	"kok":    "Keyword OR keyword",
	"knon":   "Keyword AND number compare",
	"ksos":   "Keyword AND string compare",
	"ikokn":  "Identifier keyword OR compare",
	"sck":    "String comment keyword",
	"kck":    "Keyword comment keyword",
	"scks":   "String comment keyword string",
	"dki":    "Delimiter keyword identifier",
	"dkis":   "Delimiter keyword identifier string",
	"fdi":    "Function delimiter identifier",
	"kfdi":   "Keyword function with id",
}

type SQLTokenizer struct{}

func NewSQLTokenizer() *SQLTokenizer {
	return &SQLTokenizer{}
}
func (t *SQLTokenizer) Tokenize(input string) []Token {
	input = normalizeForTokenization(input)
	if input == "" {
		return nil
	}

	var tokens []Token
	i := 0
	n := len(input)

	for i < n {
		for i < n && unicode.IsSpace(rune(input[i])) {
			i++
		}
		if i >= n {
			break
		}

		c := input[i]

		if c == '-' && i+1 < n && input[i+1] == '-' {
			tokens = append(tokens, Token{Type: TokenComment, Value: "--"})
			i += 2
			for i < n && input[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < n && input[i+1] == '*' {
			tokens = append(tokens, Token{Type: TokenComment, Value: "/*"})
			i += 2
			for i < n-1 && !(input[i] == '*' && input[i+1] == '/') {
				i++
			}
			if i < n-1 {
				i += 2
			}
			continue
		}
		if c == '#' {
			tokens = append(tokens, Token{Type: TokenComment, Value: "#"})
			i++
			continue
		}

		if c == '\'' || c == '"' {
			quote := c
			i++
			start := i
			for i < n && input[i] != quote {
				if input[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
			value := ""
			if i > start {
				value = input[start:i]
			}
			tokens = append(tokens, Token{Type: TokenString, Value: value})
			if i < n {
				i++
			}
			continue
		}

		if unicode.IsDigit(rune(c)) || (c == '.' && i+1 < n && unicode.IsDigit(rune(input[i+1]))) {
			start := i
			for i < n && (unicode.IsDigit(rune(input[i])) || input[i] == '.') {
				i++
			}
			tokens = append(tokens, Token{Type: TokenNumber, Value: input[start:i]})
			continue
		}

		if strings.ContainsRune("=<>!%", rune(c)) {
			start := i
			i++
			if i < n && strings.ContainsRune("=<>", rune(input[i])) {
				i++
			}
			tokens = append(tokens, Token{Type: TokenOperator, Value: input[start:i]})
			continue
		}

		if strings.ContainsRune("(),;", rune(c)) {
			tokens = append(tokens, Token{Type: TokenDelimiter, Value: string(c)})
			i++
			continue
		}

		if unicode.IsLetter(rune(c)) || c == '_' || c == '@' {
			start := i
			for i < n && (unicode.IsLetter(rune(input[i])) || unicode.IsDigit(rune(input[i])) || input[i] == '_' || input[i] == '@') {
				i++
			}
			word := strings.ToLower(input[start:i])

			nextNonSpace := i
			for nextNonSpace < n && unicode.IsSpace(rune(input[nextNonSpace])) {
				nextNonSpace++
			}
			if nextNonSpace < n && input[nextNonSpace] == '(' {
				if DangerousFunctions[word] {
					tokens = append(tokens, Token{Type: TokenFunction, Value: word})
					continue
				}
			}

			if SQLKeywords[word] {
				tokens = append(tokens, Token{Type: TokenKeyword, Value: word})
			} else {
				tokens = append(tokens, Token{Type: TokenIdentifier, Value: word})
			}
			continue
		}

		i++
	}

	return tokens
}

func (t *SQLTokenizer) ToFingerprint(tokens []Token) string {
	if len(tokens) == 0 {
		return ""
	}
	maxLen := len(tokens)
	if maxLen > 10 {
		maxLen = 10
	}

	fp := make([]byte, maxLen)
	for i := 0; i < maxLen; i++ {
		fp[i] = tokenToChar[tokens[i].Type]
	}
	return string(fp)
}

func (t *SQLTokenizer) MatchesFingerprint(tokens []Token) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}

	fingerprint := t.ToFingerprint(tokens)

	if desc, ok := sqliFingerprints[fingerprint]; ok {
		return true, desc
	}
	for windowSize := 2; windowSize <= len(fingerprint) && windowSize <= 6; windowSize++ {
		for i := 0; i <= len(fingerprint)-windowSize; i++ {
			substr := fingerprint[i : i+windowSize]
			if desc, ok := sqliFingerprints[substr]; ok {
				return true, desc
			}
		}
	}

	return false, ""
}

func (t *SQLTokenizer) MatchesPattern(tokens []Token) (bool, TokenPattern) {
	if matched, desc := t.MatchesFingerprint(tokens); matched {
		return true, TokenPattern{
			Description: desc,
			RiskScore:   9,
		}
	}
	return false, TokenPattern{}
}

func normalizeForTokenization(s string) string {
	if s == "" {
		return ""
	}

	s = urlDecodeMultiPass(s, 3)

	s = strings.ToLower(s)

	s = strings.ReplaceAll(s, "\x00", "")

	return s
}

type SQLTokenizerDetector struct {
	tokenizer *SQLTokenizer
}

func NewSQLTokenizerDetector() *SQLTokenizerDetector {
	return &SQLTokenizerDetector{
		tokenizer: NewSQLTokenizer(),
	}
}

func (d *SQLTokenizerDetector) Detect(ctx context.Context, entry *domain.LogEntry) domain.DetectionResult {
	if entry == nil {
		return domain.NoDetection()
	}

	targets := []string{entry.Path, entry.BodyString()}

	for _, v := range entry.QueryParams {
		targets = append(targets, v)
	}

	for _, target := range targets {
		if target == "" {
			continue
		}

		tokens := d.tokenizer.Tokenize(target)
		if len(tokens) < 2 {
			continue
		}

		if matches, pattern := d.tokenizer.MatchesPattern(tokens); matches {
			return domain.DetectionResult{
				Detected:   true,
				ThreatType: domain.ThreatTypeSQLInjection,
				Level:      domain.AlertLevelCritical,
				RiskScore:  pattern.RiskScore,
				Message:    "SQL injection detected via token analysis: " + pattern.Description,
				Details: map[string]interface{}{
					"pattern":     pattern.Description,
					"token_count": len(tokens),
				},
			}
		}

		keywordCount := 0
		for _, token := range tokens {
			if token.Type == TokenKeyword || token.Type == TokenFunction {
				keywordCount++
			}
		}
		if keywordCount >= 3 && len(tokens) >= 5 {
			density := float64(keywordCount) / float64(len(tokens))
			if density > 0.3 {
				return domain.DetectionResult{
					Detected:   true,
					ThreatType: domain.ThreatTypeSQLInjection,
					Level:      domain.AlertLevelWarning,
					RiskScore:  7,
					Message:    "High SQL keyword density detected",
					Details: map[string]interface{}{
						"keyword_count": keywordCount,
						"token_count":   len(tokens),
						"density":       density,
					},
				}
			}
		}
	}

	return domain.NoDetection()
}

func (d *SQLTokenizerDetector) Name() string {
	return "sql_tokenizer"
}
func (d *SQLTokenizerDetector) Type() domain.ThreatType {
	return domain.ThreatTypeSQLInjection
}
