// Package detection implements SQL tokenization for injection detection.
//
// This file provides token-based SQL injection analysis that examines query
// structure rather than pattern matching. More resistant to encoding/obfuscation
// attacks than regex-only approaches.
//
// Detection Strategy:
//   - Tokenize input into SQL tokens (keywords, strings, operators, etc.)
//   - Generate fingerprint from token sequence
//   - Match fingerprint against known SQLi patterns
//   - Also detect high SQL keyword density
//
// Thread Safety: Tokenizer is stateless and safe for concurrent use.
package detection

import (
	"context"
	"strings"
	"unicode"

	"github.com/xoelrdgz/logradar/internal/domain"
)

// TokenType represents the category of a SQL token.
type TokenType int

const (
	TokenUnknown    TokenType = iota // Unknown or unrecognized token
	TokenString                      // String literal ('...' or "...")
	TokenNumber                      // Numeric literal (123, 45.67)
	TokenKeyword                     // SQL keyword (SELECT, UNION, etc.)
	TokenOperator                    // Operator (=, <, >, !=, etc.)
	TokenComment                     // SQL comment (--, /*, #)
	TokenFunction                    // SQL function call (SLEEP(), CONCAT())
	TokenDelimiter                   // Delimiter (;, ,, (, ))
	TokenIdentifier                  // Identifier (table/column name)
)

// Token represents a single SQL token with type and value.
type Token struct {
	Type  TokenType // Token category
	Value string    // Token content
}

// SQLKeywords is the set of SQL keywords to recognize.
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

// DangerousFunctions are SQL functions commonly used in attacks.
var DangerousFunctions = map[string]bool{
	"sleep": true, "benchmark": true, "waitfor": true,
	"load_file": true, "into outfile": true, "into dumpfile": true,
	"user": true, "current_user": true, "system_user": true,
	"database": true, "version": true, "@@version": true,
	"char": true, "concat": true, "group_concat": true,
	"substring": true, "substr": true, "ascii": true,
	"hex": true, "unhex": true, "conv": true,
}

// TokenPattern represents a detected SQLi pattern.
type TokenPattern struct {
	Pattern     []TokenType // Token type sequence
	Description string      // Human-readable description
	RiskScore   int         // Severity 1-10
}

// tokenToChar maps token types to single chars for fingerprinting.
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

// sqliFingerprints maps known SQLi token fingerprints to descriptions.
// Fingerprints are compact strings representing token sequences.
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

// SQLTokenizer converts SQL strings into token sequences.
type SQLTokenizer struct{}

// NewSQLTokenizer creates a new SQL tokenizer.
func NewSQLTokenizer() *SQLTokenizer {
	return &SQLTokenizer{}
}

// Tokenize breaks input into SQL tokens.
//
// Parameters:
//   - input: String to tokenize (query, path, etc.)
//
// Returns:
//   - Slice of tokens representing SQL structure
//
// Recognized Elements:
//   - Comments: --, /* */, #
//   - Strings: '...', "..."
//   - Numbers: integers and decimals
//   - Operators: =, <, >, !=, etc.
//   - Delimiters: (, ), ;, ,
//   - Keywords: SQL reserved words
//   - Functions: SQL functions followed by (
//   - Identifiers: other word tokens
func (t *SQLTokenizer) Tokenize(input string) []Token {
	input = normalizeForTokenization(input)
	if input == "" {
		return nil
	}

	var tokens []Token
	i := 0
	n := len(input)

	for i < n {
		// Skip whitespace
		for i < n && unicode.IsSpace(rune(input[i])) {
			i++
		}
		if i >= n {
			break
		}

		c := input[i]

		// SQL comments: --
		if c == '-' && i+1 < n && input[i+1] == '-' {
			tokens = append(tokens, Token{Type: TokenComment, Value: "--"})
			i += 2
			for i < n && input[i] != '\n' {
				i++
			}
			continue
		}
		// SQL comments: /* */
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
		// MySQL comment: #
		if c == '#' {
			tokens = append(tokens, Token{Type: TokenComment, Value: "#"})
			i++
			continue
		}

		// String literals
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

		// Numbers
		if unicode.IsDigit(rune(c)) || (c == '.' && i+1 < n && unicode.IsDigit(rune(input[i+1]))) {
			start := i
			for i < n && (unicode.IsDigit(rune(input[i])) || input[i] == '.') {
				i++
			}
			tokens = append(tokens, Token{Type: TokenNumber, Value: input[start:i]})
			continue
		}

		// Operators
		if strings.ContainsRune("=<>!%", rune(c)) {
			start := i
			i++
			if i < n && strings.ContainsRune("=<>", rune(input[i])) {
				i++
			}
			tokens = append(tokens, Token{Type: TokenOperator, Value: input[start:i]})
			continue
		}

		// Delimiters
		if strings.ContainsRune("(),;", rune(c)) {
			tokens = append(tokens, Token{Type: TokenDelimiter, Value: string(c)})
			i++
			continue
		}

		// Keywords, functions, identifiers
		if unicode.IsLetter(rune(c)) || c == '_' || c == '@' {
			start := i
			for i < n && (unicode.IsLetter(rune(input[i])) || unicode.IsDigit(rune(input[i])) || input[i] == '_' || input[i] == '@') {
				i++
			}
			word := strings.ToLower(input[start:i])

			// Check if followed by ( -> function
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

// ToFingerprint converts tokens to a compact fingerprint string.
//
// Parameters:
//   - tokens: Token sequence to fingerprint
//
// Returns:
//   - String of single chars representing token types (max 10 chars)
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

// MatchesFingerprint checks if tokens match any known SQLi fingerprint.
//
// Parameters:
//   - tokens: Token sequence to analyze
//
// Returns:
//   - true and description if match found
//   - false and empty string otherwise
func (t *SQLTokenizer) MatchesFingerprint(tokens []Token) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}

	fingerprint := t.ToFingerprint(tokens)

	// Exact match
	if desc, ok := sqliFingerprints[fingerprint]; ok {
		return true, desc
	}

	// Sliding window match
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

// MatchesPattern checks for SQLi patterns and returns match details.
func (t *SQLTokenizer) MatchesPattern(tokens []Token) (bool, TokenPattern) {
	if matched, desc := t.MatchesFingerprint(tokens); matched {
		return true, TokenPattern{
			Description: desc,
			RiskScore:   9,
		}
	}
	return false, TokenPattern{}
}

// normalizeForTokenization prepares input for tokenization.
func normalizeForTokenization(s string) string {
	if s == "" {
		return ""
	}

	s = urlDecodeMultiPass(s, 3)
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "\x00", "")

	return s
}

// SQLTokenizerDetector wraps tokenizer as a ThreatDetector.
type SQLTokenizerDetector struct {
	tokenizer *SQLTokenizer
}

// NewSQLTokenizerDetector creates a token-based SQL injection detector.
func NewSQLTokenizerDetector() *SQLTokenizerDetector {
	return &SQLTokenizerDetector{
		tokenizer: NewSQLTokenizer(),
	}
}

// Detect analyzes a log entry for SQL injection using tokenization.
//
// Parameters:
//   - ctx: Context for cancellation
//   - entry: Log entry to analyze
//
// Returns:
//   - DetectionResult with Detected=true if SQLi pattern found
//
// Detection Strategies:
//  1. Fingerprint matching against known SQLi patterns
//  2. High SQL keyword density detection (>30% keywords)
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

		// Fingerprint matching
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

		// Keyword density analysis
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

// Name returns the detector identifier.
func (d *SQLTokenizerDetector) Name() string {
	return "sql_tokenizer"
}

// Type returns the primary threat type this detector handles.
func (d *SQLTokenizerDetector) Type() domain.ThreatType {
	return domain.ThreatTypeSQLInjection
}
