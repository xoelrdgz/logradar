// Package ahocorasick implements the Aho-Corasick multi-pattern string matching algorithm.
//
// The Aho-Corasick algorithm enables efficient searching for multiple patterns
// simultaneously in O(n + m + z) time, where:
//   - n is text length
//   - m is total pattern length
//   - z is number of matches
//
// Used by LogRadar for pre-filtering log entries before regex pattern matching,
// significantly improving performance when checking many attack signatures.
//
// Thread Safety: Match/MatchAll are safe for concurrent calls after construction.
// The Matcher is immutable after New() returns.
package ahocorasick

import "unicode"

// Matcher is an Aho-Corasick automaton for multi-pattern string matching.
//
// The automaton is built from a set of patterns and can efficiently find
// all occurrences of any pattern in a text string.
type Matcher struct {
	root     *node    // Root of the trie
	patterns []string // Original patterns for reference
}

// node represents a state in the Aho-Corasick automaton.
type node struct {
	children map[rune]*node // Transitions for each character
	fail     *node          // Failure link for non-matching transitions
	output   []int          // Pattern indices matching at this state
	depth    int            // Depth in trie (for debugging)
}

// New creates an Aho-Corasick matcher from the given patterns.
//
// Parameters:
//   - patterns: List of strings to search for (case-insensitive)
//
// Returns:
//   - Configured Matcher ready for Match/MatchAll calls
//
// Complexity:
//   - Construction: O(sum of pattern lengths)
//   - Memory: O(sum of pattern lengths * alphabet size for edges)
//
// Note: Patterns are matched case-insensitively.
func New(patterns []string) *Matcher {
	m := &Matcher{
		root:     newNode(0),
		patterns: patterns,
	}

	// Build trie from patterns
	for i, pattern := range patterns {
		m.addPattern(pattern, i)
	}

	// Build failure links (BFS from root)
	m.buildFailureLinks()

	return m
}

// newNode creates an automaton node.
func newNode(depth int) *node {
	return &node{
		children: make(map[rune]*node),
		depth:    depth,
	}
}

// addPattern inserts a pattern into the trie.
func (m *Matcher) addPattern(pattern string, index int) {
	current := m.root
	for _, r := range pattern {
		r = toLower(r)
		if _, ok := current.children[r]; !ok {
			current.children[r] = newNode(current.depth + 1)
		}
		current = current.children[r]
	}
	current.output = append(current.output, index)
}

// buildFailureLinks constructs failure links using BFS.
// Failure links enable efficient backtracking when a pattern doesn't match.
func (m *Matcher) buildFailureLinks() {
	queue := make([]*node, 0)

	// Level 1 nodes fail to root
	for _, child := range m.root.children {
		child.fail = m.root
		queue = append(queue, child)
	}

	// BFS to build failure links for deeper nodes
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for r, child := range current.children {
			queue = append(queue, child)

			// Follow failure links to find longest proper suffix
			fail := current.fail
			for fail != nil {
				if next, ok := fail.children[r]; ok {
					child.fail = next
					child.output = append(child.output, next.output...)
					break
				}
				fail = fail.fail
			}
			if child.fail == nil {
				child.fail = m.root
			}
		}
	}
}

// Match returns true if any pattern matches in the text.
//
// Parameters:
//   - text: String to search (case-insensitive)
//
// Returns:
//   - true if any pattern is found
//   - false if no patterns match
//
// Complexity: O(text length)
//
// Use Case: Fast pre-filtering before expensive regex matching.
func (m *Matcher) Match(text string) bool {
	if m.root == nil || len(m.patterns) == 0 {
		return false
	}

	current := m.root
	for _, r := range text {
		r = toLower(r)

		// Follow failure links until we find a match or reach root
		for current != m.root {
			if _, ok := current.children[r]; ok {
				break
			}
			current = current.fail
		}

		if next, ok := current.children[r]; ok {
			current = next
		}

		// Check if we're at a matching state
		if len(current.output) > 0 {
			return true
		}
	}

	return false
}

// MatchAll returns indices of all patterns found in the text.
//
// Parameters:
//   - text: String to search (case-insensitive)
//
// Returns:
//   - Slice of pattern indices that matched (deduplicated)
//   - Empty slice if no matches
//
// Complexity: O(text length + number of matches)
//
// Note: Each pattern index appears at most once, even if it matches multiple times.
func (m *Matcher) MatchAll(text string) []int {
	if m.root == nil || len(m.patterns) == 0 {
		return nil
	}

	var matches []int
	seen := make(map[int]bool)

	current := m.root
	for _, r := range text {
		r = toLower(r)

		for current != m.root {
			if _, ok := current.children[r]; ok {
				break
			}
			current = current.fail
		}

		if next, ok := current.children[r]; ok {
			current = next
		}

		// Collect all matches at this state
		for _, idx := range current.output {
			if !seen[idx] {
				matches = append(matches, idx)
				seen[idx] = true
			}
		}
	}

	return matches
}

// PatternCount returns the number of patterns in the automaton.
func (m *Matcher) PatternCount() int {
	return len(m.patterns)
}

// toLower converts a rune to lowercase for case-insensitive matching.
func toLower(r rune) rune {
	return unicode.ToLower(r)
}
