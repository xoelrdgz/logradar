package ahocorasick

import "unicode"

type Matcher struct {
	root     *node
	patterns []string
}

type node struct {
	children map[rune]*node
	fail     *node
	output   []int
	depth    int
}

func New(patterns []string) *Matcher {
	m := &Matcher{
		root:     newNode(0),
		patterns: patterns,
	}

	for i, pattern := range patterns {
		m.addPattern(pattern, i)
	}

	m.buildFailureLinks()

	return m
}

func newNode(depth int) *node {
	return &node{
		children: make(map[rune]*node),
		depth:    depth,
	}
}

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

func (m *Matcher) buildFailureLinks() {
	queue := make([]*node, 0)

	for _, child := range m.root.children {
		child.fail = m.root
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for r, child := range current.children {
			queue = append(queue, child)

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

func (m *Matcher) Match(text string) bool {
	if m.root == nil || len(m.patterns) == 0 {
		return false
	}

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

		if len(current.output) > 0 {
			return true
		}
	}

	return false
}

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

		for _, idx := range current.output {
			if !seen[idx] {
				matches = append(matches, idx)
				seen[idx] = true
			}
		}
	}

	return matches
}

func (m *Matcher) PatternCount() int {
	return len(m.patterns)
}

func toLower(r rune) rune {
	return unicode.ToLower(r)
}
