package rules

import "strings"

// domainIndex holds the name-based indexes: an exact map for DOMAIN, a label
// trie for DOMAIN-SUFFIX and the expansions of DOMAIN-SET, and a first-byte
// bucketed keyword list for DOMAIN-KEYWORD.
type domainIndex struct {
	exact      map[string]int32
	suffix     *suffixNode
	suffixSize int
	kw         [256][]keywordEntry
	kwCount    int
}

type suffixNode struct {
	children map[string]*suffixNode
	idx      int32 // -1 when no rule ends here
	payload  string
}

type keywordEntry struct {
	word string
	idx  int32
}

func newDomainIndex() *domainIndex {
	return &domainIndex{exact: make(map[string]int32), suffix: newSuffixNode()}
}

func newSuffixNode() *suffixNode { return &suffixNode{idx: -1} }

// addExact registers a DOMAIN rule. The first rule registered for a name wins,
// so a later rule can never take priority away from an earlier one.
func (d *domainIndex) addExact(name string, idx int32) {
	if _, ok := d.exact[name]; !ok {
		d.exact[name] = idx
	}
}

// addSuffix registers a DOMAIN-SUFFIX rule, or one name of a DOMAIN-SET.
func (d *domainIndex) addSuffix(name string, idx int32, payload string) {
	if name == "" {
		return
	}
	node := d.suffix
	labels := strings.Split(name, ".")
	// Labels are walked from the right so that a suffix and every name below
	// it share a path; the deepest terminal is the longest match.
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if node.children == nil {
			node.children = make(map[string]*suffixNode, 4)
		}
		next, ok := node.children[label]
		if !ok {
			next = newSuffixNode()
			node.children[label] = next
		}
		node = next
	}
	if node.idx < 0 {
		node.idx = idx
		node.payload = payload
		d.suffixSize++
	}
}

// addKeyword registers a DOMAIN-KEYWORD rule.
func (d *domainIndex) addKeyword(word string, idx int32) {
	if word == "" {
		return
	}
	b := word[0]
	if !isASCIILower(b) {
		b = toASCIILower(b)
	}
	d.kw[b] = append(d.kw[b], keywordEntry{word: word, idx: idx})
	d.kwCount++
}

// matchExact returns the DOMAIN rule for an already lower-cased name.
func (d *domainIndex) matchExact(lower string) (int32, bool) {
	idx, ok := d.exact[lower]
	return idx, ok
}

// matchSuffix walks the trie label by label and returns the lowest rule index
// among the terminals on the path, together with the payload that produced it.
func (d *domainIndex) matchSuffix(lower string) (idx int32, payload string, ok bool) {
	idx = -1
	node := d.suffix
	for end := len(lower); end > 0; {
		start := strings.LastIndexByte(lower[:end], '.') + 1
		node = node.children[lower[start:end]]
		if node == nil {
			break
		}
		if node.idx >= 0 && (idx < 0 || node.idx < idx) {
			idx, payload = node.idx, node.payload
		}
		if start == 0 {
			break
		}
		end = start - 1
	}
	return idx, payload, idx >= 0
}

// matchKeyword scans the buckets for every start position of the name and
// returns the lowest rule index among the keywords found.
func (d *domainIndex) matchKeyword(lower string) (idx int32, word string, ok bool) {
	idx = -1
	for i := 0; i < len(lower); i++ {
		bucket := d.kw[lower[i]]
		if len(bucket) == 0 {
			continue
		}
		rest := lower[i:]
		for _, e := range bucket {
			if len(e.word) > len(rest) || rest[:len(e.word)] != e.word {
				continue
			}
			if idx < 0 || e.idx < idx {
				idx, word = e.idx, e.word
			}
		}
	}
	return idx, word, idx >= 0
}

func isASCIILower(c byte) bool { return c >= 'a' && c <= 'z' }

func toASCIILower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// lowerASCII lower-cases a host name without allocating when the name is
// already lower case. Names longer than the scratch buffer fall back to
// strings.ToLower.
func lowerASCII(s string, scratch []byte) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 'A' || c > 'Z' {
			continue
		}
		if len(s) > len(scratch) {
			return strings.ToLower(s)
		}
		n := copy(scratch, s)
		buf := scratch[:n]
		for j := i; j < n; j++ {
			buf[j] = toASCIILower(buf[j])
		}
		return string(buf)
	}
	return s
}

// suffixHasRules reports whether the suffix trie holds any terminal.
func (d *domainIndex) suffixHasRules() bool { return d.suffixSize > 0 }

// trimTrailingDot removes the root label from a fully qualified name.
func trimTrailingDot(s string) string {
	for len(s) > 1 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}
