package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	defaultMaxRuleSetDepth = 16
	defaultMaxRuleSetRules = 500000
	maxRuleSetBytes        = 64 << 20
)

// setLoader resolves external rule sets. A name maps to a file; the kind of the
// rule that references the name decides how the file is read.
type setLoader struct {
	paths    map[string]string
	root     string
	readFile func(string) ([]byte, error)

	maxDepth int
	maxRules int

	parsed map[string][]*Rule // parsed RULE-SET files, target-less
	kinds  map[string]Kind    // first kind each name was used with
	names  []string
	count  int
}

func newSetLoader(opts Options) *setLoader {
	read := opts.ReadFile
	if read == nil {
		read = os.ReadFile
	}
	maxDepth := opts.MaxRuleSetDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxRuleSetDepth
	}
	maxRules := opts.MaxRuleSetRules
	if maxRules <= 0 {
		maxRules = defaultMaxRuleSetRules
	}
	paths := make(map[string]string, len(opts.RuleSets))
	for k, v := range opts.RuleSets {
		paths[k] = v
	}
	return &setLoader{
		paths:    paths,
		root:     opts.Root,
		readFile: read,
		maxDepth: maxDepth,
		maxRules: maxRules,
		parsed:   make(map[string][]*Rule),
		kinds:    make(map[string]Kind),
	}
}

// path resolves a set name to a file path.
func (l *setLoader) path(name string) (string, error) {
	p, ok := l.paths[name]
	if !ok {
		return "", fmt.Errorf("rule set %q is not declared", name)
	}
	if p == "" {
		return "", fmt.Errorf("rule set %q has an empty path", name)
	}
	if !filepath.IsAbs(p) && l.root != "" {
		p = filepath.Join(l.root, p)
	}
	return p, nil
}

// read returns the file contents of a set.
func (l *setLoader) read(name string) ([]byte, error) {
	p, err := l.path(name)
	if err != nil {
		return nil, err
	}
	data, err := l.readFile(p)
	if err != nil {
		return nil, fmt.Errorf("rule set %q: %w", name, err)
	}
	if len(data) > maxRuleSetBytes {
		return nil, fmt.Errorf("rule set %q is larger than %d bytes", name, maxRuleSetBytes)
	}
	return data, nil
}

// claim records how a name is used and rejects a name that is used as both
// RULE-SET and DOMAIN-SET, since the two interpretations differ.
func (l *setLoader) claim(name string, kind Kind) error {
	if prev, ok := l.kinds[name]; ok {
		if prev != kind {
			return fmt.Errorf("rule set %q is used both as %s and as %s", name, prev, kind)
		}
		return nil
	}
	l.kinds[name] = kind
	l.names = append(l.names, name)
	return nil
}

// loadRuleSet parses a RULE-SET file and caches the target-less rules.
func (l *setLoader) loadRuleSet(name string) ([]*Rule, error) {
	if cached, ok := l.parsed[name]; ok {
		return cached, nil
	}
	data, err := l.read(name)
	if err != nil {
		return nil, err
	}
	rules, err := parseRuleSetFile(name, data)
	if err != nil {
		return nil, err
	}
	l.parsed[name] = rules
	return rules, nil
}

// expand returns the rules of a RULE-SET with every nested RULE-SET reference
// flattened. chain carries the names currently being expanded so a cycle is
// reported instead of recursing forever.
func (l *setLoader) expand(name, target string, chain []string) ([]*Rule, error) {
	if err := l.claim(name, KindRuleSet); err != nil {
		return nil, err
	}
	for _, seen := range chain {
		if seen == name {
			return nil, fmt.Errorf("rule set cycle: %s", strings.Join(append(chain, name), " -> "))
		}
	}
	if len(chain) >= l.maxDepth {
		return nil, fmt.Errorf("rule set nesting deeper than %d at %q", l.maxDepth, name)
	}
	rules, err := l.loadRuleSet(name)
	if err != nil {
		return nil, err
	}

	out := make([]*Rule, 0, len(rules))
	chain = append(chain, name)
	for _, r := range rules {
		switch r.Kind {
		case KindRuleSet:
			nested, err := l.expand(r.Payload, target, chain)
			if err != nil {
				return nil, err
			}
			out = append(out, nested...)
		case KindDomainSet:
			// Kept as one rule; its file is expanded into the domain index at
			// build time so the reference costs a single priority slot.
			if err := l.claim(r.Payload, KindDomainSet); err != nil {
				return nil, err
			}
			c := *r
			c.Target = target
			out = append(out, &c)
		default:
			c := *r
			c.Target = target
			out = append(out, &c)
		}
		l.count++
		if l.count > l.maxRules {
			return nil, fmt.Errorf("rule sets expand to more than %d rules", l.maxRules)
		}
	}
	return out, nil
}

// domainEntries loads a DOMAIN-SET file and returns its entries as plain
// domain rules without a target.
func (l *setLoader) domainEntries(name string) ([]*Rule, error) {
	if err := l.claim(name, KindDomainSet); err != nil {
		return nil, err
	}
	data, err := l.read(name)
	if err != nil {
		return nil, err
	}
	return parseDomainSetFile(name, data)
}

// usedNames lists the rule set names the program actually read, sorted.
func (l *setLoader) usedNames() []string {
	out := append([]string(nil), l.names...)
	sort.Strings(out)
	return out
}

// parseRuleSetFile reads a file of target-less rules.
func parseRuleSetFile(name string, data []byte) ([]*Rule, error) {
	lines := splitLines(data)
	out := make([]*Rule, 0, len(lines))
	for _, ln := range lines {
		text := cleanLine(ln.text)
		if text == "" {
			continue
		}
		r, err := parseRuleFields(text, false)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, ln.number, err)
		}
		if r.Kind == KindFinal {
			return nil, fmt.Errorf("%s:%d: a rule set must not contain FINAL", name, ln.number)
		}
		r.Source = name
		r.Line = ln.number
		out = append(out, r)
	}
	return out, nil
}

// parseDomainSetFile reads a plain domain list. A bare name is a suffix entry;
// an explicit DOMAIN or DOMAIN-SUFFIX prefix is honoured.
func parseDomainSetFile(name string, data []byte) ([]*Rule, error) {
	lines := splitLines(data)
	out := make([]*Rule, 0, len(lines))
	for _, ln := range lines {
		text := cleanLine(ln.text)
		if text == "" {
			continue
		}
		r := &Rule{Source: name, Line: ln.number, index: -1}
		if strings.Contains(text, ",") {
			parsed, err := parseRuleFields(text, false)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", name, ln.number, err)
			}
			if parsed.Kind != KindDomain && parsed.Kind != KindDomainSuffix {
				return nil, fmt.Errorf("%s:%d: a domain set holds DOMAIN and DOMAIN-SUFFIX entries, not %s", name, ln.number, parsed.Kind)
			}
			*r = *parsed
			r.Source = name
			r.Line = ln.number
			out = append(out, r)
			continue
		}
		domain, err := normaliseName(text)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, ln.number, err)
		}
		r.Kind = KindDomainSuffix
		r.Payload = domain
		out = append(out, r)
	}
	return out, nil
}

// sourceLine is one line of a text file with its 1-based number.
type sourceLine struct {
	number int
	text   string
}

func splitLines(data []byte) []sourceLine {
	text := strings.TrimPrefix(string(data), "\ufeff")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	raw := strings.Split(text, "\n")
	out := make([]sourceLine, 0, len(raw))
	for i, l := range raw {
		out = append(out, sourceLine{number: i + 1, text: l})
	}
	return out
}

// cleanLine trims a line, drops full-line comments and strips a trailing
// comment introduced by whitespace followed by # or ;.
func cleanLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "//") {
		return ""
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c == '#' || c == ';') && (s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}
