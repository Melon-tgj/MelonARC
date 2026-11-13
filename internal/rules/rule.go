package rules

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Rule is one parsed rule: a kind, the pattern it matches, the target it
// dispatches to and where it came from.
//
// Rules are created by ParseRule or by loading a rule set, then compiled into a
// Program. A compiled rule remembers its position in the program, which is its
// priority: lower index wins.
type Rule struct {
	Kind    Kind
	Payload string // normalised pattern; the set name for RULE-SET / DOMAIN-SET
	Target  string // outbound, policy group or built-in action
	// NoResolve tells the resolver not to turn the destination name into an
	// address before matching. It is only meaningful for address rules and is
	// carried through compilation untouched.
	NoResolve bool
	// Source is "config" for rules that came from the main configuration and
	// the rule set name for rules that were expanded from one.
	Source string
	// Line is the 1-based line the rule was read from, or 0 when unknown.
	Line int

	index int32 // position in the compiled program, -1 before compilation
}

// Index returns the rule's position in the program it was compiled into, or -1
// when the rule was never compiled.
func (r *Rule) Index() int { return int(r.index) }

// String renders the rule in configuration syntax.
func (r *Rule) String() string {
	var b strings.Builder
	b.WriteString(string(r.Kind))
	if r.Kind != KindFinal {
		b.WriteString(",")
		b.WriteString(r.Payload)
	}
	b.WriteString(",")
	b.WriteString(r.Target)
	if r.NoResolve {
		b.WriteString(",no-resolve")
	}
	return b.String()
}

// Origin describes where the rule was read from, for error messages and for
// the match explanation.
func (r *Rule) Origin() string {
	if r.Line == 0 {
		return r.Source
	}
	return fmt.Sprintf("%s:%d", r.Source, r.Line)
}

// ErrTargetMissing is returned when a rule line carries no target.
var ErrTargetMissing = errors.New("rule has no target")

// ParseRule parses one rule line in the form
//
//	KIND,payload,target[,no-resolve]
//
// The type token is case insensitive; payloads are normalised (domains and
// protocol names to lower case, prefixes to their network form).
func ParseRule(line string) (*Rule, error) {
	r, err := parseRuleFields(line, true)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// parseRuleFields parses a rule line. When wantTarget is false the line must
// not carry a target, which is the shape used inside rule set files: the rule
// that references the set supplies the target.
func parseRuleFields(line string, wantTarget bool) (*Rule, error) {
	fields, err := splitFields(line)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, errors.New("empty rule")
	}
	kind, ok := ParseKind(fields[0])
	if !ok {
		return nil, fmt.Errorf("unknown rule type %q", fields[0])
	}
	r := &Rule{Kind: kind, index: -1}

	rest := fields[1:]
	// Strip the optional trailing no-resolve flag before positional parsing.
	if n := len(rest); n > 0 && strings.EqualFold(rest[n-1], "no-resolve") {
		if !kind.AllowsNoResolve() {
			return nil, fmt.Errorf("%s does not accept no-resolve", kind)
		}
		r.NoResolve = true
		rest = rest[:n-1]
	}

	if kind == KindFinal {
		switch {
		case len(rest) == 0 && wantTarget:
			return nil, ErrTargetMissing
		case len(rest) == 0:
			return r, nil
		case len(rest) > 1:
			return nil, fmt.Errorf("FINAL takes only a target, got %d fields", len(rest))
		}
		if err := validateTarget(rest[0]); err != nil {
			return nil, err
		}
		r.Target = rest[0]
		return r, nil
	}

	if len(rest) == 0 {
		return nil, fmt.Errorf("%s has no payload", kind)
	}
	payload := rest[0]
	rest = rest[1:]

	switch len(rest) {
	case 0:
		if wantTarget {
			return nil, ErrTargetMissing
		}
	case 1:
		if !wantTarget {
			return nil, fmt.Errorf("%s must not carry a target inside a rule set", kind)
		}
		if err := validateTarget(rest[0]); err != nil {
			return nil, err
		}
		r.Target = rest[0]
	default:
		return nil, fmt.Errorf("%s has too many fields (%d)", kind, len(fields))
	}

	norm, err := normalisePayload(kind, payload)
	if err != nil {
		return nil, err
	}
	r.Payload = norm
	return r, nil
}

// splitFields splits on commas, trims every field and rejects empty ones so a
// stray comma is reported instead of silently shifting the arguments.
func splitFields(line string) ([]string, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}
	raw := strings.Split(line, ",")
	fields := make([]string, 0, len(raw))
	for i, f := range raw {
		f = strings.TrimSpace(f)
		if f == "" {
			return nil, fmt.Errorf("empty field %d", i+1)
		}
		fields = append(fields, f)
	}
	return fields, nil
}

// normalisePayload validates the pattern of a rule and returns its canonical
// spelling.
func normalisePayload(kind Kind, payload string) (string, error) {
	switch kind {
	case KindDomain, KindDomainSuffix:
		d, err := normaliseName(payload)
		if err != nil {
			return "", err
		}
		if kind == KindDomain && strings.HasPrefix(d, ".") {
			return "", fmt.Errorf("DOMAIN takes an exact name, use DOMAIN-SUFFIX for %q", payload)
		}
		return d, nil

	case KindDomainKeyword:
		k := strings.ToLower(strings.TrimSpace(payload))
		if k == "" {
			return "", errors.New("empty domain keyword")
		}
		if strings.ContainsAny(k, " \t/") {
			return "", fmt.Errorf("invalid domain keyword %q", payload)
		}
		return k, nil

	case KindDomainSet, KindRuleSet:
		if err := validateSetName(payload); err != nil {
			return "", err
		}
		return payload, nil

	case KindIPCIDR, KindIPCIDR6:
		prefix, isV4, err := normaliseCIDR(payload)
		if err != nil {
			return "", err
		}
		if kind == KindIPCIDR && !isV4 {
			return "", fmt.Errorf("IP-CIDR needs an IPv4 prefix, %q is IPv6", payload)
		}
		if kind == KindIPCIDR6 && isV4 {
			return "", fmt.Errorf("IP-CIDR6 needs an IPv6 prefix, %q is IPv4", payload)
		}
		return prefix, nil

	case KindGeoIP:
		cc := strings.ToUpper(strings.TrimSpace(payload))
		if len(cc) != 2 {
			return "", fmt.Errorf("GEOIP needs a two letter country code, got %q", payload)
		}
		for i := 0; i < len(cc); i++ {
			if cc[i] < 'A' || cc[i] > 'Z' {
				return "", fmt.Errorf("invalid country code %q", payload)
			}
		}
		return cc, nil

	case KindIPASN:
		s := strings.TrimSpace(payload)
		s = strings.TrimPrefix(strings.TrimPrefix(s, "AS"), "as")
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 {
			return "", fmt.Errorf("IP-ASN needs a positive number, got %q", payload)
		}
		return strconv.FormatUint(n, 10), nil

	case KindDestPort:
		lo, hi, err := parsePortSpec(payload)
		if err != nil {
			return "", err
		}
		if lo == hi {
			return strconv.Itoa(lo), nil
		}
		return strconv.Itoa(lo) + "-" + strconv.Itoa(hi), nil

	case KindProtocol:
		p := strings.ToLower(strings.TrimSpace(payload))
		switch p {
		case "tcp", "udp":
			return p, nil
		}
		return "", fmt.Errorf("PROTOCOL supports tcp and udp, got %q", payload)
	}
	return "", fmt.Errorf("unsupported rule type %q", kind)
}

// parsePortSpec parses "443" or the inclusive range "8000-9000".
func parsePortSpec(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	loStr, hiStr, isRange := strings.Cut(s, "-")
	lo, err := parsePort(loStr)
	if err != nil {
		return 0, 0, err
	}
	hi := lo
	if isRange {
		if hi, err = parsePort(hiStr); err != nil {
			return 0, 0, err
		}
		if hi < lo {
			return 0, 0, fmt.Errorf("port range %q ends before it starts", s)
		}
	}
	return lo, hi, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return n, nil
}

// normaliseCIDR validates a prefix and returns its canonical network form, so
// that "10.1.2.3/8" and "10.0.0.0/8" are the same rule.
func normaliseCIDR(s string) (prefix string, isV4 bool, err error) {
	_, network, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return "", false, fmt.Errorf("invalid prefix %q", s)
	}
	ones, bits := network.Mask.Size()
	return network.IP.String() + "/" + strconv.Itoa(ones), bits == 32, nil
}

// normaliseName lower-cases a host name and rejects the characters that would
// make it ambiguous in a rule line.
func normaliseName(s string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(s))
	if d == "" {
		return "", errors.New("empty domain")
	}
	if strings.ContainsAny(d, " \t/\\") {
		return "", fmt.Errorf("invalid domain %q", s)
	}
	d = strings.TrimSuffix(d, ".")
	if d == "" || d == "." || strings.Contains(d, "..") {
		return "", fmt.Errorf("invalid domain %q", s)
	}
	return d, nil
}

// validateTarget checks the shape of a target name.
func validateTarget(s string) error {
	if err := validateSetName(s); err != nil {
		return fmt.Errorf("invalid target %q: %w", s, err)
	}
	return nil
}

// validateSetName checks a rule set name or a target name: a short identifier
// so that it survives round-tripping through a comma separated line.
func validateSetName(s string) error {
	if s == "" {
		return errors.New("empty name")
	}
	if len(s) > maxNameLen {
		return fmt.Errorf("name %q is longer than %d bytes", s, maxNameLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return fmt.Errorf("name %q contains an unsupported character %q", s, c)
		}
	}
	if s[0] == '.' || s[0] == '-' {
		return fmt.Errorf("name %q must start with a letter, digit or underscore", s)
	}
	return nil
}

const maxNameLen = 128
