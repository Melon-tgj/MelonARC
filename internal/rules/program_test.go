package rules

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

// compileLines parses rule lines and compiles them with the given options.
func compileLines(t *testing.T, lines []string, opts Options) *Program {
	t.Helper()
	rules := make([]*Rule, 0, len(lines))
	for i, line := range lines {
		r, err := ParseRule(line)
		if err != nil {
			t.Fatalf("line %d %q: %v", i+1, line, err)
		}
		r.Source = "config"
		r.Line = i + 1
		rules = append(rules, r)
	}
	opts.Rules = rules
	p, err := Compile(opts)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return p
}

// mixedRules exercises every literal rule kind in a single ordered list.
var mixedRules = []string{
	"DOMAIN,exact.example.com,DIRECT",        // 0
	"DOMAIN-SUFFIX,sub.example.com,ProxySub", // 1
	"DOMAIN-SUFFIX,example.com,Proxy",        // 2
	"DOMAIN-KEYWORD,tracker,REJECT",          // 3
	"IP-CIDR,10.1.2.0/24,Proxy",              // 4
	"IP-CIDR,10.0.0.0/8,DIRECT",              // 5
	"IP-CIDR6,2001:db8::/32,Proxy6",          // 6
	"DEST-PORT,8080,Proxy",                   // 7
	"DEST-PORT,9000-9100,DIRECT",             // 8
	"PROTOCOL,udp,REJECT",                    // 9
	"FINAL,Fallback",                         // 10
}

func TestMatchByKind(t *testing.T) {
	p := compileLines(t, mixedRules, Options{})

	ip := func(s string) []byte { return net.ParseIP(s) }
	tests := []struct {
		name    string
		q       Query
		want    string
		wantIdx int
	}{
		{name: "exact domain", q: Query{Name: "exact.example.com", Port: 443, Network: "tcp"}, want: "DIRECT", wantIdx: 0},
		{name: "exact domain case and trailing dot", q: Query{Name: "EXACT.Example.COM."}, want: "DIRECT", wantIdx: 0},
		{name: "longer suffix wins by order", q: Query{Name: "a.sub.example.com"}, want: "ProxySub", wantIdx: 1},
		{name: "parent suffix", q: Query{Name: "a.example.com"}, want: "Proxy", wantIdx: 2},
		{name: "suffix matches itself", q: Query{Name: "example.com"}, want: "Proxy", wantIdx: 2},
		{name: "keyword", q: Query{Name: "cdn.tracker.io"}, want: "REJECT", wantIdx: 3},
		{name: "keyword at start", q: Query{Name: "tracker.io"}, want: "REJECT", wantIdx: 3},
		{name: "keyword inside a label", q: Query{Name: "mytrackers.io"}, want: "REJECT", wantIdx: 3},
		{name: "ipv4 narrow prefix", q: Query{Addr: ip("10.1.2.7")}, want: "Proxy", wantIdx: 4},
		{name: "ipv4 wide prefix", q: Query{Addr: ip("10.9.0.1")}, want: "DIRECT", wantIdx: 5},
		{name: "ipv6 prefix", q: Query{Addr: ip("2001:db8::5")}, want: "Proxy6", wantIdx: 6},
		{name: "ipv6 outside prefix", q: Query{Addr: ip("2001:db9::5")}, want: "Fallback", wantIdx: 10},
		{name: "single port", q: Query{Port: 8080}, want: "Proxy", wantIdx: 7},
		{name: "port range", q: Query{Port: 9050}, want: "DIRECT", wantIdx: 8},
		{name: "port outside range", q: Query{Port: 22}, want: "Fallback", wantIdx: 10},
		{name: "protocol", q: Query{Network: "udp"}, want: "REJECT", wantIdx: 9},
		{name: "unknown protocol", q: Query{Network: "sctp"}, want: "Fallback", wantIdx: 10},
		{name: "nothing known", q: Query{}, want: "Fallback", wantIdx: 10},
		{name: "earlier domain beats later port", q: Query{Name: "example.com", Port: 8080}, want: "Proxy", wantIdx: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := p.Match(tc.q)
			if !ok {
				t.Fatalf("Match(%+v) did not match, want %q", tc.q, tc.want)
			}
			if got.Target != tc.want {
				t.Errorf("target = %q, want %q", got.Target, tc.want)
			}
			if got.Rule.Index() != tc.wantIdx {
				t.Errorf("rule index = %d (%s), want %d", got.Rule.Index(), got.Rule, tc.wantIdx)
			}
		})
	}
}

func TestMatchWithoutFinal(t *testing.T) {
	p := compileLines(t, []string{"DOMAIN,example.com,Proxy"}, Options{})
	if _, ok := p.Match(Query{Name: "other.org"}); ok {
		t.Fatal("expected no match without a FINAL rule")
	}
}

func TestSuffixNeedsLabelBoundary(t *testing.T) {
	p := compileLines(t, []string{"DOMAIN-SUFFIX,example.com,Proxy", "FINAL,DIRECT"}, Options{})
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"a.example.com", true},
		{"a.b.example.com", true},
		{"EXAMPLE.COM", true},
		{"notexample.com", false},
		{"example.com.evil", false},
		{"example.co", false},
		{"", false},
	}
	for _, tc := range tests {
		got, _ := p.Match(Query{Name: tc.host})
		if (got.Target == "Proxy") != tc.want {
			t.Errorf("%q: matched suffix = %v, want %v", tc.host, got.Target == "Proxy", tc.want)
		}
	}
}

// TestNestedPrefixFirstMatchWins pins that rule order, not prefix length,
// decides nested blocks.
func TestNestedPrefixFirstMatchWins(t *testing.T) {
	tests := []struct {
		name  string
		rules []string
		addr  string
		want  string
	}{
		{
			name:  "wide block first",
			rules: []string{"IP-CIDR,10.0.0.0/8,DIRECT", "IP-CIDR,10.1.2.0/24,Proxy", "FINAL,REJECT"},
			addr:  "10.1.2.9",
			want:  "DIRECT",
		},
		{
			name:  "narrow block first",
			rules: []string{"IP-CIDR,10.1.2.0/24,Proxy", "IP-CIDR,10.0.0.0/8,DIRECT", "FINAL,REJECT"},
			addr:  "10.1.2.9",
			want:  "Proxy",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := compileLines(t, tc.rules, Options{})
			got, _ := p.Match(Query{Addr: net.ParseIP(tc.addr)})
			if got.Target != tc.want {
				t.Fatalf("target = %q, want %q", got.Target, tc.want)
			}
		})
	}
}

func TestAddressFamiliesDoNotLeak(t *testing.T) {
	p := compileLines(t, []string{"IP-CIDR,10.0.0.0/8,DIRECT", "FINAL,Proxy"}, Options{})
	// 10.0.0.0/8 has no meaning for an IPv6 address, even though the low bytes
	// of ::a00:0 would match a naive 32-bit comparison.
	got, _ := p.Match(Query{Addr: net.ParseIP("::a00:1")})
	if got.Target != "Proxy" {
		t.Fatalf("IPv6 address matched an IPv4 prefix: %s", got)
	}
}

func TestExplain(t *testing.T) {
	p := compileLines(t, mixedRules, Options{})
	e := p.Explain(Query{Name: "a.example.com", Port: 443, Network: "tcp"})
	if !e.Matched {
		t.Fatal("expected a match")
	}
	if e.Decision.Target != "Proxy" || e.Decision.Rule.Index() != 2 {
		t.Fatalf("decision = %s", e.Decision)
	}
	if len(e.Steps) < 3 {
		t.Fatalf("expected several steps, got %d", len(e.Steps))
	}
	var hit bool
	for _, s := range e.Steps {
		if s.Match && s.Index == 2 {
			hit = true
		}
	}
	if !hit {
		t.Error("the winning rule is not recorded in the steps")
	}
	text := e.String()
	for _, want := range []string{"query: name=a.example.com", "DOMAIN-SUFFIX", "decision: #2"} {
		if !strings.Contains(text, want) {
			t.Errorf("explanation does not contain %q:\n%s", want, text)
		}
	}
}

func TestExplainWithoutName(t *testing.T) {
	p := compileLines(t, mixedRules, Options{})
	e := p.Explain(Query{Addr: net.ParseIP("10.1.2.3")})
	if got := e.Decision.Target; got != "Proxy" {
		t.Fatalf("target = %q", got)
	}
	if !strings.Contains(e.String(), "skipped: query carries no name") {
		t.Errorf("explanation should record that the name dimension was skipped:\n%s", e.String())
	}
}

func TestExplainNoMatch(t *testing.T) {
	p := compileLines(t, []string{"DOMAIN,example.com,Proxy"}, Options{})
	e := p.Explain(Query{Name: "other.org"})
	if e.Matched {
		t.Fatal("unexpected match")
	}
	if !strings.Contains(e.String(), "no rule matched") {
		t.Errorf("unexpected report:\n%s", e.String())
	}
}

func TestExplainMarksMisses(t *testing.T) {
	p := compileLines(t, mixedRules, Options{})
	e := p.Explain(Query{Name: "other.org", Port: 443, Network: "tcp"})
	if got := e.Decision.Target; got != "Fallback" {
		t.Fatalf("target = %q", got)
	}
	for _, s := range e.Steps {
		if !s.Match && s.Index != -1 {
			t.Errorf("miss for %s reported index %d, want -1", s.Kind, s.Index)
		}
	}
	// The decision is reported once, as the footer of the report, not as an
	// extra step that repeats the winning rule.
	wins := 0
	for _, s := range e.Steps {
		if s.Match {
			wins++
		}
	}
	if wins > 1 {
		t.Errorf("%d steps claim a hit, want at most one per dimension", wins)
	}
	if !strings.HasSuffix(strings.TrimSpace(e.String()), "decision: #"+strconv.Itoa(e.Decision.Rule.Index())+" "+e.Decision.Rule.String()+" -> "+e.Decision.Target) {
		t.Errorf("report does not end with the decision:\n%s", e.String())
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{
			name: "no rules",
			opts: Options{},
			want: "no rules",
		},
		{
			name: "geoip without database",
			opts: Options{Rules: mustParse(t, "GEOIP,CN,DIRECT")},
			want: "needs a GEOIP database",
		},
		{
			name: "asn without database",
			opts: Options{Rules: mustParse(t, "IP-ASN,13335,DIRECT")},
			want: "needs an ASN database",
		},
		{
			name: "undeclared rule set",
			opts: Options{Rules: mustParse(t, "RULE-SET,missing,REJECT")},
			want: "not declared",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.opts)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func mustParse(t *testing.T, lines ...string) []*Rule {
	t.Helper()
	out := make([]*Rule, 0, len(lines))
	for _, l := range lines {
		r, err := ParseRule(l)
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", l, err)
		}
		out = append(out, r)
	}
	return out
}

func TestStats(t *testing.T) {
	p := compileLines(t, []string{
		"DOMAIN,a.example.com,DIRECT",
		"DOMAIN-SUFFIX,example.com,Proxy",
		"IP-CIDR,10.0.0.0/8,DIRECT",
		"IP-CIDR6,2001:db8::/32,DIRECT",
		"FINAL,Proxy",
	}, Options{})
	s := p.Stats()
	if s.Total != 5 || !s.Final {
		t.Fatalf("stats = %+v", s)
	}
	if s.Domains != 1 || s.Suffixes != 1 || s.Ranges4 != 1 || s.Ranges6 != 1 {
		t.Fatalf("index sizes = %+v", s)
	}
	if s.ByKind[KindIPCIDR] != 1 || s.ByKind[KindFinal] != 1 {
		t.Fatalf("kind counts = %+v", s.ByKind)
	}
}

func TestRulesCopyIsImmutable(t *testing.T) {
	p := compileLines(t, []string{"DOMAIN,example.com,Proxy", "FINAL,DIRECT"}, Options{})
	rules := p.Rules()
	rules[0] = nil
	if p.Rules()[0] == nil {
		t.Fatal("Rules() exposed the internal slice")
	}
	if p.Len() != 2 {
		t.Fatalf("Len() = %d", p.Len())
	}
}

func TestQueryPortOutOfRangeIsIgnored(t *testing.T) {
	p := compileLines(t, []string{"DEST-PORT,8080,Proxy", "FINAL,DIRECT"}, Options{})
	got, _ := p.Match(Query{Port: 70000})
	if got.Target != "DIRECT" {
		t.Fatalf("out of range port matched: %s", got)
	}
}

func TestOriginFormatting(t *testing.T) {
	r := &Rule{Kind: KindDomain, Payload: "a.example.com", Target: "Proxy", Source: "ads", Line: 12}
	if got := r.Origin(); got != "ads:12" {
		t.Fatalf("Origin() = %q", got)
	}
	r.Line = 0
	if got := r.Origin(); got != "ads" {
		t.Fatalf("Origin() = %q", got)
	}
}

var errNotExist = errors.New("file does not exist")

func readFileMap(files map[string]string) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		if data, ok := files[path]; ok {
			return []byte(data), nil
		}
		return nil, fmt.Errorf("%w: %s", errNotExist, path)
	}
}
