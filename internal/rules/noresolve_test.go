package rules

import (
	"net"
	"strings"
	"testing"
)

// TestNoResolveSkipsALookedUpAddress is the core of the no-resolve semantics: a
// rule that carries the flag only applies to an address the client supplied, so
// a name whose address came from a lookup must fall through to the next rule
// that covers the same prefix.
func TestNoResolveSkipsALookedUpAddress(t *testing.T) {
	p := compileLines(t, []string{
		"IP-CIDR,10.0.0.0/8,Guarded,no-resolve", // 0
		"IP-CIDR,10.0.0.0/8,Open",               // 1
		"FINAL,DIRECT",                          // 2
	}, Options{})

	addr := net.ParseIP("10.1.2.3")
	tests := []struct {
		name    string
		query   Query
		want    string
		wantIdx int
	}{
		{
			name:    "address the client supplied",
			query:   Query{Addr: addr, Port: 443, Network: "tcp"},
			want:    "Guarded",
			wantIdx: 0,
		},
		{
			name:    "address obtained by a lookup",
			query:   Query{Name: "inside.example.com", Addr: addr, Resolved: true, Port: 443, Network: "tcp"},
			want:    "Open",
			wantIdx: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision, ok := p.Match(tc.query)
			if !ok {
				t.Fatal("no rule matched")
			}
			if decision.Target != tc.want || decision.Rule.Index() != tc.wantIdx {
				t.Fatalf("decision = %s, want %s at index %d", decision, tc.want, tc.wantIdx)
			}
		})
	}
}

// TestNoResolveKeepsIPv6RulesApart is the same check for the IPv6 table, which
// has its own index.
func TestNoResolveKeepsIPv6RulesApart(t *testing.T) {
	p := compileLines(t, []string{
		"IP-CIDR6,2001:db8::/32,Guarded,no-resolve",
		"IP-CIDR6,2001:db8::/32,Open",
		"FINAL,DIRECT",
	}, Options{})

	addr := net.ParseIP("2001:db8::1")
	if got, _ := p.Match(Query{Addr: addr}); got.Target != "Guarded" {
		t.Fatalf("literal address matched %s, want Guarded", got)
	}
	if got, _ := p.Match(Query{Name: "v6.example.com", Addr: addr, Resolved: true}); got.Target != "Open" {
		t.Fatalf("resolved address matched %s, want Open", got)
	}
}

// TestNoResolveSkipsGeoAndASN checks the rule-by-rule dimensions, which keep
// their own lists rather than an index.
func TestNoResolveSkipsGeoAndASN(t *testing.T) {
	geo, err := NewMemGeoIP(map[string][]string{"CN": {"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("NewMemGeoIP: %v", err)
	}
	asn, err := NewMemASN(map[uint32][]string{64500: {"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("NewMemASN: %v", err)
	}
	p := compileLines(t, []string{
		"GEOIP,CN,Guarded,no-resolve",
		"IP-ASN,64500,Guarded,no-resolve",
		"GEOIP,CN,Open",
		"IP-ASN,64500,Open",
		"FINAL,DIRECT",
	}, Options{GeoIP: geo, ASN: asn})

	addr := net.ParseIP("203.0.113.9")
	literal, ok := p.Match(Query{Addr: addr})
	if !ok || literal.Target != "Guarded" || literal.Rule.Index() != 0 {
		t.Fatalf("literal address decided %s, want Guarded at index 0", literal)
	}
	resolved, ok := p.Match(Query{Name: "cn.example.com", Addr: addr, Resolved: true})
	if !ok || resolved.Target != "Open" || resolved.Rule.Index() != 2 {
		t.Fatalf("resolved address decided %s, want Open at index 2", resolved)
	}
}

// TestNoResolveDoesNotChangeNameRules checks that resolving a name for an
// address rule still lets every name rule take part: the flag narrows address
// rules only.
func TestNoResolveDoesNotChangeNameRules(t *testing.T) {
	p := compileLines(t, []string{
		"DOMAIN-SUFFIX,example.com,Named",
		"IP-CIDR,10.0.0.0/8,Guarded,no-resolve",
		"FINAL,DIRECT",
	}, Options{})

	got, ok := p.Match(Query{Name: "a.example.com", Addr: net.ParseIP("10.7.7.7"), Resolved: true})
	if !ok || got.Target != "Named" || got.Rule.Index() != 0 {
		t.Fatalf("decision = %s, want Named at index 0", got)
	}
}

// TestNeedsResolution checks the predicate the pipeline uses to decide whether a
// lookup is worth doing at all.
func TestNeedsResolution(t *testing.T) {
	geo, err := NewMemGeoIP(map[string][]string{"CN": {"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("NewMemGeoIP: %v", err)
	}
	tests := []struct {
		name  string
		lines []string
		opts  Options
		want  bool
	}{
		{
			name:  "no address rule",
			lines: []string{"DOMAIN-SUFFIX,example.com,Proxy", "FINAL,DIRECT"},
			want:  false,
		},
		{
			name:  "address rule without the flag",
			lines: []string{"IP-CIDR,10.0.0.0/8,Proxy", "FINAL,DIRECT"},
			want:  true,
		},
		{
			name:  "every address rule carries the flag",
			lines: []string{"IP-CIDR,10.0.0.0/8,Proxy,no-resolve", "IP-CIDR6,2001:db8::/32,Proxy,no-resolve", "FINAL,DIRECT"},
			want:  false,
		},
		{
			name:  "a port rule does not need an address",
			lines: []string{"IP-CIDR,10.0.0.0/8,Proxy,no-resolve", "DEST-PORT,8080,Proxy", "FINAL,DIRECT"},
			want:  false,
		},
		{
			name:  "one open address rule among closed ones",
			lines: []string{"IP-CIDR,10.0.0.0/8,Proxy,no-resolve", "IP-CIDR,192.0.2.0/24,Proxy", "FINAL,DIRECT"},
			want:  true,
		},
		{
			name:  "geoip with the flag",
			lines: []string{"GEOIP,CN,DIRECT,no-resolve", "FINAL,Proxy"},
			opts:  Options{GeoIP: geo},
			want:  false,
		},
		{
			name:  "geoip without the flag",
			lines: []string{"GEOIP,CN,DIRECT", "FINAL,Proxy"},
			opts:  Options{GeoIP: geo},
			want:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := compileLines(t, tc.lines, tc.opts)
			if got := p.NeedsResolution(); got != tc.want {
				t.Fatalf("NeedsResolution = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestExplainReportsSuppressedRule checks that the report says why a prefix that
// covers the address did not decide the request.
func TestExplainReportsSuppressedRule(t *testing.T) {
	p := compileLines(t, []string{
		"IP-CIDR,10.0.0.0/8,Guarded,no-resolve",
		"FINAL,DIRECT",
	}, Options{})

	exp := p.Explain(Query{Name: "inside.example.com", Addr: net.ParseIP("10.1.2.3"), Resolved: true})
	if exp.Matched != true || exp.Decision.Target != "DIRECT" {
		t.Fatalf("decision = %s, want FINAL", exp.Decision)
	}
	var detail string
	for _, step := range exp.Steps {
		if step.Kind == KindIPCIDR {
			detail = step.Detail
			if step.Match {
				t.Fatalf("the no-resolve rule reported a match: %+v", step)
			}
		}
	}
	if !strings.Contains(detail, "no-resolve") || !strings.Contains(detail, "10.0.0.0/8") {
		t.Fatalf("IP-CIDR detail = %q, want it to name the suppressed rule", detail)
	}

	// The same query with a literal address must hit the guarded rule, and the
	// report must then show the hit.
	exp = p.Explain(Query{Addr: net.ParseIP("10.1.2.3")})
	if !exp.Matched || exp.Decision.Target != "Guarded" {
		t.Fatalf("literal address decided %s, want Guarded", exp.Decision)
	}
}

// TestExplanationRendersResolution checks the report line that separates "no
// lookup was made" from "the address came from here", which is what makes an
// explanation answer the question the flag exists for.
func TestExplanationRendersResolution(t *testing.T) {
	p := compileLines(t, []string{"FINAL,DIRECT"}, Options{})

	tests := []struct {
		name       string
		resolution *Resolution
		want       string
	}{
		{
			name: "no lookup was made",
			resolution: &Resolution{
				Note: "no address rule can use a resolved address",
			},
			want: "resolution: not attempted: no address rule can use a resolved address",
		},
		{
			name:       "static mapping",
			resolution: &Resolution{Source: "hosts", Addrs: []net.IP{net.ParseIP("203.0.113.5")}},
			want:       "resolution: 203.0.113.5 (hosts)",
		},
		{
			name:       "failed lookup",
			resolution: &Resolution{Err: "no such host"},
			want:       "resolution: failed: no such host",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exp := p.Explain(Query{Name: "a.example.com"})
			exp.Resolution = tc.resolution
			if got := exp.String(); !strings.Contains(got, tc.want) {
				t.Fatalf("report =\n%s\nwant a line %q", got, tc.want)
			}
		})
	}
}

// TestQueryDescribesAResolvedAddress checks that a report cannot be read as if
// the client had supplied the address.
func TestQueryDescribesAResolvedAddress(t *testing.T) {
	p := compileLines(t, []string{"FINAL,DIRECT"}, Options{})
	exp := p.Explain(Query{Name: "a.example.com", Addr: net.ParseIP("203.0.113.5"), Resolved: true})
	if report := exp.String(); !strings.Contains(report, "addr=203.0.113.5(resolved)") {
		t.Fatalf("report =\n%s\nwant the address marked as resolved", report)
	}
}

// TestNoResolveSurvivesARuleSet checks that the flag belongs to the rule, not to
// the line it was written on: a rule set that carries it must keep it through
// expansion, or a shared rule set would silently start resolving names for every
// configuration that references it.
func TestNoResolveSurvivesARuleSet(t *testing.T) {
	files := map[string]string{"guarded": "IP-CIDR,10.0.0.0/8,no-resolve"}
	p := compileLines(t, []string{
		"RULE-SET,guarded,Guarded",
		"IP-CIDR,10.0.0.0/8,Open",
		"FINAL,DIRECT",
	}, Options{RuleSets: map[string]string{"guarded": "guarded"}, ReadFile: readFileMap(files)})

	addr := net.ParseIP("10.4.5.6")
	if got, _ := p.Match(Query{Addr: addr}); got.Target != "Guarded" {
		t.Fatalf("literal address matched %s, want Guarded", got)
	}
	if got, _ := p.Match(Query{Name: "inside.example.com", Addr: addr, Resolved: true}); got.Target != "Open" {
		t.Fatalf("resolved address matched %s, want Open: the flag was lost in expansion", got)
	}
	if !p.NeedsResolution() {
		t.Fatal("NeedsResolution = false, want true: the second rule accepts a lookup")
	}
}
