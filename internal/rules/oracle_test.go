package rules

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/melon-tgj/melonarc/internal/geoip"
	"github.com/melon-tgj/melonarc/internal/geoip/geoiptest"
)

// This file checks the rule engine against a second, deliberately naive
// implementation of the same semantics.
//
// The engine answers a query by asking every index "which of your rules matches,
// and which has the lowest index", then taking the global minimum. That is what
// makes it fast, and it is also the part of the package a per-kind unit test
// cannot see: an interval table that keeps the wrong index for a nested prefix, a
// suffix trie that prefers the longest match over the earliest rule, a no-resolve
// rule leaking into the view a looked-up address takes.
//
// The oracle is the same semantics written the obvious way: walk the compiled
// rule list from the first entry, spell out each kind with the plainest
// expression of its documented meaning, stop at the first hit. It shares no
// index, no normalisation helper and no payload parser with the engine. The only
// things it takes from the engine are the flattened rule list — configuration,
// not computation — and the two databases it has to look up in, which is the
// point of injecting them.
//
// Both directions of trust matter. The oracle is only as good as the semantics it
// encodes, so when the two disagree the question is which side is wrong, and the
// documented behaviour in kind.go, rule.go and the tests next door decides it. A
// disagreement is never resolved by dropping the generated case or loosening the
// comparison.

// oracleRule is one compiled rule as the oracle reads it: the kind, payload,
// target and no-resolve flag the engine also sees, plus whatever the oracle
// needs to interpret the payload itself. Every field is derived from the rule
// text; none comes from an engine index.
type oracleRule struct {
	kind      Kind
	payload   string
	target    string
	noResolve bool

	// prefix is the parsed IP-CIDR / IP-CIDR6 payload.
	prefix *net.IPNet
	// portLo and portHi bound a DEST-PORT payload.
	portLo, portHi int
	// exact and suffix hold the entries of a DOMAIN-SET, as the file is meant
	// to read. They are what the set is supposed to contain, not what the
	// engine's parser made of it.
	exact  []string
	suffix []string
}

// oracle decides queries. It holds no state between calls.
type oracle struct {
	rules []oracleRule
	geo   GeoIPLookup
	asn   ASNLookup
}

// newOracle builds the oracle from a compiled program. domainSets supplies the
// entries of every DOMAIN-SET the program references, keyed by set name.
func newOracle(t *testing.T, p *Program, domainSets map[string]*oracleSet, geo GeoIPLookup, asn ASNLookup) *oracle {
	t.Helper()
	o := &oracle{geo: geo, asn: asn}
	for i, r := range p.Rules() {
		or := oracleRule{kind: r.Kind, payload: r.Payload, target: r.Target, noResolve: r.NoResolve}
		switch r.Kind {
		case KindIPCIDR, KindIPCIDR6:
			_, network, err := net.ParseCIDR(r.Payload)
			if err != nil {
				t.Fatalf("rule #%d %s: the oracle cannot parse the prefix: %v", i, r, err)
			}
			or.prefix = network
		case KindDestPort:
			lo, hi := oraclePortRange(r.Payload)
			or.portLo, or.portHi = lo, hi
		case KindDomainSet:
			set, ok := domainSets[r.Payload]
			if !ok {
				t.Fatalf("rule #%d %s: the generator declared no entries for this set", i, r)
			}
			or.exact, or.suffix = set.exact, set.suffix
		case KindRuleSet:
			// Compile expands every RULE-SET, so one reaching here means the
			// oracle is being handed a list the engine never matches against.
			t.Fatalf("rule #%d %s: RULE-SET was not expanded by Compile", i, r)
		}
		o.rules = append(o.rules, or)
	}
	return o
}

// oracleQuery is a Query taken apart the way the rules look at it.
type oracleQuery struct {
	name       string
	addr       net.IP
	family     int // 0 none, 4 or 6
	port       int
	hasPort    bool
	network    string
	fromLookup bool
}

// prepare applies the documented reading of a Query's fields: an unknown part is
// left at its zero value, so an empty name, a nil address, port 0 and an empty
// protocol all mean "not known" rather than "matches the empty value".
func oraclePrepare(q Query) oracleQuery {
	out := oracleQuery{name: oracleName(q.Name), port: q.Port, network: strings.ToLower(strings.TrimSpace(q.Network))}
	if len(q.Addr) > 0 {
		out.addr = net.IP(q.Addr)
		switch {
		case out.addr.To4() != nil:
			out.family = 4
		case out.addr.To16() != nil:
			out.family = 6
		}
	}
	out.hasPort = out.port > 0 && out.port <= 65535
	out.fromLookup = out.family != 0 && q.Resolved
	return out
}

// oracleName is the name normalisation the engine documents: trimmed, the root
// label removed, lower case. Lowering is byte-wise ASCII, which is what a host
// name needs; the generated names are ASCII, so this is exact for them. (The
// engine falls back to a full Unicode lowering when an ASCII upper-case byte is
// present, a difference that only a mixed-script name could tell apart, and the
// contract does not pin that down either way.)
func oracleName(s string) string {
	s = strings.TrimSpace(s)
	for len(s) > 1 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// oraclePortRange reads "443" or the inclusive range "8000-9000".
func oraclePortRange(spec string) (lo, hi int) {
	loStr, hiStr, isRange := strings.Cut(spec, "-")
	lo, _ = strconv.Atoi(strings.TrimSpace(loStr))
	if !isRange {
		return lo, lo
	}
	hi, _ = strconv.Atoi(strings.TrimSpace(hiStr))
	return lo, hi
}

// coversSuffix is DOMAIN-SUFFIX as documented: the name is the suffix itself or
// sits below it at a label boundary, so "example.com" covers "a.example.com" and
// not "notexample.com".
func coversSuffix(name, suffix string) bool {
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}

// match walks the rule list once, in order, and returns the first rule whose
// documented meaning covers the query.
func (o *oracle) match(q Query) (index int, target string, ok bool) {
	oq := oraclePrepare(q)
	for i := range o.rules {
		if o.rules[i].matches(&oq, o.geo, o.asn) {
			return i, o.rules[i].target, true
		}
	}
	return 0, "", false
}

// matches is one rule against one query, written kind by kind in the plainest
// form the documentation allows.
func (r *oracleRule) matches(q *oracleQuery, geo GeoIPLookup, asn ASNLookup) bool {
	switch r.kind {
	case KindDomain:
		return q.name != "" && q.name == r.payload
	case KindDomainSuffix:
		return q.name != "" && coversSuffix(q.name, r.payload)
	case KindDomainKeyword:
		return q.name != "" && strings.Contains(q.name, r.payload)
	case KindDomainSet:
		if q.name == "" {
			return false
		}
		for _, entry := range r.exact {
			if q.name == entry {
				return true
			}
		}
		for _, entry := range r.suffix {
			if coversSuffix(q.name, entry) {
				return true
			}
		}
		return false
	case KindIPCIDR, KindIPCIDR6:
		// The families are kept apart on purpose: an IPv6 address must never be
		// tested against an IPv4 prefix, however alike their low bytes look.
		if r.kind == KindIPCIDR && q.family != 4 {
			return false
		}
		if r.kind == KindIPCIDR6 && q.family != 6 {
			return false
		}
		if q.fromLookup && r.noResolve {
			return false
		}
		return r.prefix != nil && r.prefix.Contains(q.addr)
	case KindGeoIP:
		if q.family == 0 || (q.fromLookup && r.noResolve) {
			return false
		}
		code, known := geo.Country(q.addr)
		return known && strings.EqualFold(code, r.payload)
	case KindIPASN:
		if q.family == 0 || (q.fromLookup && r.noResolve) {
			return false
		}
		number, known := asn.ASN(q.addr)
		return known && strconv.FormatUint(uint64(number), 10) == r.payload
	case KindDestPort:
		return q.hasPort && q.port >= r.portLo && q.port <= r.portHi
	case KindProtocol:
		return q.network != "" && q.network == r.payload
	case KindFinal:
		return true
	}
	return false
}

// oracleSet is the content a DOMAIN-SET file is meant to hold, split the way the
// format defines: an explicit DOMAIN line is an exact entry, a bare name or an
// explicit DOMAIN-SUFFIX line is a suffix entry.
type oracleSet struct {
	exact  []string
	suffix []string
}

// file renders the set as the text the loader will read. The entries are stored
// in their normalised form; one of them is written in upper case because domain
// payloads are documented to be lower-cased, and the oracle has to hold the
// intent rather than a copy of the parser's output.
func (s *oracleSet) file() string {
	if s == nil || (len(s.exact) == 0 && len(s.suffix) == 0) {
		return ""
	}
	var b strings.Builder
	b.WriteString("# generated domain set\n")
	for i, entry := range s.exact {
		if i == 0 {
			b.WriteString("DOMAIN," + strings.ToUpper(entry) + "\n")
			continue
		}
		b.WriteString("DOMAIN," + entry + "\n")
	}
	for i, entry := range s.suffix {
		if i == 0 {
			b.WriteString("DOMAIN-SUFFIX," + entry + "\n")
			continue
		}
		if i == 1 {
			b.WriteString(entry + "  # a bare name is a suffix entry\n")
			continue
		}
		b.WriteString(entry + "\n")
	}
	return b.String()
}

// The generator's vocabulary. It is deliberately narrow and overlapping: suffixes
// share labels, prefixes nest, ports overlap, so that a shuffled list actually
// has to decide between rules instead of falling through to FINAL.
var (
	oracleTargets     = []string{"DIRECT", "REJECT", "Proxy", "Proxy-B", "Fallback"}
	oracleExactNames  = []string{"exact.alpha.example", "one.beta.test", "gamma.example", "tracker.io"}
	oracleSuffixNames = []string{"example", "alpha.example", "sub.alpha.example", "test", "beta.test", "tracker.io", "io"}
	oracleKeywords    = []string{"tracker", "alpha", "cdn", "sub"}
	oracleV4Prefixes  = []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.128/25", "192.0.2.0/24", "203.0.113.0/24", "198.51.100.0/24"}
	oracleV6Prefixes  = []string{"2001:db8::/32", "2001:db8:1::/48", "2001:db8:1:2::/64", "2001:db8:ffff::/48"}
	oraclePortSpecs   = []string{"443", "80", "8080", "9000-9100", "8000-8100", "1000-2000", "65535"}
	oracleCountries   = []string{"CN", "US", "JP"}
	oracleASNumbers   = []string{"64500", "64501", "64502"}
)

// oracleDomainSetNames lists the DOMAIN-SET declarations, one of them empty.
var oracleDomainSetNames = []string{"dset-main", "dset-sub", "dset-empty"}

// oracleDomainSets is what each domain set is meant to contain.
func oracleDomainSets() map[string]*oracleSet {
	return map[string]*oracleSet{
		"dset-main":  {exact: []string{"exact.alpha.example"}, suffix: []string{"alpha.example", "beta.test"}},
		"dset-sub":   {suffix: []string{"sub.alpha.example", "gamma.example"}},
		"dset-empty": {},
	}
}

// oracleRuleSetNames lists the RULE-SET declarations. set-b references set-a, so
// expansion is exercised through a nested reference.
var oracleRuleSetNames = []string{"set-a", "set-b"}

// oracleRuleSetFiles is the body of each rule set, in file order, as target-less
// rule lines.
func oracleRuleSetFiles() map[string][]string {
	return map[string][]string{
		"set-a": {
			"DOMAIN-SUFFIX,cdn.alpha.example",
			"IP-CIDR,10.1.2.0/24",
			"DEST-PORT,9000-9100",
		},
		"set-b": {
			"PROTOCOL,udp",
			"RULE-SET,set-a",
			"DOMAIN,one.beta.test",
			"IP-CIDR,10.0.0.0/8,no-resolve",
		},
	}
}

// oracleWorld is one generated configuration: the rule lines, the files they
// reference, and the datasets they are evaluated against.
type oracleWorld struct {
	seed    int64
	lines   []string
	files   map[string]string
	ruleSet map[string][]string
	domain  map[string]*oracleSet
	geo     *MemGeoIP
	asn     *MemASN
}

// newOracleWorld generates a rule list for one seed. Every kind appears at least
// once, extra rules are drawn at random, and the whole list is then shuffled so
// that priority has to come from the rule order rather than from how the list was
// built.
func newOracleWorld(t *testing.T, seed int64, withFinal bool, extra int) *oracleWorld {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	pick := func(xs []string) string { return xs[rng.Intn(len(xs))] }
	noResolve := func() string {
		if rng.Intn(100) < 35 {
			return ",no-resolve"
		}
		return ""
	}

	lines := []string{
		"DOMAIN," + pick(oracleExactNames) + "," + pick(oracleTargets),
		"DOMAIN-SUFFIX," + pick(oracleSuffixNames) + "," + pick(oracleTargets),
		"DOMAIN-KEYWORD," + pick(oracleKeywords) + "," + pick(oracleTargets),
		"DOMAIN-SET," + pick(oracleDomainSetNames) + "," + pick(oracleTargets),
		"IP-CIDR," + pick(oracleV4Prefixes) + "," + pick(oracleTargets) + noResolve(),
		"IP-CIDR6," + pick(oracleV6Prefixes) + "," + pick(oracleTargets) + noResolve(),
		"GEOIP," + pick(oracleCountries) + "," + pick(oracleTargets) + noResolve(),
		"IP-ASN," + pick(oracleASNumbers) + "," + pick(oracleTargets) + noResolve(),
		"RULE-SET," + pick(oracleRuleSetNames) + "," + pick(oracleTargets),
		"DEST-PORT," + pick(oraclePortSpecs) + "," + pick(oracleTargets),
		"PROTOCOL," + pick([]string{"tcp", "udp"}) + "," + pick(oracleTargets),
	}
	for i := 0; i < extra; i++ {
		switch rng.Intn(11) {
		case 0:
			lines = append(lines, "DOMAIN,"+pick(oracleExactNames)+","+pick(oracleTargets))
		case 1:
			lines = append(lines, "DOMAIN-SUFFIX,"+pick(oracleSuffixNames)+","+pick(oracleTargets))
		case 2:
			lines = append(lines, "DOMAIN-KEYWORD,"+pick(oracleKeywords)+","+pick(oracleTargets))
		case 3:
			lines = append(lines, "DOMAIN-SET,"+pick(oracleDomainSetNames)+","+pick(oracleTargets))
		case 4:
			lines = append(lines, "IP-CIDR,"+pick(oracleV4Prefixes)+","+pick(oracleTargets)+noResolve())
		case 5:
			lines = append(lines, "IP-CIDR6,"+pick(oracleV6Prefixes)+","+pick(oracleTargets)+noResolve())
		case 6:
			lines = append(lines, "GEOIP,"+pick(oracleCountries)+","+pick(oracleTargets)+noResolve())
		case 7:
			lines = append(lines, "IP-ASN,"+pick(oracleASNumbers)+","+pick(oracleTargets)+noResolve())
		case 8:
			lines = append(lines, "RULE-SET,"+pick(oracleRuleSetNames)+","+pick(oracleTargets))
		case 9:
			lines = append(lines, "DEST-PORT,"+pick(oraclePortSpecs)+","+pick(oracleTargets))
		default:
			lines = append(lines, "PROTOCOL,"+pick([]string{"tcp", "udp"})+","+pick(oracleTargets))
		}
	}
	if withFinal {
		lines = append(lines, "FINAL,"+pick(oracleTargets))
	}
	rng.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })
	if withFinal {
		// A FINAL on the first line answers every query by itself, which would
		// turn the whole world into one comparison repeated many times. When the
		// shuffle puts it there, move it; the ordering where FINAL does win
		// immediately has its own case in TestOracleEdgeCases.
		for i, line := range lines {
			if strings.HasPrefix(line, "FINAL,") && i == 0 {
				j := 1 + rng.Intn(len(lines)-1)
				lines[0], lines[j] = lines[j], lines[0]
				break
			}
		}
	}

	geo, err := NewMemGeoIP(map[string][]string{
		"CN": {"10.1.2.0/24", "203.0.113.0/24"},
		"US": {"192.0.2.0/24"},
		"JP": {"2001:db8::/32"},
	})
	if err != nil {
		t.Fatalf("seed %d: NewMemGeoIP: %v", seed, err)
	}
	asn, err := NewMemASN(map[uint32][]string{
		64500: {"10.0.0.0/8"},
		64501: {"192.0.2.0/24"},
		64502: {"198.51.100.0/24"},
	})
	if err != nil {
		t.Fatalf("seed %d: NewMemASN: %v", seed, err)
	}

	w := &oracleWorld{seed: seed, lines: lines, files: make(map[string]string), domain: oracleDomainSets(), geo: geo, asn: asn}
	w.ruleSet = oracleRuleSetFiles()
	for name, body := range w.ruleSet {
		w.files[name] = strings.Join(body, "\n") + "\n"
	}
	for name, set := range w.domain {
		w.files[name] = set.file()
	}
	return w
}

// options is the compile input for the world.
func (w *oracleWorld) options(t *testing.T) Options {
	t.Helper()
	rules := make([]*Rule, 0, len(w.lines))
	for i, line := range w.lines {
		r, err := ParseRule(line)
		if err != nil {
			t.Fatalf("seed %d line %d %q: %v", w.seed, i+1, line, err)
		}
		r.Source = "config"
		r.Line = i + 1
		rules = append(rules, r)
	}
	sets := make(map[string]string, len(w.files))
	for name := range w.files {
		sets[name] = name
	}
	for _, name := range append(append([]string{}, oracleRuleSetNames...), oracleDomainSetNames...) {
		if _, ok := sets[name]; !ok {
			t.Fatalf("seed %d: the world references %q without a file", w.seed, name)
		}
	}
	return Options{
		Rules:    rules,
		RuleSets: sets,
		ReadFile: readFileMap(w.files),
		GeoIP:    w.geo,
		ASN:      w.asn,
	}
}

// expectedFlatten spells out the list Compile must produce, in the shape
// Rule.String() renders: a RULE-SET is replaced in place by the rules of its
// file, each taking the target of the rule that referenced the set, and a nested
// reference is replaced the same way. A DOMAIN-SET stays one rule, because it is
// one slot in the priority order.
//
// This is the one thing the oracle cannot check on its own — it is handed the
// flattened list as its input — so it is checked here, against the generator's
// intent rather than against the engine's own expansion.
func (w *oracleWorld) expectedFlatten(t *testing.T) []string {
	t.Helper()
	var out []string

	var expand func(name, target string)
	expand = func(name, target string) {
		body, ok := w.ruleSet[name]
		if !ok {
			t.Fatalf("seed %d: no body for rule set %q", w.seed, name)
		}
		for _, line := range body {
			r, err := parseRuleFields(line, false)
			if err != nil {
				t.Fatalf("seed %d: rule set %q line %q: %v", w.seed, name, line, err)
			}
			if r.Kind == KindRuleSet {
				expand(r.Payload, target)
				continue
			}
			c := *r
			c.Target = target
			out = append(out, c.String())
		}
	}

	for _, line := range w.lines {
		r, err := ParseRule(line)
		if err != nil {
			t.Fatalf("seed %d line %q: %v", w.seed, line, err)
		}
		if r.Kind == KindRuleSet {
			expand(r.Payload, r.Target)
			continue
		}
		out = append(out, r.String())
	}
	return out
}

// dump renders the world so a failure can be copied into a minimal case.
func (w *oracleWorld) dump() string {
	var b strings.Builder
	fmt.Fprintf(&b, "seed %d\n[Rule]\n", w.seed)
	for _, line := range w.lines {
		b.WriteString("  " + line + "\n")
	}
	for _, name := range append(append([]string{}, oracleRuleSetNames...), oracleDomainSetNames...) {
		fmt.Fprintf(&b, "file %q:\n%s\n", name, w.files[name])
	}
	return b.String()
}

// compare checks one query against both implementations and reports the first
// disagreement with enough context to reproduce it.
func (w *oracleWorld) compare(t *testing.T, p *Program, o *oracle, q Query) (Decision, bool) {
	t.Helper()
	got, gotOK := p.Match(q)
	wantIdx, wantTarget, wantOK := o.match(q)
	if gotOK != wantOK || got.Target != wantTarget || (gotOK && got.Rule.Index() != wantIdx) {
		t.Fatalf("the engine and the oracle disagree on %s\n  engine: matched=%v target=%q index=%d\n  oracle: matched=%v target=%q index=%d\n%s",
			describeQuery(q), gotOK, got.Target, ruleIndexOf(got), wantOK, wantTarget, wantIdx, w.dump())
	}
	return got, gotOK
}

// ruleIndexOf reports the winning index, or -1 when nothing matched.
func ruleIndexOf(d Decision) int {
	if d.Rule == nil {
		return -1
	}
	return d.Rule.Index()
}

// TestOracleAgreesWithTheEngine compiles a generated rule list per seed and
// compares both implementations on every query in the set.
func TestOracleAgreesWithTheEngine(t *testing.T) {
	seeds := []int64{1, 2, 3, 4, 5, 6}
	var total, matched int
	decidedBy := make(map[Kind]int, len(kinds))
	for _, seed := range seeds {
		// One world has no FINAL, so the "nothing matched" answer is exercised
		// against a list that has nowhere to fall through to.
		w := newOracleWorld(t, seed, seed != 4, 12)
		p, err := Compile(w.options(t))
		if err != nil {
			t.Fatalf("seed %d: Compile: %v\n%s", seed, err, w.dump())
		}
		o := newOracle(t, p, w.domain, w.geo, w.asn)

		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			expected := w.expectedFlatten(t)
			got := p.Rules()
			if len(got) != len(expected) {
				t.Fatalf("seed %d: Compile produced %d rules, the generator expects %d\n  engine: %v\n  want:   %v\n%s",
					seed, len(got), len(expected), ruleStrings(got), expected, w.dump())
			}
			for i := range got {
				if got[i].String() != expected[i] {
					t.Fatalf("seed %d: rule #%d is %q, the generator expects %q\n%s", seed, i, got[i].String(), expected[i], w.dump())
				}
			}

			queries := oracleQuerySet(t)
			worldHits := 0
			for _, q := range queries {
				if decision, ok := w.compare(t, p, o, q); ok {
					worldHits++
					decidedBy[decision.Rule.Kind]++
				}
			}
			t.Logf("seed %d: %d rules, %d queries, %d decided by a rule and %d by nothing",
				seed, len(got), len(queries), worldHits, len(queries)-worldHits)
			total += len(queries)
			matched += worldHits
		})
	}
	if t.Failed() {
		return
	}
	t.Logf("compared %d queries over %d seeded rule lists: %d matched a rule, %d matched nothing",
		total, len(seeds), matched, total-matched)

	// A corpus that has quietly collapsed to "FINAL answers everything" would
	// still compare clean, so the spread of winning kinds is asserted rather than
	// assumed. Every kind must win somewhere except RULE-SET, which cannot: Compile
	// replaces it with the rules of its file, so the winning rule is always one of
	// those.
	for _, kind := range kinds {
		if kind == KindRuleSet {
			continue
		}
		if decidedBy[kind] == 0 {
			t.Errorf("no query in %d rule lists was decided by a %s rule, so this run did not exercise that kind", len(seeds), kind)
		}
	}
	t.Logf("winning kinds: %v", decidedBy)
}

// ruleStrings renders a rule list for a failure message.
func ruleStrings(rules []*Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.String())
	}
	return out
}

// oracleQuerySet is the cross product the engine is checked against: every
// combination of "carries a name" and "carries an address", both values of
// Resolved, and a rotating port and protocol so the unknown values are hit as
// often as the known ones.
func oracleQuerySet(t *testing.T) []Query {
	t.Helper()
	ports := []int{0, 22, 80, 443, 8080, 8099, 8100, 9000, 9050, 9100, 9101, 1000, 2000, 65535, 65536, -1}
	nets := []string{"", "tcp", "udp", "TCP", "sctp"}
	names := append([]string{""}, oracleQueryNames()...)
	addrs := append([]net.IP{nil}, oracleQueryAddrs(t)...)

	out := make([]Query, 0, len(names)*len(addrs)*2)
	k := 0
	for _, name := range names {
		for _, addr := range addrs {
			for _, resolved := range []bool{false, true} {
				out = append(out, Query{
					Name:     name,
					Addr:     addr,
					Resolved: resolved,
					Port:     ports[k%len(ports)],
					Network:  nets[k%len(nets)],
				})
				k++
			}
		}
	}
	return out
}

// oracleQueryNames covers the values a name rule can see: an exact payload, a
// name below a suffix at one and two labels, a name that shares the suffix's tail
// but not its boundary, names holding a keyword, and names that hold nothing.
func oracleQueryNames() []string {
	out := append([]string{}, oracleExactNames...)
	for _, suffix := range []string{"alpha.example", "example", "tracker.io"} {
		out = append(out, "a."+suffix, "b.a."+suffix)
	}
	for _, keyword := range []string{"tracker", "alpha"} {
		out = append(out, "pre"+keyword+"post.example")
	}
	// "notalpha.example" shares its tail with a suffix but not at a label
	// boundary, and "alpha.example.evil" extends one in the other direction.
	out = append(out, "notalpha.example", "alpha.example.evil", "unrelated.invalid", "nothing.local")
	return out
}

// oracleQueryAddrs covers the inside, the edges and both sides of every prefix in
// the vocabulary, for both families.
func oracleQueryAddrs(t *testing.T) []net.IP {
	t.Helper()
	var out []net.IP
	for _, cidr := range append(append([]string{}, oracleV4Prefixes...), oracleV6Prefixes...) {
		first, last := oraclePrefixBounds(t, cidr)
		out = append(out, first, last, oracleIPAdd(first, 3))
		if before := oracleIPAdd(first, -1); before != nil {
			out = append(out, before)
		}
		if after := oracleIPAdd(last, 1); after != nil {
			out = append(out, after)
		}
	}
	return out
}

// oraclePrefixBounds returns the first and last address of a prefix.
func oraclePrefixBounds(t *testing.T, cidr string) (first, last net.IP) {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("the generator's prefix %q does not parse: %v", cidr, err)
	}
	first = append(net.IP(nil), network.IP...)
	last = make(net.IP, len(first))
	for i := range first {
		last[i] = first[i] | ^network.Mask[i]
	}
	return first, last
}

// oracleIPAdd shifts an address by delta, or reports nil when it leaves the
// address space. Small deltas only, which is all the generator needs.
func oracleIPAdd(ip net.IP, delta int) net.IP {
	b := make([]byte, len(ip))
	copy(b, ip)
	if delta >= 0 {
		carry := delta
		for i := len(b) - 1; i >= 0 && carry > 0; i-- {
			sum := int(b[i]) + carry
			b[i] = byte(sum)
			carry = sum >> 8
		}
		if carry > 0 {
			return nil
		}
		return b
	}
	borrow := -delta
	for i := len(b) - 1; i >= 0 && borrow > 0; i-- {
		diff := int(b[i]) - borrow
		borrow = 0
		if diff < 0 {
			diff += 256
			borrow = 1
		}
		b[i] = byte(diff)
	}
	if borrow > 0 {
		return nil
	}
	return b
}

// TestOracleEdgeCases covers the shapes a generated world cannot reach: no rules
// at all, a list with nowhere to fall through to, a rule set file with nothing in
// it, and a FINAL that wins from the first line.
func TestOracleEdgeCases(t *testing.T) {
	t.Run("no rules", func(t *testing.T) {
		if _, err := Compile(Options{}); err == nil || !strings.Contains(err.Error(), "no rules") {
			t.Fatalf("Compile with no rules = %v, want an error naming the empty list", err)
		}
	})

	t.Run("an empty rule set leaves nothing to compile", func(t *testing.T) {
		// Expansion happens before the emptiness check, so a list made only of an
		// empty rule set is the same as an empty list.
		_, err := Compile(Options{
			Rules:    mustParse(t, "RULE-SET,empty,REJECT"),
			RuleSets: map[string]string{"empty": "empty"},
			ReadFile: readFileMap(map[string]string{"empty": ""}),
		})
		if err == nil || !strings.Contains(err.Error(), "no rules") {
			t.Fatalf("Compile of an empty rule set = %v, want the empty-list error", err)
		}
	})

	t.Run("no FINAL and nothing matches", func(t *testing.T) {
		lines := []string{"DOMAIN-SUFFIX,example.com,Proxy", "IP-CIDR,10.1.2.0/24,Proxy", "DEST-PORT,443,Proxy"}
		p := compileLines(t, lines, Options{})
		o := newOracle(t, p, nil, nil, nil)
		q := Query{Name: "other.invalid", Addr: net.ParseIP("198.51.100.7"), Port: 22, Network: "udp"}
		if got, ok := p.Match(q); ok {
			t.Fatalf("Match(%s) = %s, want no match: the list has no FINAL", describeQuery(q), got)
		}
		if _, _, ok := o.match(q); ok {
			t.Fatal("the oracle matched a rule the engine did not")
		}
	})

	t.Run("an empty rule set takes no priority slot", func(t *testing.T) {
		p, err := Compile(Options{
			Rules:    mustParse(t, "RULE-SET,empty,REJECT", "DOMAIN,example.com,Proxy", "FINAL,DIRECT"),
			RuleSets: map[string]string{"empty": "empty"},
			ReadFile: readFileMap(map[string]string{"empty": ""}),
		})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if p.Len() != 2 {
			t.Fatalf("Len() = %d, want 2: an expanded rule set contributes its rules, and an empty one contributes none", p.Len())
		}
		if got := p.Rules()[0].String(); got != "DOMAIN,example.com,Proxy" {
			t.Fatalf("rule #0 = %q, want the rule that followed the empty set", got)
		}
	})

	t.Run("an empty domain set keeps its slot", func(t *testing.T) {
		// A DOMAIN-SET is one entry in the priority order, so unlike a RULE-SET it
		// stays in the list even when its file holds nothing; it then simply never
		// matches.
		files := map[string]string{"none": ""}
		p, err := Compile(Options{
			Rules:    mustParse(t, "DOMAIN-SET,none,REJECT", "DOMAIN,example.com,Proxy", "FINAL,DIRECT"),
			RuleSets: map[string]string{"none": "none"},
			ReadFile: readFileMap(files),
		})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if p.Len() != 3 {
			t.Fatalf("Len() = %d, want 3", p.Len())
		}
		o := newOracle(t, p, map[string]*oracleSet{"none": {}}, nil, nil)
		for _, q := range []Query{{Name: "example.com"}, {Name: "a.example.com"}, {Name: "other.invalid"}} {
			got, ok := p.Match(q)
			wantIdx, wantTarget, wantOK := o.match(q)
			if ok != wantOK || got.Target != wantTarget || ruleIndexOf(got) != wantIdx {
				t.Fatalf("%s: engine %v/%q/#%d, oracle %v/%q/#%d", describeQuery(q), ok, got.Target, ruleIndexOf(got), wantOK, wantTarget, wantIdx)
			}
		}
	})

	t.Run("FINAL on the first line wins everything", func(t *testing.T) {
		p, err := Compile(Options{Rules: mustParse(t, "FINAL,REJECT", "DOMAIN,example.com,Proxy")})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		o := newOracle(t, p, nil, nil, nil)
		for _, q := range []Query{{Name: "example.com"}, {Addr: net.ParseIP("10.1.2.3")}, {}} {
			got, ok := p.Match(q)
			wantIdx, wantTarget, wantOK := o.match(q)
			if !ok || got.Target != wantTarget || ruleIndexOf(got) != wantIdx {
				t.Fatalf("%s: engine %v/%q/#%d, oracle %v/%q/#%d", describeQuery(q), ok, got.Target, ruleIndexOf(got), wantOK, wantTarget, wantIdx)
			}
			if got.Target != "REJECT" {
				t.Fatalf("%s decided %q, want the FINAL that comes first", describeQuery(q), got.Target)
			}
		}
	})
}

// TestOracleWithAMMDBBackedDatabase runs the same comparison against a database
// loaded from a file rather than the in-memory one, so the oracle is not tied to a
// single implementation of the lookup interfaces. The fixture is a tiny database
// written by geoiptest and read back through the production loader.
func TestOracleWithAMMDBBackedDatabase(t *testing.T) {
	dir := t.TempDir()
	countries := map[string][]string{
		"CN": {"203.0.113.0/24", "10.1.2.0/24"},
		"US": {"192.0.2.0/24"},
	}
	data, err := geoiptest.Country(countries)
	if err != nil {
		t.Fatalf("geoiptest.Country: %v", err)
	}
	path := filepath.Join(dir, "country.mmdb")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write the database: %v", err)
	}
	db, err := geoip.Open(path, geoip.KindCountry)
	if err != nil {
		t.Fatalf("geoip.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	p := compileLines(t, []string{
		"GEOIP,CN,From-CN",                    // 0
		"IP-CIDR,203.0.113.0/24,From-Prefix",  // 1
		"GEOIP,US,From-US,no-resolve",         // 2
		"IP-CIDR6,2001:db8::/32,From-Prefix6", // 3
		"FINAL,Everything-Else",               // 4
	}, Options{GeoIP: db})
	o := newOracle(t, p, nil, db, nil)

	queries := []Query{
		{Addr: net.ParseIP("203.0.113.9")},
		{Addr: net.ParseIP("10.1.2.9")},
		{Addr: net.ParseIP("192.0.2.9")},
		{Name: "a.example.com", Addr: net.ParseIP("192.0.2.9"), Resolved: true},
		{Addr: net.ParseIP("2001:db8::1")},
		{Addr: net.ParseIP("198.51.100.9")},
		{Name: "no-address.example"},
	}
	for _, q := range queries {
		got, ok := p.Match(q)
		wantIdx, wantTarget, wantOK := o.match(q)
		if ok != wantOK || got.Target != wantTarget || ruleIndexOf(got) != wantIdx {
			t.Fatalf("%s: engine %v/%q/#%d, oracle %v/%q/#%d",
				describeQuery(q), ok, got.Target, ruleIndexOf(got), wantOK, wantTarget, wantIdx)
		}
	}

	// The resolved address of a US block must fall through rule 2 and reach FINAL,
	// which is the no-resolve contract surviving a file-backed lookup.
	if got, ok := p.Match(queries[3]); !ok || got.Target != "Everything-Else" {
		t.Fatalf("resolved US address decided %q, want FINAL", got.Target)
	}
	// The literal US address must hit the guarded rule, at its own index.
	if got, ok := p.Match(queries[2]); !ok || got.Target != "From-US" || got.Rule.Index() != 2 {
		t.Fatalf("literal US address decided %s, want From-US at index 2", got)
	}
}
