// Package rules compiles rule sets into index structures and answers match
// queries together with the decision path that produced them.
package rules

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Options configures Compile.
type Options struct {
	// Rules are the rules in configuration order. Index in this slice is
	// priority: the first rule that matches wins.
	Rules []*Rule
	// RuleSets maps a rule set name to its file. Relative paths are resolved
	// against Root.
	RuleSets map[string]string
	// Root is the directory relative rule set paths are resolved against.
	Root string
	// ReadFile reads a rule set file. It defaults to os.ReadFile and exists so
	// that tests and embedded configurations can supply files directly.
	ReadFile func(path string) ([]byte, error)
	// GeoIP supplies the country database for GEOIP rules. It is required when
	// a GEOIP rule is present.
	GeoIP GeoIPLookup
	// ASN supplies the autonomous system database for IP-ASN rules. It is
	// required when an IP-ASN rule is present.
	ASN ASNLookup
	// MaxRuleSetDepth limits nested RULE-SET references. Zero means 16.
	MaxRuleSetDepth int
	// MaxRuleSetRules limits how many rules rule sets may expand to. Zero means
	// 500000.
	MaxRuleSetRules int
}

// Program is a compiled rule list. It is immutable after Compile and safe for
// concurrent use.
//
// Compile records each rule's position in the rule it was given, so a rule list
// belongs to the program it produced: compiling the same list twice is safe
// only one after the other, and the daemon re-parses the configuration for a
// reload instead of reusing rule values.
type Program struct {
	rules  []*Rule
	final  *Rule
	loader *setLoader

	domains   *domainIndex
	v4        *rangeTable[uint32]
	v6        *rangeTable[u128]
	ports     *rangeTable[uint32]
	protocols map[string]int32

	geo []*Rule
	asn []*Rule

	geoDB GeoIPLookup
	asnDB ASNLookup

	counts map[Kind]int
}

// Compile validates the rules, loads every rule set and builds the indexes.
//
// It fails when a reference cannot be resolved, when rule sets form a cycle,
// when a pattern is malformed or when a database-backed rule has no database,
// so a program that compiles is a program that can be enforced.
func Compile(opts Options) (*Program, error) {
	loader := newSetLoader(opts)

	rules, err := flatten(opts.Rules, loader)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, errors.New("no rules to compile")
	}

	p := &Program{
		rules:     rules,
		loader:    loader,
		domains:   newDomainIndex(),
		protocols: make(map[string]int32, 4),
		geoDB:     opts.GeoIP,
		asnDB:     opts.ASN,
		counts:    make(map[Kind]int, len(kinds)),
	}
	for i, r := range rules {
		r.index = int32(i)
		p.counts[r.Kind]++
	}

	var v4Blocks, v6Blocks, portBlocks []block
	for _, r := range rules {
		idx := r.index
		switch r.Kind {
		case KindDomain:
			p.domains.addExact(r.Payload, idx)
		case KindDomainSuffix:
			p.domains.addSuffix(r.Payload, idx, r.Payload)
		case KindDomainKeyword:
			p.domains.addKeyword(r.Payload, idx)
		case KindDomainSet:
			entries, err := loader.domainEntries(r.Payload)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if e.Kind == KindDomain {
					p.domains.addExact(e.Payload, idx)
					continue
				}
				p.domains.addSuffix(e.Payload, idx, e.Payload)
			}
		case KindIPCIDR, KindIPCIDR6:
			b, isV4, err := cidrBlock(r.Payload, idx)
			if err != nil {
				return nil, fmt.Errorf("rule #%d %s: %w", idx, r, err)
			}
			if isV4 {
				v4Blocks = append(v4Blocks, b)
			} else {
				v6Blocks = append(v6Blocks, b)
			}
		case KindDestPort:
			lo, hi, err := parsePortSpec(r.Payload)
			if err != nil {
				return nil, fmt.Errorf("rule #%d %s: %w", idx, r, err)
			}
			portBlocks = append(portBlocks, block{
				start: boundOfU32(uint32(lo)),
				end:   boundOf(u128{lo: uint64(hi) + 1}),
				idx:   idx,
			})
		case KindProtocol:
			if prev, ok := p.protocols[r.Payload]; !ok || idx < prev {
				p.protocols[r.Payload] = idx
			}
		case KindGeoIP:
			if p.geoDB == nil {
				return nil, fmt.Errorf("rule #%d %s needs a GEOIP database, none was supplied", idx, r)
			}
			p.geo = append(p.geo, r)
		case KindIPASN:
			if p.asnDB == nil {
				return nil, fmt.Errorf("rule #%d %s needs an ASN database, none was supplied", idx, r)
			}
			p.asn = append(p.asn, r)
		case KindFinal:
			if p.final == nil {
				p.final = r
			}
		default:
			return nil, fmt.Errorf("rule #%d has unsupported type %q", idx, r.Kind)
		}
	}

	p.v4 = newRangeTable4(buildRanges(v4Blocks))
	p.v6 = newRangeTable6(buildRanges(v6Blocks))
	p.ports = newRangeTablePorts(buildRanges(portBlocks))
	return p, nil
}

// flatten expands RULE-SET references and keeps everything else in order.
func flatten(rules []*Rule, loader *setLoader) ([]*Rule, error) {
	out := make([]*Rule, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			return nil, errors.New("nil rule")
		}
		if r.Kind != KindRuleSet {
			out = append(out, r)
			continue
		}
		expanded, err := loader.expand(r.Payload, r.Target, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, expanded...)
	}
	return out, nil
}

// Rules returns the compiled rules in priority order.
func (p *Program) Rules() []*Rule { return append([]*Rule(nil), p.rules...) }

// Len returns the number of compiled rules.
func (p *Program) Len() int { return len(p.rules) }

// Stats summarises the program.
type Stats struct {
	Total    int
	Final    bool
	ByKind   map[Kind]int
	RuleSets []string
	Domains  int // exact DOMAIN entries
	Suffixes int // DOMAIN-SUFFIX and DOMAIN-SET entries
	Keywords int
	Ranges4  int // disjoint IPv4 ranges
	Ranges6  int // disjoint IPv6 ranges
	Ports    int
}

// Stats reports the size of the compiled program.
func (p *Program) Stats() Stats {
	s := Stats{
		Total:    len(p.rules),
		Final:    p.final != nil,
		ByKind:   make(map[Kind]int, len(p.counts)),
		RuleSets: p.loader.usedNames(),
		Domains:  len(p.domains.exact),
		Suffixes: p.domains.suffixSize,
		Keywords: p.domains.kwCount,
		Ranges4:  p.v4.len(),
		Ranges6:  p.v6.len(),
		Ports:    p.ports.len(),
	}
	for k, v := range p.counts {
		s.ByKind[k] = v
	}
	return s
}

// prepared is a query normalised once for all index lookups.
type prepared struct {
	raw     Query
	name    string
	hasName bool
	v4      uint32
	v6      u128
	family  int // 0 none, 4 or 6
	port    uint32
	hasPort bool
	network string
}

func prepareQuery(q Query) prepared {
	pre := prepared{raw: q, port: 0, family: 0}
	if name := strings.TrimSpace(q.Name); name != "" {
		name = lowerASCII(trimTrailingDot(name), nil)
		pre.name = name
		pre.hasName = true
	}
	if len(q.Addr) > 0 {
		if ip := net.IP(q.Addr); ip.To4() != nil {
			pre.v4 = be32(ip.To4())
			pre.family = 4
		} else if v6 := ip.To16(); v6 != nil {
			pre.v6 = ipToU128(v6)
			pre.family = 6
		}
	}
	if q.Port > 0 && q.Port <= 65535 {
		pre.port, pre.hasPort = uint32(q.Port), true
	}
	pre.network = strings.ToLower(strings.TrimSpace(q.Network))
	return pre
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Match classifies a query. The second result is false only when nothing
// matched, which can only happen when the program has no FINAL rule.
func (p *Program) Match(q Query) (Decision, bool) {
	pre := prepareQuery(q)
	r, ok := p.evaluate(&pre, nil)
	if !ok {
		return Decision{}, false
	}
	return Decision{Rule: r, Target: r.Target}, true
}

// Explain classifies a query and reports every step that led to the decision.
func (p *Program) Explain(q Query) Explanation {
	var steps []Step
	pre := prepareQuery(q)
	r, ok := p.evaluate(&pre, &steps)
	for i := range steps {
		// A step without a rule did not resolve to a rule index; report -1
		// rather than the zero value, which would read as rule 0.
		if steps[i].Rule == nil {
			steps[i].Index = -1
		}
	}
	e := Explanation{Query: q, Matched: ok, Steps: steps}
	if ok {
		e.Decision = Decision{Rule: r, Target: r.Target}
	}
	return e
}

// evaluate walks every index that applies to the query and keeps the lowest
// rule index, which is exactly the first matching rule of the list.
//
// Two rules keep the hot path free of work nobody asked for: a block only
// touches its index when the query carries the matching input, and the
// explanation strings are built only when steps is non-nil. Match therefore
// answers without formatting anything or allocating.
func (p *Program) evaluate(pre *prepared, steps *[]Step) (*Rule, bool) {
	best := int32(-1)
	take := func(idx int32) {
		if best < 0 || idx < best {
			best = idx
		}
	}
	add := func(s Step) { *steps = append(*steps, s) }

	// DOMAIN
	if len(p.domains.exact) > 0 {
		if !pre.hasName {
			if steps != nil {
				add(Step{Kind: KindDomain, Detail: "skipped: query carries no name"})
			}
		} else if idx, ok := p.domains.matchExact(pre.name); ok {
			take(idx)
			if steps != nil {
				add(Step{Kind: KindDomain, Index: int(idx), Rule: p.rules[idx], Match: true,
					Detail: fmt.Sprintf("exact entry %q", pre.name)})
			}
		} else if steps != nil {
			add(Step{Kind: KindDomain, Detail: fmt.Sprintf("no exact entry for %q", pre.name)})
		}
	}

	// DOMAIN-SUFFIX, including DOMAIN-SET expansions
	if p.domains.suffixHasRules() {
		if !pre.hasName {
			if steps != nil {
				add(Step{Kind: KindDomainSuffix, Detail: "skipped: query carries no name"})
			}
		} else if idx, payload, ok := p.domains.matchSuffix(pre.name); ok {
			take(idx)
			if steps != nil {
				add(Step{Kind: KindDomainSuffix, Index: int(idx), Rule: p.rules[idx], Match: true,
					Detail: fmt.Sprintf("suffix %q", payload)})
			}
		} else if steps != nil {
			add(Step{Kind: KindDomainSuffix, Detail: fmt.Sprintf("no suffix covers %q", pre.name)})
		}
	}

	// DOMAIN-KEYWORD
	if p.domains.kwCount > 0 {
		if !pre.hasName {
			if steps != nil {
				add(Step{Kind: KindDomainKeyword, Detail: "skipped: query carries no name"})
			}
		} else if idx, word, ok := p.domains.matchKeyword(pre.name); ok {
			take(idx)
			if steps != nil {
				add(Step{Kind: KindDomainKeyword, Index: int(idx), Rule: p.rules[idx], Match: true,
					Detail: fmt.Sprintf("keyword %q occurs in the name", word)})
			}
		} else if steps != nil {
			add(Step{Kind: KindDomainKeyword, Detail: "no keyword occurs in the name"})
		}
	}

	// IP-CIDR
	if p.v4.len() > 0 {
		if pre.family != 4 {
			if steps != nil {
				add(Step{Kind: KindIPCIDR, Detail: "skipped: query carries no IPv4 address"})
			}
		} else if idx, ok := p.v4.lookup(pre.v4); ok {
			take(idx)
			if steps != nil {
				add(Step{Kind: KindIPCIDR, Index: int(idx), Rule: p.rules[idx], Match: true,
					Detail: fmt.Sprintf("prefix %s covers the address", p.rules[idx].Payload)})
			}
		} else if steps != nil {
			add(Step{Kind: KindIPCIDR, Detail: "no IPv4 prefix covers the address"})
		}
	}

	// IP-CIDR6
	if p.v6.len() > 0 {
		if pre.family != 6 {
			if steps != nil {
				add(Step{Kind: KindIPCIDR6, Detail: "skipped: query carries no IPv6 address"})
			}
		} else if idx, ok := p.v6.lookup(pre.v6); ok {
			take(idx)
			if steps != nil {
				add(Step{Kind: KindIPCIDR6, Index: int(idx), Rule: p.rules[idx], Match: true,
					Detail: fmt.Sprintf("prefix %s covers the address", p.rules[idx].Payload)})
			}
		} else if steps != nil {
			add(Step{Kind: KindIPCIDR6, Detail: "no IPv6 prefix covers the address"})
		}
	}

	// DEST-PORT
	if p.ports.len() > 0 {
		if !pre.hasPort {
			if steps != nil {
				add(Step{Kind: KindDestPort, Detail: "skipped: query carries no port"})
			}
		} else if idx, ok := p.ports.lookup(pre.port); ok {
			take(idx)
			if steps != nil {
				add(Step{Kind: KindDestPort, Index: int(idx), Rule: p.rules[idx], Match: true,
					Detail: fmt.Sprintf("DEST-PORT %s covers port %d", p.rules[idx].Payload, pre.port)})
			}
		} else if steps != nil {
			add(Step{Kind: KindDestPort, Detail: fmt.Sprintf("no port rule covers %d", pre.port)})
		}
	}

	// PROTOCOL
	if len(p.protocols) > 0 {
		if pre.network == "" {
			if steps != nil {
				add(Step{Kind: KindProtocol, Detail: "skipped: query carries no protocol"})
			}
		} else if idx, ok := p.protocols[pre.network]; ok {
			take(idx)
			if steps != nil {
				add(Step{Kind: KindProtocol, Index: int(idx), Rule: p.rules[idx], Match: true,
					Detail: fmt.Sprintf("protocol %q", pre.network)})
			}
		} else if steps != nil {
			add(Step{Kind: KindProtocol, Detail: fmt.Sprintf("no rule for protocol %q", pre.network)})
		}
	}

	// GEOIP and IP-ASN are evaluated rule by rule because each rule carries its
	// own lookup value. Rules are in ascending order, so the first hit is the
	// best one and later rules are skipped once a lower index is known.
	if pre.family == 0 {
		if steps != nil && len(p.geo) > 0 {
			add(Step{Kind: KindGeoIP, Detail: "skipped: query carries no address"})
		}
		if steps != nil && len(p.asn) > 0 {
			add(Step{Kind: KindIPASN, Detail: "skipped: query carries no address"})
		}
	} else {
		ip := net.IP(pre.raw.Addr)
		for _, r := range p.geo {
			if best >= 0 && r.index >= best {
				break
			}
			cc, ok := p.geoDB.Country(ip)
			inSet := ok && strings.EqualFold(cc, r.Payload)
			if inSet {
				take(r.index)
			}
			if steps != nil {
				detail := fmt.Sprintf("address is not in %s", r.Payload)
				if inSet {
					detail = fmt.Sprintf("address is in %s", r.Payload)
				}
				add(Step{Kind: KindGeoIP, Index: int(r.index), Rule: r, Match: inSet, Detail: detail})
			}
		}
		for _, r := range p.asn {
			if best >= 0 && r.index >= best {
				break
			}
			asn, ok := p.asnDB.ASN(ip)
			inSet := ok && strconv.FormatUint(uint64(asn), 10) == r.Payload
			if inSet {
				take(r.index)
			}
			if steps != nil {
				detail := fmt.Sprintf("address is not in AS%s", r.Payload)
				if inSet {
					detail = fmt.Sprintf("address is in AS%s", r.Payload)
				}
				add(Step{Kind: KindIPASN, Index: int(r.index), Rule: r, Match: inSet, Detail: detail})
			}
		}
	}

	// FINAL matches everything, so it only wins when no earlier rule did.
	if p.final != nil {
		take(p.final.index)
	}

	if best < 0 {
		if steps != nil {
			add(Step{Kind: KindFinal, Detail: "no rule matched and the list has no FINAL"})
		}
		return nil, false
	}
	r := p.rules[best]
	return r, true
}
