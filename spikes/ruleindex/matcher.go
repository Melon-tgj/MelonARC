// Package main holds a rule matcher prototype used to size up the rule engine
// of the core: DOMAIN-SUFFIX rules are indexed in a label trie walked from the
// top-level domain down, IP-CIDR rules are turned into a sorted array of
// disjoint ranges that is searched with binary search.
//
// Run it to see build time and average match latency over 100k rules:
//
//	go run ./spikes/ruleindex
//
// Run the benchmarks for per-operation numbers:
//
//	go test -bench . -benchmem ./spikes/ruleindex
package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
)

// Rule kinds modelled by the prototype.
const (
	KindDomainSuffix = "DOMAIN-SUFFIX"
	KindIPCIDR       = "IP-CIDR"
)

// Rule is one compiled rule. Rules are immutable once the index is built.
type Rule struct {
	Kind   string
	Value  string // suffix for DOMAIN-SUFFIX, CIDR text for IP-CIDR
	Policy string // outbound or policy group the rule points at
}

func (r *Rule) String() string { return r.Kind + "," + r.Value + "," + r.Policy }

// Index answers match queries. Build it with AddDomainSuffix / AddCIDR and then
// call Build once; queries afterwards are read only and safe for concurrent use.
type Index struct {
	root   *domainNode
	cidrs  []cidrRule
	ranges []ipRange

	domainCount int
	cidrCount   int
	built       bool
}

type domainNode struct {
	children map[string]*domainNode
	rule     *Rule
}

type cidrRule struct {
	start uint32
	end   uint32 // inclusive
	bits  uint8
	rule  *Rule
}

// ipRange is a disjoint address range that all resolve to the same rule.
type ipRange struct {
	start uint32
	end   uint32 // inclusive
	rule  *Rule
}

// NewIndex returns an empty index.
func NewIndex() *Index {
	return &Index{root: &domainNode{}}
}

// AddDomainSuffix registers a DOMAIN-SUFFIX rule. The suffix matches itself and
// any name below it on a label boundary.
func (ix *Index) AddDomainSuffix(suffix string, rule *Rule) {
	labels := splitLabels(strings.ToLower(suffix))
	if len(labels) == 0 {
		return
	}
	node := ix.root
	// Labels are walked from the right, so a suffix and the names under it end
	// up on the same path and the deepest terminal wins.
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if node.children == nil {
			node.children = make(map[string]*domainNode, 4)
		}
		next, ok := node.children[label]
		if !ok {
			next = &domainNode{}
			node.children[label] = next
		}
		node = next
	}
	if node.rule == nil {
		ix.domainCount++
	}
	node.rule = rule
}

// AddCIDR registers an IP-CIDR rule.
func (ix *Index) AddCIDR(cidr string, rule *Rule) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ip := network.IP.To4()
	if ip == nil {
		return fmt.Errorf("%s is not an IPv4 prefix", cidr)
	}
	ones, _ := network.Mask.Size()
	start := binary.BigEndian.Uint32(ip)
	size := uint32(1) << (32 - ones)

	ix.cidrs = append(ix.cidrs, cidrRule{start: start, end: start + size - 1, bits: uint8(ones), rule: rule})
	ix.cidrCount++
	return nil
}

// Build compiles the collected CIDR rules into disjoint ranges. Any two CIDR
// blocks are either disjoint or nested, so a single sweep produces an ordered
// range table in which the most specific rule wins.
func (ix *Index) Build() {
	sort.Slice(ix.cidrs, func(i, j int) bool {
		if ix.cidrs[i].start != ix.cidrs[j].start {
			return ix.cidrs[i].start < ix.cidrs[j].start
		}
		return ix.cidrs[i].bits < ix.cidrs[j].bits // wider block first
	})

	ix.ranges = ix.ranges[:0]
	type frame struct {
		end  uint32
		rule *Rule
	}
	var stack []frame
	// cur is the first address not yet covered by the block on top of the
	// stack. It is 64 bit so that "one past 255.255.255.255" stays
	// representable instead of wrapping to 0.
	var cur uint64
	var open bool

	emit := func(from, to uint32, rule *Rule) {
		if from > to || rule == nil {
			return
		}
		if n := len(ix.ranges); n > 0 && ix.ranges[n-1].rule == rule && ix.ranges[n-1].end+1 == from {
			ix.ranges[n-1].end = to
			return
		}
		ix.ranges = append(ix.ranges, ipRange{start: from, end: to, rule: rule})
	}
	advance := func(frameEnd uint32, rule *Rule) {
		if open && cur <= uint64(frameEnd) {
			emit(uint32(cur), frameEnd, rule)
		}
		cur = uint64(frameEnd) + 1
	}

	for _, c := range ix.cidrs {
		// Close every block that ends before this one starts.
		for len(stack) > 0 && stack[len(stack)-1].end < c.start {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			advance(top.end, top.rule)
			open = len(stack) > 0 && cur <= uint64(stack[len(stack)-1].end)
		}
		// The enclosing block covers the gap before the nested one starts.
		if open && cur < uint64(c.start) && len(stack) > 0 {
			emit(uint32(cur), c.start-1, stack[len(stack)-1].rule)
		}
		cur = uint64(c.start)
		open = true
		stack = append(stack, frame{end: c.end, rule: c.rule})
	}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		advance(top.end, top.rule)
		open = len(stack) > 0 && cur <= uint64(stack[len(stack)-1].end)
	}
	ix.built = true
}

// MatchDomain returns the most specific suffix rule for host.
func (ix *Index) MatchDomain(host string) (*Rule, bool) {
	if host == "" {
		return nil, false
	}
	var buf [256]byte
	s := lowerASCII(host, buf[:])

	var matched *Rule
	node := ix.root
	// Walk label by label from the right, remembering the deepest terminal.
	for end := len(s); end > 0; {
		start := strings.LastIndexByte(s[:end], '.') + 1
		label := s[start:end]
		if node = node.children[label]; node == nil {
			break
		}
		if node.rule != nil {
			matched = node.rule
		}
		if start == 0 {
			break
		}
		end = start - 1
	}
	return matched, matched != nil
}

// MatchIP returns the rule whose block contains ip, most specific first.
func (ix *Index) MatchIP(ip net.IP) (*Rule, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return nil, false
	}
	return ix.MatchUint32(binary.BigEndian.Uint32(v4))
}

// MatchUint32 is MatchIP for an address already in host byte order.
func (ix *Index) MatchUint32(addr uint32) (*Rule, bool) {
	lo, hi := 0, len(ix.ranges)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if ix.ranges[mid].start <= addr {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return nil, false
	}
	r := ix.ranges[lo-1]
	if addr >= r.start && addr <= r.end {
		return r.rule, true
	}
	return nil, false
}

// Match dispatches on whether the input parses as an IPv4 literal.
func (ix *Index) Match(target string) (*Rule, bool) {
	if ip := net.ParseIP(target); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return ix.MatchUint32(binary.BigEndian.Uint32(v4))
		}
		return nil, false
	}
	return ix.MatchDomain(target)
}

// Stats reports how many rules went in and how many ranges came out.
func (ix *Index) Stats() (domains, cidrs, ranges int) {
	return ix.domainCount, ix.cidrCount, len(ix.ranges)
}

func splitLabels(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ".")
}

// lowerASCII lowercases ASCII in place in buf when needed, so the common
// already-lowercase case does not allocate.
func lowerASCII(s string, buf []byte) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			if len(s) > len(buf) {
				return strings.ToLower(s)
			}
			n := copy(buf, s)
			for j := 0; j < n; j++ {
				if buf[j] >= 'A' && buf[j] <= 'Z' {
					buf[j] += 'a' - 'A'
				}
			}
			return string(buf[:n])
		}
	}
	return s
}

// dataset holds generated rules and the probe inputs used by the benchmark and
// by the standalone runner.
type dataset struct {
	rules   []*Rule
	hosts   []string // probe domains
	addrs   []uint32 // probe addresses
	build   func(ix *Index)
	domains int
	cidrs   int
}

// generate builds a deterministic mixed rule set: half DOMAIN-SUFFIX, half
// IP-CIDR, with probe inputs that hit and miss.
func generate(domainCount, cidrCount int, seed int64) *dataset {
	rnd := rand.New(rand.NewSource(seed))
	ds := &dataset{domains: domainCount, cidrs: cidrCount}

	tlds := []string{"com", "net", "org", "io", "dev"}
	words := []string{"api", "cdn", "img", "static", "edge", "www", "mail", "login",
		"shop", "news", "video", "docs", "app", "assets", "auth", "pay", "search", "map", "chat", "data"}

	seen := make(map[string]struct{}, domainCount)
	for i := 0; i < domainCount; i++ {
		host := fmt.Sprintf("%s%d.%s", words[i%len(words)], i, tlds[i%len(tlds)])
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		ds.rules = append(ds.rules, &Rule{Kind: KindDomainSuffix, Value: host, Policy: "PROXY"})
	}
	domainHosts := make([]string, 0, domainCount)
	for host := range seen {
		domainHosts = append(domainHosts, host)
	}
	sort.Strings(domainHosts)

	cidrRules := make([]cidrRule, 0, cidrCount)
	seenCIDR := make(map[[5]byte]struct{}, cidrCount)
	for attempts := 0; len(cidrRules) < cidrCount && attempts < 20*cidrCount; attempts++ {
		bits := uint8(8 + rnd.Intn(25)) // /8 .. /32
		start := rnd.Uint32()
		size := uint32(1) << (32 - bits)
		start = start &^ (size - 1)
		key := [5]byte{byte(start >> 24), byte(start >> 16), byte(start >> 8), byte(start), bits}
		if _, dup := seenCIDR[key]; dup {
			continue
		}
		seenCIDR[key] = struct{}{}
		rule := &Rule{Kind: KindIPCIDR, Value: fmt.Sprintf("%s/%d", uint32ToIP(start), bits), Policy: "DIRECT"}
		ds.rules = append(ds.rules, rule)
		cidrRules = append(cidrRules, cidrRule{start: start, end: start + size - 1, bits: bits, rule: rule})
	}

	// Two thirds of the probes hit something, one third misses.
	for i := 0; i < 4096; i++ {
		switch i % 3 {
		case 0, 1:
			host := domainHosts[rnd.Intn(len(domainHosts))]
			ds.hosts = append(ds.hosts, "probe"+fmt.Sprint(i)+"."+host)
		default:
			ds.hosts = append(ds.hosts, fmt.Sprintf("nomatch%d.invalid", i))
		}
	}
	for i := 0; i < 4096; i++ {
		if i%3 == 2 || len(cidrRules) == 0 {
			ds.addrs = append(ds.addrs, rnd.Uint32())
			continue
		}
		r := cidrRules[rnd.Intn(len(cidrRules))]
		span := r.end - r.start
		ds.addrs = append(ds.addrs, r.start+rnd.Uint32()%(span+1))
	}

	ds.build = func(ix *Index) {
		for _, r := range ds.rules {
			if r.Kind == KindDomainSuffix {
				ix.AddDomainSuffix(r.Value, r)
				continue
			}
			if err := ix.AddCIDR(r.Value, r); err != nil {
				panic(err)
			}
		}
		ix.Build()
	}
	return ds
}

func uint32ToIP(v uint32) net.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IP(b[:])
}
