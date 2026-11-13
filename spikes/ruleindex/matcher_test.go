package main

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// oracleDomain answers queries by scanning every domain rule, and returns the
// longest matching suffix.
func oracleDomain(rules []*Rule, host string) (*Rule, bool) {
	var best *Rule
	for _, r := range rules {
		if r.Kind != KindDomainSuffix {
			continue
		}
		if host == r.Value || strings.HasSuffix(host, "."+r.Value) {
			if best == nil || len(r.Value) > len(best.Value) {
				best = r
			}
		}
	}
	return best, best != nil
}

// oracleIP answers queries by scanning every CIDR rule, and returns the block
// with the longest prefix that contains addr.
func oracleIP(rules []*Rule, addr uint32) (*Rule, bool) {
	var best *Rule
	var bestBits int
	for _, r := range rules {
		if r.Kind != KindIPCIDR {
			continue
		}
		_, network, err := net.ParseCIDR(r.Value)
		if err != nil {
			continue
		}
		start := binary.BigEndian.Uint32(network.IP.To4())
		ones, _ := network.Mask.Size()
		size := uint32(1) << (32 - ones)
		if addr >= start && addr < start+size {
			if best == nil || ones > bestBits {
				best, bestBits = r, ones
			}
		}
	}
	return best, best != nil
}

func buildIndex(t *testing.T) (*Index, *dataset) {
	t.Helper()
	ds := generate(2000, 2000, 7)
	ix := NewIndex()
	ds.build(ix)
	return ix, ds
}

// TestIndexMatchesOracle checks the trie and the range table against a linear
// scan on the same inputs.
func TestIndexMatchesOracle(t *testing.T) {
	ix, ds := buildIndex(t)

	for _, host := range ds.hosts {
		want, wantOK := oracleDomain(ds.rules, host)
		got, gotOK := ix.MatchDomain(host)
		if wantOK != gotOK || (wantOK && want != got) {
			t.Fatalf("domain %q: got %v (%v), want %v (%v)", host, got, gotOK, want, wantOK)
		}
	}
	for _, addr := range ds.addrs {
		want, wantOK := oracleIP(ds.rules, addr)
		got, gotOK := ix.MatchUint32(addr)
		if wantOK != gotOK || (wantOK && want != got) {
			t.Fatalf("addr %s: got %v (%v), want %v (%v)", uint32ToIP(addr), got, gotOK, want, wantOK)
		}
	}
}

// TestSuffixNeedsLabelBoundary pins the DOMAIN-SUFFIX semantics.
func TestSuffixNeedsLabelBoundary(t *testing.T) {
	ix := NewIndex()
	rule := &Rule{Kind: KindDomainSuffix, Value: "example.com", Policy: "PROXY"}
	ix.AddDomainSuffix(rule.Value, rule)

	cases := map[string]bool{
		"example.com":      true,
		"a.example.com":    true,
		"a.b.example.com":  true,
		"EXAMPLE.COM":      true,
		"notexample.com":   false,
		"example.com.evil": false,
		"example.co":       false,
		"":                 false,
	}
	for host, want := range cases {
		_, ok := ix.MatchDomain(host)
		if ok != want {
			t.Errorf("%q: matched=%v, want %v", host, ok, want)
		}
	}
}

// TestCIDRMostSpecificWins covers nested and disjoint blocks.
func TestCIDRMostSpecificWins(t *testing.T) {
	ix := NewIndex()
	wide := &Rule{Kind: KindIPCIDR, Value: "10.0.0.0/8", Policy: "DIRECT"}
	narrow := &Rule{Kind: KindIPCIDR, Value: "10.1.2.0/24", Policy: "PROXY"}
	other := &Rule{Kind: KindIPCIDR, Value: "192.168.0.0/16", Policy: "REJECT"}
	for _, r := range []*Rule{wide, narrow, other} {
		if err := ix.AddCIDR(r.Value, r); err != nil {
			t.Fatal(err)
		}
	}
	ix.Build()

	cases := []struct {
		addr string
		want *Rule
	}{
		{"10.1.2.3", narrow},
		{"10.1.3.3", wide},
		{"10.200.0.1", wide},
		{"192.168.5.5", other},
		{"8.8.8.8", nil},
	}
	for _, c := range cases {
		got, ok := ix.MatchIP(net.ParseIP(c.addr))
		if c.want == nil {
			if ok {
				t.Errorf("%s: unexpected match %v", c.addr, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("%s: got %v (%v), want %v", c.addr, got, ok, c.want)
		}
	}
}

var (
	benchIndex *Index
	benchData  *dataset
)

func benchSetup(b *testing.B) (*Index, *dataset) {
	b.Helper()
	if benchIndex == nil {
		benchData = generate(domainRules, cidrRules, seed)
		benchIndex = NewIndex()
		benchData.build(benchIndex)
	}
	return benchIndex, benchData
}

// BenchmarkMatchDomain measures one DOMAIN-SUFFIX lookup over 50k rules.
func BenchmarkMatchDomain(b *testing.B) {
	ix, ds := benchSetup(b)
	b.ReportAllocs()
	b.ResetTimer()
	var hit int
	for i := 0; i < b.N; i++ {
		if _, ok := ix.MatchDomain(ds.hosts[i%len(ds.hosts)]); ok {
			hit++
		}
	}
	sink += hit
}

// BenchmarkMatchIP measures one IP-CIDR lookup over 50k rules.
func BenchmarkMatchIP(b *testing.B) {
	ix, ds := benchSetup(b)
	b.ReportAllocs()
	b.ResetTimer()
	var hit int
	for i := 0; i < b.N; i++ {
		if _, ok := ix.MatchUint32(ds.addrs[i%len(ds.addrs)]); ok {
			hit++
		}
	}
	sink += hit
}

// BenchmarkMatchMixed measures the dispatcher used by the hot path, alternating
// a domain and an address per operation.
func BenchmarkMatchMixed(b *testing.B) {
	ix, ds := benchSetup(b)
	b.ReportAllocs()
	b.ResetTimer()
	var hit int
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			if _, ok := ix.Match(ds.hosts[i%len(ds.hosts)]); ok {
				hit++
			}
			continue
		}
		if _, ok := ix.MatchUint32(ds.addrs[i%len(ds.addrs)]); ok {
			hit++
		}
	}
	sink += hit
}

// BenchmarkBuild measures compiling 100k rules into the index.
func BenchmarkBuild(b *testing.B) {
	ds := generate(domainRules, cidrRules, seed)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ix := NewIndex()
		ds.build(ix)
		benchIndex = ix
	}
}

// TestRangesSortedAndDisjoint checks the invariant the binary search relies on,
// on the full 100k rule set.
func TestRangesSortedAndDisjoint(t *testing.T) {
	ds := generate(domainRules, cidrRules, seed)
	ix := NewIndex()
	ds.build(ix)

	if len(ix.ranges) == 0 {
		t.Fatal("no ranges built")
	}
	for i := 1; i < len(ix.ranges); i++ {
		prev, cur := ix.ranges[i-1], ix.ranges[i]
		if prev.end >= cur.start {
			t.Fatalf("ranges %d and %d overlap: [%s,%s] [%s,%s]", i-1, i,
				uint32ToIP(prev.start), uint32ToIP(prev.end), uint32ToIP(cur.start), uint32ToIP(cur.end))
		}
		if prev.start > prev.end || cur.start > cur.end {
			t.Fatalf("range %d is inverted", i)
		}
	}
	t.Logf("ranges: %d, domains: %d, cidrs: %d", len(ix.ranges), ix.domainCount, ix.cidrCount)
}
