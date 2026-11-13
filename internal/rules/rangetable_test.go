package rules

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
	"testing"
)

func TestBuildRangesInvariants(t *testing.T) {
	rnd := rand.New(rand.NewSource(11))
	var blocks []block
	for i := 0; i < 5000; i++ {
		bits := 1 + rnd.Intn(32)
		start := rnd.Uint32() &^ (uint32(1)<<uint(32-bits) - 1)
		size := uint64(1) << uint(32-bits)
		blocks = append(blocks, block{
			start: boundOf(u128{lo: uint64(start)}),
			end:   boundOf(u128{lo: uint64(start) + size}),
			idx:   int32(i % 97),
		})
	}
	ranges := buildRanges(blocks)
	if len(ranges) == 0 {
		t.Fatal("no ranges built")
	}
	for i, r := range ranges {
		if cmpBound(r.start, r.end) > 0 {
			t.Fatalf("range %d is inverted: %v..%v", i, r.start, r.end)
		}
		if i == 0 {
			continue
		}
		prev := ranges[i-1]
		if cmpBound(prev.end.next(), r.start) > 0 {
			t.Fatalf("range %d overlaps its predecessor", i)
		}
		if prev.idx == r.idx && cmpBound(prev.end.next(), r.start) == 0 {
			t.Fatalf("range %d was not merged with an adjacent range of the same rule", i)
		}
	}
}

// oracleV4 answers with the lowest rule index covering addr by scanning every
// block, which is the definition the range table must implement.
func oracleV4(blocks []block, addr uint32) (int32, bool) {
	best := int32(-1)
	for _, b := range blocks {
		start := uint32(b.start.v.lo)
		var end uint32
		if b.end.past {
			end = math.MaxUint32
		} else {
			end = uint32(b.end.v.lo - 1)
		}
		if addr < start || addr > end {
			continue
		}
		if best < 0 || b.idx < best {
			best = b.idx
		}
	}
	return best, best >= 0
}

func TestRangeTableMatchesOracle(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	var blocks []block
	for i := 0; i < 600; i++ {
		bits := 8 + rnd.Intn(25)
		start := rnd.Uint32() &^ (uint32(1)<<uint(32-bits) - 1)
		size := uint64(1) << uint(32-bits)
		blocks = append(blocks, block{
			start: boundOf(u128{lo: uint64(start)}),
			end:   boundOf(u128{lo: uint64(start) + size}),
			idx:   int32(i),
		})
	}
	table := newRangeTable4(buildRanges(blocks))
	for i := 0; i < 20000; i++ {
		addr := rnd.Uint32()
		want, wantOK := oracleV4(blocks, addr)
		got, ok := table.lookup(addr)
		if ok != wantOK || (ok && got != want) {
			t.Fatalf("%s: got (%d,%v), want (%d,%v)", u32ToIP(addr), got, ok, want, wantOK)
		}
	}
}

func TestRangeTableEdgePrefixes(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		hit  []string
		miss []string
	}{
		{
			name: "default route",
			cidr: "0.0.0.0/0",
			hit:  []string{"0.0.0.0", "8.8.8.8", "255.255.255.255"},
			miss: nil,
		},
		{
			name: "single host at the top of the space",
			cidr: "255.255.255.255/32",
			hit:  []string{"255.255.255.255"},
			miss: []string{"255.255.255.254", "0.0.0.0"},
		},
		{
			name: "single host at zero",
			cidr: "0.0.0.0/32",
			hit:  []string{"0.0.0.0"},
			miss: []string{"0.0.0.1"},
		},
		{
			name: "ipv6 default route",
			cidr: "::/0",
			hit:  []string{"::", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
			miss: nil,
		},
		{
			name: "ipv6 single host",
			cidr: "2001:db8::1/128",
			hit:  []string{"2001:db8::1"},
			miss: []string{"2001:db8::2", "::"},
		},
		{
			name: "ipv6 top of the space",
			cidr: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
			hit:  []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
			miss: []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, isV4, err := cidrBlock(tc.cidr, 0)
			if err != nil {
				t.Fatalf("cidrBlock(%q): %v", tc.cidr, err)
			}
			var table4 *rangeTable[uint32]
			var table6 *rangeTable[u128]
			if isV4 {
				table4 = newRangeTable4(buildRanges([]block{b}))
			} else {
				table6 = newRangeTable6(buildRanges([]block{b}))
			}
			for _, s := range tc.hit {
				if !lookupAny(table4, table6, s) {
					t.Errorf("%s should be covered by %s", s, tc.cidr)
				}
			}
			for _, s := range tc.miss {
				if lookupAny(table4, table6, s) {
					t.Errorf("%s should not be covered by %s", s, tc.cidr)
				}
			}
		})
	}
}

func lookupAny(table4 *rangeTable[uint32], table6 *rangeTable[u128], s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("bad address " + s)
	}
	if v4 := ip.To4(); v4 != nil {
		if table4 == nil {
			return false
		}
		_, ok := table4.lookup(binary.BigEndian.Uint32(v4))
		return ok
	}
	if table6 == nil {
		return false
	}
	_, ok := table6.lookup(ipToU128(ip.To16()))
	return ok
}

func TestRangeTableEmpty(t *testing.T) {
	table := newRangeTable4(nil)
	if _, ok := table.lookup(0); ok {
		t.Fatal("an empty table matched")
	}
	if table.len() != 0 {
		t.Fatalf("len = %d", table.len())
	}
}

func TestPortRanges(t *testing.T) {
	rules := []string{
		"DEST-PORT,9000-9100,DIRECT",
		"DEST-PORT,9050,Proxy",
		"FINAL,REJECT",
	}
	p := compileLines(t, rules, Options{})
	tests := []struct {
		port int
		want string
	}{
		{8999, "REJECT"},
		{9000, "DIRECT"},
		{9050, "DIRECT"}, // the earlier range wins over the later single port
		{9100, "DIRECT"},
		{9101, "REJECT"},
	}
	for _, tc := range tests {
		got, _ := p.Match(Query{Port: tc.port})
		if got.Target != tc.want {
			t.Errorf("port %d: target = %q, want %q", tc.port, got.Target, tc.want)
		}
	}
}

func u32ToIP(v uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IP(b[:]).String()
}

func TestU128Arithmetic(t *testing.T) {
	tests := []struct {
		name    string
		in      u128
		inc     u128
		wrapped bool
	}{
		{name: "carry into the high word", in: u128{hi: 1, lo: math.MaxUint64}, inc: u128{hi: 2}},
		{name: "plain increment", in: u128{hi: 7, lo: 41}, inc: u128{hi: 7, lo: 42}},
		{name: "wrap", in: u128{hi: math.MaxUint64, lo: math.MaxUint64}, wrapped: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, wrapped := incU128(tc.in)
			if wrapped != tc.wrapped || got != tc.inc {
				t.Fatalf("incU128(%v) = %v, %v; want %v, %v", tc.in, got, wrapped, tc.inc, tc.wrapped)
			}
		})
	}
	if got := decU128(u128{hi: 2}); got != (u128{hi: 1, lo: math.MaxUint64}) {
		t.Fatalf("decU128 borrow = %v", got)
	}
	if cmpU128(u128{hi: 1}, u128{hi: 0, lo: math.MaxUint64}) <= 0 {
		t.Fatal("u128 comparison ignores the high word")
	}
	if cmpBound(boundPast(), boundOf(u128{hi: math.MaxUint64, lo: math.MaxUint64})) <= 0 {
		t.Fatal("the past sentinel must sort last")
	}
}

// buildScaleRules creates a deterministic mixed rule set of the size named in
// the performance target: half suffix rules, half prefixes.
func buildScaleRules(suffixes, prefixes int, seed int64) []*Rule {
	rnd := rand.New(rand.NewSource(seed))
	out := make([]*Rule, 0, suffixes+prefixes)
	tlds := []string{"com", "net", "org", "io", "dev"}
	words := []string{"api", "cdn", "img", "static", "edge", "www", "mail", "login",
		"shop", "news", "video", "docs", "app", "assets", "auth", "pay", "search", "map", "chat", "data"}
	for i := 0; i < suffixes; i++ {
		out = append(out, &Rule{
			Kind:    KindDomainSuffix,
			Payload: fmt.Sprintf("%s%d.%s", words[i%len(words)], i, tlds[i%len(tlds)]),
			Target:  "Proxy",
			Source:  "bench",
			index:   -1,
		})
	}
	seen := make(map[[5]byte]struct{}, prefixes)
	for len(seen) < prefixes {
		bits := uint8(8 + rnd.Intn(25))
		start := rnd.Uint32()
		start = start &^ (uint32(1)<<(32-bits) - 1)
		key := [5]byte{byte(start >> 24), byte(start >> 16), byte(start >> 8), byte(start), bits}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, &Rule{
			Kind:    KindIPCIDR,
			Payload: fmt.Sprintf("%s/%d", u32ToIP(start), bits),
			Target:  "DIRECT",
			Source:  "bench",
			index:   -1,
		})
	}
	return out
}
