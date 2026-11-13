package rules

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
)

const (
	scaleSuffixes = 50000
	scalePrefixes = 50000
	scaleSeed     = 42
)

var (
	scaleProgram *Program
	scaleHosts   []string
	scaleAddrs   [][]byte
)

func scaleSetup(tb testing.TB) (*Program, []string, [][]byte) {
	tb.Helper()
	if scaleProgram != nil {
		return scaleProgram, scaleHosts, scaleAddrs
	}
	rules := buildScaleRules(scaleSuffixes, scalePrefixes, scaleSeed)
	p, err := Compile(Options{Rules: rules})
	if err != nil {
		tb.Fatalf("Compile: %v", err)
	}
	if got := p.Len(); got != scaleSuffixes+scalePrefixes {
		tb.Fatalf("compiled %d rules, want %d", got, scaleSuffixes+scalePrefixes)
	}
	rnd := rand.New(rand.NewSource(scaleSeed))
	for i := 0; i < 4096; i++ {
		switch i % 3 {
		case 0, 1:
			src := rules[rnd.Intn(scaleSuffixes)]
			scaleHosts = append(scaleHosts, fmt.Sprintf("probe%d.%s", i, src.Payload))
		default:
			scaleHosts = append(scaleHosts, fmt.Sprintf("nomatch%d.invalid", i))
		}
		scaleAddrs = append(scaleAddrs, net.ParseIP(fmt.Sprintf("%d.%d.%d.%d",
			rnd.Intn(256), rnd.Intn(256), rnd.Intn(256), rnd.Intn(256))))
	}
	scaleProgram = p
	return p, scaleHosts, scaleAddrs
}

// TestScaleMatches checks that a 100k rule program answers correctly and that
// the index stays coherent at scale.
func TestScaleMatches(t *testing.T) {
	p, hosts, addrs := scaleSetup(t)
	if len(p.Rules()) != scaleSuffixes+scalePrefixes {
		t.Fatalf("rule count = %d", len(p.Rules()))
	}
	stats := p.Stats()
	if stats.Ranges4 == 0 || stats.Ranges4 > scalePrefixes {
		t.Fatalf("unexpected range count %d", stats.Ranges4)
	}
	hits := 0
	for i, host := range hosts {
		d, ok := p.Match(Query{Name: host, Addr: addrs[i], Port: 443, Network: "tcp"})
		if !ok {
			t.Fatalf("%q did not match", host)
		}
		if d.Rule == nil {
			t.Fatalf("%q produced a nil rule", host)
		}
		if d.Target == "Proxy" || d.Target == "DIRECT" {
			hits++
		}
	}
	if hits == 0 {
		t.Fatal("no probe matched a generated rule")
	}
}

func BenchmarkMatchDomain(b *testing.B) {
	p, hosts, _ := scaleSetup(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Match(Query{Name: hosts[i%len(hosts)]})
	}
}

func BenchmarkMatchAddr(b *testing.B) {
	p, _, addrs := scaleSetup(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Match(Query{Addr: addrs[i%len(addrs)]})
	}
}

func BenchmarkMatchMixed(b *testing.B) {
	p, hosts, addrs := scaleSetup(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			p.Match(Query{Name: hosts[i%len(hosts)], Port: 443, Network: "tcp"})
			continue
		}
		p.Match(Query{Addr: addrs[i%len(addrs)], Port: 443, Network: "tcp"})
	}
}

func BenchmarkCompile(b *testing.B) {
	rules := buildScaleRules(scaleSuffixes, scalePrefixes, scaleSeed)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Compile(Options{Rules: rules}); err != nil {
			b.Fatalf("Compile: %v", err)
		}
	}
}
