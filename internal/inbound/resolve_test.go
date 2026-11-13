package inbound

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/outbound"
	"github.com/melon-tgj/melonarc/internal/rules"
)

// countingResolver answers from a script and records every name it was asked
// for. It is how a test proves that a lookup did or did not happen: the point of
// no-resolve is an absent call, which nothing else can show.
type countingResolver struct {
	answer map[string][]net.IP
	source dns.Source
	err    error

	mu    sync.Mutex
	names []string
}

// Resolve implements Resolver.
func (r *countingResolver) Resolve(_ context.Context, host string) (dns.Result, error) {
	r.mu.Lock()
	r.names = append(r.names, host)
	r.mu.Unlock()
	if r.err != nil {
		return dns.Result{}, r.err
	}
	ips, ok := r.answer[host]
	if !ok {
		return dns.Result{}, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	source := r.source
	if source == "" {
		source = dns.SourceSystem
	}
	return dns.Result{IPs: ips, Source: source}, nil
}

// count returns how many lookups were made.
func (r *countingResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.names)
}

// asked returns the names looked up, in order.
func (r *countingResolver) asked() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.names...)
}

// streamDialer is a fakeDialer that hands back one end of an in-memory pipe and
// closes the other: enough for a test that only cares which path a request took.
func streamDialer() *fakeDialer {
	return &fakeDialer{streamFn: func(string) (net.Conn, error) {
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}}
}

// TestNoResolveDoesNotTriggerALookup is the acceptance case for the flag: a rule
// set whose address rules all carry no-resolve must not resolve the destination
// at all, so the destination falls through to the rule that does not need an
// address.
func TestNoResolveDoesNotTriggerALookup(t *testing.T) {
	guarded, named := streamDialer(), streamDialer()
	resolver := &countingResolver{answer: map[string][]net.IP{
		"inside.test": {net.ParseIP("10.1.2.3")},
	}}
	env := newTestEnv(t, envOptions{
		rules: []string{
			"IP-CIDR,10.0.0.0/8,Guarded,no-resolve",
			"FINAL,Named",
		},
		leaves:   map[string]outbound.Dialer{"Guarded": guarded, "Named": named},
		resolver: resolver,
	})

	conn, sel, err := env.handler.Stream(context.Background(), Request{
		Target:  outbound.Target{Host: "inside.test", Port: 443},
		Network: networkTCP,
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer conn.Close()

	if got := resolver.count(); got != 0 {
		t.Fatalf("the resolver was asked %d times (%v), want 0: every address rule carries no-resolve",
			got, resolver.asked())
	}
	if sel.Target != "Named" || sel.Rule.Kind != rules.KindFinal {
		t.Fatalf("selection = %s, want the FINAL rule: an address rule must not see a name", sel.Rule)
	}
	if got := guarded.Streams(); len(got) != 0 {
		t.Fatalf("the guarded path was dialed: %v", got)
	}
	if got := named.Streams(); len(got) != 1 || got[0] != "inside.test:443" {
		t.Fatalf("the named path was dialed %v, want the destination once", got)
	}
}

// TestResolvedNameMatchesAnAddressRule is the other half of the semantics: a
// destination without no-resolve is resolved, the address decides the rule, and
// the outbound still receives the name so a proxy can resolve it remotely.
func TestResolvedNameMatchesAnAddressRule(t *testing.T) {
	byAddr, named := streamDialer(), streamDialer()
	resolver := &countingResolver{answer: map[string][]net.IP{
		"inside.test": {net.ParseIP("10.1.2.3")},
	}}
	env := newTestEnv(t, envOptions{
		rules: []string{
			"IP-CIDR,10.0.0.0/8,ByAddr",
			"FINAL,Named",
		},
		leaves:   map[string]outbound.Dialer{"ByAddr": byAddr, "Named": named},
		resolver: resolver,
	})

	conn, sel, err := env.handler.Stream(context.Background(), Request{
		Target:  outbound.Target{Host: "inside.test", Port: 443},
		Network: networkTCP,
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer conn.Close()

	if got := resolver.count(); got != 1 {
		t.Fatalf("the resolver was asked %d times, want 1", got)
	}
	if sel.Target != "ByAddr" || sel.Rule.Kind != rules.KindIPCIDR {
		t.Fatalf("selection = %s, want the IP-CIDR rule", sel.Rule)
	}
	if got := byAddr.Streams(); len(got) != 1 || got[0] != "inside.test:443" {
		t.Fatalf("the address path was dialed %v, want the name %q: the outbound resolves it",
			got, "inside.test:443")
	}
	if got := named.Streams(); len(got) != 0 {
		t.Fatalf("the name path was dialed: %v", got)
	}
}

// TestNoResolveRuleIsSkippedBesideAnOpenOne checks the mixed case: the lookup
// happens because one address rule needs it, and the rule that carries
// no-resolve still stays out of the decision.
func TestNoResolveRuleIsSkippedBesideAnOpenOne(t *testing.T) {
	guarded, open := streamDialer(), streamDialer()
	resolver := &countingResolver{answer: map[string][]net.IP{
		"inside.test": {net.ParseIP("10.1.2.3")},
	}}
	env := newTestEnv(t, envOptions{
		rules: []string{
			"IP-CIDR,10.0.0.0/8,Guarded,no-resolve",
			"IP-CIDR,10.0.0.0/8,Open",
			"FINAL,Guarded",
		},
		leaves:   map[string]outbound.Dialer{"Guarded": guarded, "Open": open},
		resolver: resolver,
	})

	conn, sel, err := env.handler.Stream(context.Background(), Request{
		Target:  outbound.Target{Host: "inside.test", Port: 443},
		Network: networkTCP,
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer conn.Close()

	if got := resolver.count(); got != 1 {
		t.Fatalf("the resolver was asked %d times, want 1: one rule needs an address", got)
	}
	if sel.Target != "Open" || sel.Rule.Index() != 1 {
		t.Fatalf("selection = %s at index %d, want the rule that accepts a resolved address",
			sel.Rule, sel.Rule.Index())
	}
}

// TestDirectReusesTheResolvedAnswer checks the other end of the pipeline: once a
// name has been resolved for matching, the direct dial must not resolve it a
// second time. The counting lookup sees one call for one request, and the
// connection still reaches the endpoint.
func TestDirectReusesTheResolvedAnswer(t *testing.T) {
	echo := startEcho(t)
	echoTarget, err := outbound.ParseTarget(echo)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	var (
		mu     sync.Mutex
		looked []string
	)
	resolver, err := dns.New(dns.Options{
		Lookup: func(_ context.Context, host string) ([]net.IP, error) {
			mu.Lock()
			looked = append(looked, host)
			mu.Unlock()
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	})
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	direct := &outbound.Direct{Timeout: testDeadline, Lookup: resolver.Lookup}
	env := newTestEnv(t, envOptions{
		rules:    []string{"IP-CIDR,127.0.0.0/8,DIRECT", "FINAL,DIRECT"},
		leaves:   map[string]outbound.Dialer{"DIRECT": direct},
		resolver: resolver,
	})

	conn, sel, err := env.handler.Stream(context.Background(), Request{
		Target:  outbound.Target{Host: "once.test", Port: echoTarget.Port},
		Network: networkTCP,
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer conn.Close()
	if sel.Target != "DIRECT" || sel.Rule.Kind != rules.KindIPCIDR {
		t.Fatalf("selection = %s, want the IP-CIDR rule", sel.Rule)
	}

	mu.Lock()
	got := append([]string(nil), looked...)
	mu.Unlock()
	if len(got) != 1 || got[0] != "once.test" {
		t.Fatalf("the name was looked up %v, want exactly one lookup: the dial reused the answer", got)
	}

	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hi" {
		t.Fatalf("echo = %q, want %q", buf, "hi")
	}
}

// TestFailedLookupKeepsTheNameRulesWorking checks that a name the resolver cannot
// answer still routes: matching continues without an address, and the dial is
// what decides whether the request fails.
func TestFailedLookupKeepsTheNameRulesWorking(t *testing.T) {
	byAddr, named := streamDialer(), streamDialer()
	resolver := &countingResolver{
		err: &net.DNSError{Err: "no such host", Name: "inside.test", IsNotFound: true},
	}
	env := newTestEnv(t, envOptions{
		rules: []string{
			"IP-CIDR,10.0.0.0/8,ByAddr",
			"DOMAIN-SUFFIX,inside.test,Named",
			"FINAL,ByAddr",
		},
		leaves:   map[string]outbound.Dialer{"ByAddr": byAddr, "Named": named},
		resolver: resolver,
	})

	conn, sel, err := env.handler.Stream(context.Background(), Request{
		Target:  outbound.Target{Host: "inside.test", Port: 443},
		Network: networkTCP,
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer conn.Close()

	if sel.Target != "Named" {
		t.Fatalf("selection = %s, want the name rule", sel.Rule)
	}
	if got := named.Streams(); len(got) != 1 {
		t.Fatalf("the name path was dialed %v, want it once", got)
	}
}

// TestExplainReportsWhereTheAddressCameFrom checks the operator-facing half of
// the feature: the report names the source of the address the rules saw.
func TestExplainReportsWhereTheAddressCameFrom(t *testing.T) {
	resolver := &countingResolver{
		answer: map[string][]net.IP{"inside.test": {net.ParseIP("10.1.2.3")}},
		source: dns.SourceHosts,
	}
	env := newTestEnv(t, envOptions{
		rules:    []string{"IP-CIDR,10.0.0.0/8,Guarded", "FINAL,Named"},
		leaves:   map[string]outbound.Dialer{"Guarded": streamDialer(), "Named": streamDialer()},
		resolver: resolver,
	})

	exp, err := env.handler.Explain(context.Background(), rules.Query{
		Name: "inside.test", Port: 443, Network: networkTCP,
	})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if exp.Resolution == nil {
		t.Fatal("the explanation carries no resolution record")
	}
	if exp.Resolution.Source != string(dns.SourceHosts) {
		t.Fatalf("resolution source = %q, want %q", exp.Resolution.Source, dns.SourceHosts)
	}
	if len(exp.Resolution.Addrs) != 1 || !exp.Resolution.Addrs[0].Equal(net.ParseIP("10.1.2.3")) {
		t.Fatalf("resolution addresses = %v", exp.Resolution.Addrs)
	}
	if report := exp.String(); !strings.Contains(report, "resolution: 10.1.2.3 (hosts)") {
		t.Fatalf("report =\n%s\nwant the resolution line", report)
	}
	if !exp.Matched || exp.Decision.Target != "Guarded" {
		t.Fatalf("decision = %s, want the address rule", exp.Decision)
	}
}

// TestExplainSaysWhenNoLookupWasNeeded checks that the report distinguishes "the
// address came from the cache" from "nothing was looked up at all", which is the
// question the flag exists to answer.
func TestExplainSaysWhenNoLookupWasNeeded(t *testing.T) {
	resolver := &countingResolver{answer: map[string][]net.IP{
		"inside.test": {net.ParseIP("10.1.2.3")},
	}}
	env := newTestEnv(t, envOptions{
		rules: []string{
			"IP-CIDR,10.0.0.0/8,Guarded,no-resolve",
			"FINAL,Named",
		},
		leaves:   map[string]outbound.Dialer{"Guarded": streamDialer(), "Named": streamDialer()},
		resolver: resolver,
	})

	exp, err := env.handler.Explain(context.Background(), rules.Query{Name: "inside.test"})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if exp.Resolution.Source != "" {
		t.Fatalf("resolution source = %q, want none", exp.Resolution.Source)
	}
	if report := exp.String(); !strings.Contains(report, "resolution: not attempted") {
		t.Fatalf("report =\n%s\nwant it to say no lookup was made", report)
	}
	if got := resolver.count(); got != 0 {
		t.Fatalf("the resolver was asked %d times, want 0", got)
	}
}
