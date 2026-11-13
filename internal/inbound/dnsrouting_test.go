package inbound

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/outbound"
)

// startOriginOn serves body on one loopback address. Two of them on different
// addresses are how a test gives two names different addresses while everything
// stays on the machine.
func startOriginOn(t *testing.T, ip, body string) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Skipf("this environment cannot bind %s: %v", ip, err)
	}
	srv := &httptest.Server{
		Listener: listener,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		})},
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// countingLookup stands in for the system resolver: it records the names it is
// asked for and refuses them all. Every name in this test is mapped by [Host], so
// any call would be a bug, and the count is the proof.
type countingLookup struct {
	names *[]string
}

// lookup implements dns.LookupFunc.
func (l countingLookup) lookup(_ context.Context, host string) ([]net.IP, error) {
	*l.names = append(*l.names, host)
	return nil, fmt.Errorf("the system resolver must not run for %s", host)
}

// TestHostMappingDrivesTheIPRules is the end-to-end proof of the DNS layer: a
// name is mapped by [Host], the mapped address decides an IP rule, and the
// request leaves by the path that rule chose.
//
// The same pair of destinations is used twice. Without no-resolve the mapped
// address matches the IP rule and the request goes through the proxy; with
// no-resolve the name stays a name, the IP rule cannot fire, and the request
// reaches the second origin directly. Nothing about the configuration changes but
// one keyword, so the difference in outcome can only come from the semantics
// under test.
func TestHostMappingDrivesTheIPRules(t *testing.T) {
	directOrigin := startOriginOn(t, "127.0.0.1", "direct origin")
	proxiedOrigin := startOriginOn(t, "127.0.0.2", "proxied origin")
	directPort := portOf(t, hostPort(t, directOrigin.URL))
	proxiedPort := portOf(t, hostPort(t, proxiedOrigin.URL))
	directName := net.JoinHostPort("direct.test", fmt.Sprint(directPort))
	proxiedName := net.JoinHostPort("proxied.test", fmt.Sprint(proxiedPort))

	inbounds := []struct {
		name  string
		fetch fetchFunc
		start func(t *testing.T, env *testEnv) string
	}{
		{
			name:  "http inbound",
			fetch: fetchThroughHTTPProxy,
			start: func(t *testing.T, env *testEnv) string {
				return startHTTPService(t, env).Addr()
			},
		},
		{
			name:  "socks5 inbound",
			fetch: fetchThroughSOCKS5,
			start: func(t *testing.T, env *testEnv) string {
				return startSOCKS5Service(t, env).Addr()
			},
		},
	}

	cases := []struct {
		name       string
		rule       string
		want       string
		wantTarget []string
	}{
		{
			name:       "mapped address matches the IP rule",
			rule:       "IP-CIDR,127.0.0.2/32,via",
			want:       "proxied " + proxiedName,
			wantTarget: []string{proxiedName},
		},
		{
			name:       "no-resolve keeps the name off the IP rule",
			rule:       "IP-CIDR,127.0.0.2/32,via,no-resolve",
			want:       "proxied origin",
			wantTarget: nil,
		},
	}

	for _, inbound := range inbounds {
		t.Run(inbound.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					var looked []string
					resolver, err := dns.New(dns.Options{
						Hosts: map[string][]net.IP{
							"direct.test":  {net.ParseIP("127.0.0.1")},
							"proxied.test": {net.ParseIP("127.0.0.2")},
						},
						Lookup: countingLookup{names: &looked}.lookup,
					})
					if err != nil {
						t.Fatalf("dns.New: %v", err)
					}

					proxy := startRecordingProxy(t)
					via, err := outbound.NewSOCKS5(outbound.SOCKS5Options{
						Server:  splitHost(t, proxy.addr),
						Port:    portOf(t, proxy.addr),
						Timeout: testDeadline,
					})
					if err != nil {
						t.Fatalf("NewSOCKS5: %v", err)
					}
					// DIRECT resolves through the same resolver, as the daemon
					// wires it: a name the pipeline already looked up must not
					// cost a second query.
					direct := &outbound.Direct{Timeout: testDeadline, Lookup: resolver.Lookup}
					env := newTestEnv(t, envOptions{
						rules: []string{tc.rule, "FINAL,DIRECT"},
						leaves: map[string]outbound.Dialer{
							"DIRECT": direct,
							"via":    via,
						},
						resolver: resolver,
					})
					serviceAddr := inbound.start(t, env)

					// The name the IP rule does not cover stays on the direct
					// path in both cases: the rule only speaks about one address.
					if got := inbound.fetch(t, serviceAddr, directName); got != "direct origin" {
						t.Fatalf("the unmapped path answered %q, want the direct origin", got)
					}

					if got := inbound.fetch(t, serviceAddr, proxiedName); got != tc.want {
						t.Fatalf("proxied.test answered %q, want %q", got, tc.want)
					}
					targets := make([]string, 0, len(proxy.Targets()))
					for _, target := range proxy.Targets() {
						targets = append(targets, target.String())
					}
					if len(targets) != len(tc.wantTarget) {
						t.Fatalf("the proxy was asked for %v, want %v", targets, tc.wantTarget)
					}
					for i, want := range tc.wantTarget {
						if targets[i] != want {
							t.Fatalf("the proxy was asked for %v, want %v", targets, tc.wantTarget)
						}
					}
					// Every name is in [Host], so the system resolver must never
					// have run, on the matching path or on the dial path.
					if len(looked) != 0 {
						t.Fatalf("the system resolver ran for %v, want no lookup", looked)
					}
				})
			}
		})
	}
}
