package inbound

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
	"github.com/melon-tgj/melonarc/internal/policy"
)

// stubRouter is a Router that returns one fixed route and counts the failures
// reported to it.
type stubRouter struct {
	dialer outbound.Dialer
	path   []string
	err    error

	mu     sync.Mutex
	failed int
}

// Route implements Router.
func (r *stubRouter) Route(string) (outbound.Dialer, []string, error) {
	return r.dialer, r.path, r.err
}

// Failed implements Router.
func (r *stubRouter) Failed([]string) {
	r.mu.Lock()
	r.failed++
	r.mu.Unlock()
}

// Failures is the number of times Failed was called.
func (r *stubRouter) Failures() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed
}

// echoThrough copies from the connection back to itself so a pipeline test has
// something to talk to.
func echoThrough(conn net.Conn) {
	_, _ = io.Copy(conn, conn)
}

// TestHandlerRoutesByDestinationAndPort checks that the pipeline hands the rule
// engine the destination the client asked for, in the dimension the rule uses:
// a name for a name rule, an address for an address rule, and the port for
// both.
func TestHandlerRoutesByDestinationAndPort(t *testing.T) {
	const (
		originHost = "origin.test"
		originAddr = "203.0.113.7"
		originPort = 8080
	)
	// newLeaves builds a fresh set per case, so the dial records of one case
	// cannot be read as those of the next.
	newLeaves := func() map[string]outbound.Dialer {
		broken := func(string) (net.Conn, error) { return nil, errors.New("no stream") }
		return map[string]outbound.Dialer{
			"ByName":   &fakeDialer{streamFn: broken},
			"ByAddr":   &fakeDialer{streamFn: broken},
			"Fallback": &fakeDialer{streamFn: broken},
		}
	}
	rules := []string{
		"DOMAIN,origin.test,ByName",
		"IP-CIDR,203.0.113.0/24,ByAddr",
		"FINAL,Fallback",
	}

	tests := []struct {
		name       string
		target     outbound.Target
		wantDialer string
	}{
		{
			name:       "a name is matched by a name rule",
			target:     outbound.Target{Host: originHost, Port: 80},
			wantDialer: "ByName",
		},
		{
			name:       "an address is matched by an address rule",
			target:     outbound.Target{Host: originAddr, Port: originPort},
			wantDialer: "ByAddr",
		},
		{
			name:       "anything else falls through to FINAL",
			target:     outbound.Target{Host: "198.51.100.9", Port: 443},
			wantDialer: "Fallback",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaves := newLeaves()
			env := newTestEnv(t, envOptions{rules: rules, leaves: leaves})
			ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
			defer cancel()
			_, sel, err := env.handler.Stream(ctx, Request{Target: tc.target, Network: networkTCP})
			if err == nil {
				t.Fatal("the scripted dialers never succeed")
			}
			if len(sel.Path) != 1 || sel.Path[0] != sel.Target {
				t.Fatalf("path = %v, want the target %q", sel.Path, sel.Target)
			}
			if sel.Rule == nil {
				t.Fatal("the selection carries no rule")
			}
			if sel.Target != tc.wantDialer {
				t.Fatalf("rule chose %q, want %q (rule: %s)", sel.Target, tc.wantDialer, sel.Rule)
			}
			for name, dialer := range leaves {
				got := dialer.(*fakeDialer).Streams()
				if name == tc.wantDialer {
					if len(got) != 1 || got[0] != tc.target.String() {
						t.Errorf("%s dialed %v, want exactly %s", name, got, tc.target)
					}
					continue
				}
				if len(got) != 0 {
					t.Errorf("%s was dialed %v and should not have been", name, got)
				}
			}
		})
	}
}

// TestHandlerReportsFailureToTheRouter checks that a failed dial is reported and
// that a rejection is not: a rule that blocks traffic did its job, so treating
// it as a member failure would mark a healthy proxy down.
func TestHandlerReportsFailureToTheRouter(t *testing.T) {
	tests := []struct {
		name     string
		dialer   outbound.Dialer
		wantFail int
		wantErr  error
	}{
		{
			name: "a broken dial is a failure",
			dialer: &fakeDialer{streamFn: func(string) (net.Conn, error) {
				return nil, errors.New("connection refused")
			}},
			wantFail: 1,
		},
		{
			name:     "a rejection is not a failure",
			dialer:   outbound.NewReject(),
			wantFail: 0,
			wantErr:  outbound.ErrRejected,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			router := &stubRouter{dialer: tc.dialer, path: []string{"auto", "member"}}
			handler, err := NewHandler(HandlerOptions{
				Matcher: newTestProgram(t, "FINAL,DIRECT"),
				Router:  router,
				Logger:  testLogger(),
			})
			if err != nil {
				t.Fatalf("NewHandler: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
			defer cancel()
			_, sel, err := handler.Stream(ctx, Request{
				Target:  outbound.Target{Host: "127.0.0.1", Port: 9},
				Network: networkTCP,
			})
			if err == nil {
				t.Fatal("expected the dial to fail")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got := router.Failures(); got != tc.wantFail {
				t.Fatalf("failures reported = %d, want %d", got, tc.wantFail)
			}
			if len(sel.Path) != 2 {
				t.Fatalf("path = %v, want the router path", sel.Path)
			}
		})
	}
}

// TestHandlerRejectsUnknownNetwork makes sure a transport the rules cannot
// classify never reaches a dialer.
func TestHandlerRejectsUnknownNetwork(t *testing.T) {
	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,DIRECT"},
		leaves: map[string]outbound.Dialer{"DIRECT": &fakeDialer{}},
	})
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	if _, _, err := env.handler.Stream(ctx, Request{
		Target:  outbound.Target{Host: "127.0.0.1", Port: 80},
		Network: "icmp",
	}); err == nil {
		t.Fatal("an unknown transport was accepted")
	}
}

// TestHandlerFailureMovesAFallbackGroup is the end-to-end version of the
// failure report: a Fallback group whose first member cannot be reached must
// move to its second member immediately, without waiting for a probe round.
func TestHandlerFailureMovesAFallbackGroup(t *testing.T) {
	dead := &fakeDialer{streamFn: func(string) (net.Conn, error) {
		return nil, errors.New("network is unreachable")
	}}
	group, err := policy.NewFallback("auto", []string{"dead", "DIRECT"}, failingProber(), time.Minute, time.Second)
	if err != nil {
		t.Fatalf("NewFallback: %v", err)
	}
	if got := group.Active(); got != "dead" {
		t.Fatalf("active = %q, want the first member before any failure", got)
	}

	direct := &fakeDialer{streamFn: func(string) (net.Conn, error) { return nil, errors.New("stop here") }}
	env := newTestEnv(t, envOptions{
		rules: []string{"FINAL,auto"},
		leaves: map[string]outbound.Dialer{
			"dead":   dead,
			"DIRECT": direct,
		},
		groups: []policy.Group{group},
	})

	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	if _, _, err := env.handler.Stream(ctx, Request{
		Target:  outbound.Target{Host: "127.0.0.1", Port: 80},
		Network: networkTCP,
	}); err == nil {
		t.Fatal("expected the first member to fail")
	}
	if got := group.Active(); got != "DIRECT" {
		t.Fatalf("active = %q, want DIRECT after the reported failure", got)
	}
	// The next request must now go to the second member without another
	// failure being needed to steer it.
	if _, _, err := env.handler.Stream(ctx, Request{
		Target:  outbound.Target{Host: "127.0.0.1", Port: 81},
		Network: networkTCP,
	}); err == nil {
		t.Fatal("expected the scripted second member to stop the dial")
	}
	if got := direct.Streams(); len(got) != 1 || got[0] != "127.0.0.1:81" {
		t.Fatalf("DIRECT dialed %v, want the second request", got)
	}
}

// TestPolicyRouterFailureWalksEveryGroup checks that a failure is reported to
// every group on the resolution path, which is what keeps a nested group from
// staying on a member that is known to be down.
func TestPolicyRouterFailureWalksEveryGroup(t *testing.T) {
	inner, err := policy.NewFallback("inner", []string{"dead", "DIRECT"}, failingProber(), time.Minute, time.Second)
	if err != nil {
		t.Fatalf("NewFallback(inner): %v", err)
	}
	outer, err := policy.NewFallback("outer", []string{"inner", "DIRECT"}, failingProber(), time.Minute, time.Second)
	if err != nil {
		t.Fatalf("NewFallback(outer): %v", err)
	}
	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,outer"},
		leaves: map[string]outbound.Dialer{"dead": &fakeDialer{}, "DIRECT": outbound.NewDirect()},
		groups: []policy.Group{outer, inner},
	})

	resolution, err := env.registry.Resolve("outer")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := []string{"outer", "inner", "dead"}
	if len(resolution.Path) != len(want) {
		t.Fatalf("path = %v, want %v", resolution.Path, want)
	}
	for i, name := range want {
		if resolution.Path[i] != name {
			t.Fatalf("path = %v, want %v", resolution.Path, want)
		}
	}

	env.router.Failed(resolution.Path)

	if got := inner.Active(); got != "DIRECT" {
		t.Errorf("inner active = %q, want DIRECT", got)
	}
	if got := outer.Active(); got != "DIRECT" {
		t.Errorf("outer active = %q, want DIRECT", got)
	}
}
