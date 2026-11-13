package inbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/outbound"
)

// waitFor polls cond until it holds or the test deadline passes. The counters
// move on the handler goroutines, so a test that reads them right after closing
// a connection would be racing the deferred decrement.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testDeadline)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// deadAddress returns a loopback address nothing listens on. The port is
// released before it is returned, so the test only needs the connection to be
// refused, which it is either way.
func deadAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

// connectStatus performs a CONNECT handshake and returns the status code the
// proxy answered with, without failing on a non-200 answer.
func connectStatus(t *testing.T, proxyAddr, target string) int {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testDeadline))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	var code int
	if _, err := fmt.Sscanf(status, "HTTP/1.1 %d", &code); err != nil {
		t.Fatalf("parse status line %q: %v", strings.TrimSpace(status), err)
	}
	return code
}

// protocolStats returns the counters of one protocol, failing when the listener
// is not reported at all.
func protocolStats(t *testing.T, m *Metrics, protocol string) ProtocolStats {
	t.Helper()
	for _, p := range m.Snapshot().Protocols {
		if p.Protocol == protocol {
			return p
		}
	}
	t.Fatalf("%s is missing from the snapshot: %+v", protocol, m.Snapshot())
	return ProtocolStats{}
}

// TestMetricsCountConnectionsPerProtocol checks that a connection moves the
// counters of its own listener and no other.
func TestMetricsCountConnectionsPerProtocol(t *testing.T) {
	m := NewMetrics(4)
	m.listen(protocolHTTP)
	m.connectionOpened(protocolHTTP)
	m.connectionOpened(protocolHTTP)
	m.connectionClosed(protocolHTTP)
	m.datagramOpened()
	m.datagramClosed()

	snap := m.Snapshot()
	if len(snap.Protocols) != 1 {
		t.Fatalf("snapshot lists %+v, want only the bound listener", snap.Protocols)
	}
	got := snap.Protocols[0]
	if got.Protocol != protocolHTTP || got.Open != 1 || got.Accepted != 2 {
		t.Fatalf("counters = %+v, want one open out of two accepted", got)
	}
	// A datagram association belongs to the SOCKS5 listener, which is not
	// bound here, so the HTTP counters never see it.
	if got.Datagrams != 0 || got.DatagramTotal != 0 {
		t.Fatalf("http listener reports datagram counters: %+v", got)
	}
}

// TestMetricsCountersAreConcurrencySafe hammers the counters from many
// goroutines: every open has a close, so the open count has to come back to
// zero and the accepted count has to be exact.
func TestMetricsCountersAreConcurrencySafe(t *testing.T) {
	m := NewMetrics(4)
	m.listen(protocolSOCKS5)
	const (
		workers = 16
		rounds  = 200
	)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				m.connectionOpened(protocolSOCKS5)
				m.datagramOpened()
				m.datagramClosed()
				m.connectionClosed(protocolSOCKS5)
			}
		}()
	}
	wg.Wait()

	got := protocolStats(t, m, protocolSOCKS5)
	if got.Open != 0 {
		t.Errorf("open = %d after every connection closed", got.Open)
	}
	if want := uint64(workers * rounds); got.Accepted != want {
		t.Errorf("accepted = %d, want %d", got.Accepted, want)
	}
	if got.Datagrams != 0 {
		t.Errorf("datagrams = %d after every association closed", got.Datagrams)
	}
	if want := uint64(workers * rounds); got.DatagramTotal != want {
		t.Errorf("datagram total = %d, want %d", got.DatagramTotal, want)
	}
}

// TestFailureRingEvictsTheOldest checks the bound: the ring keeps the newest
// records and the counters keep counting everything.
func TestFailureRingEvictsTheOldest(t *testing.T) {
	m := NewMetrics(3)
	for i := 0; i < 5; i++ {
		m.Record(Failure{
			Time:     time.Unix(int64(i), 0),
			Target:   fmt.Sprintf("host%d.example:443", i),
			Stage:    StageDial,
			Category: CategoryUnknown,
		})
	}
	got := m.Recent(0)
	if len(got) != 3 {
		t.Fatalf("ring holds %d records, want 3", len(got))
	}
	for i, want := range []string{"host2.example:443", "host3.example:443", "host4.example:443"} {
		if got[i].Target != want {
			t.Errorf("record %d = %q, want %q (oldest first)", i, got[i].Target, want)
		}
	}
	snap := m.Snapshot()
	if snap.FailureCount != 3 || snap.FailureCapacity != 3 {
		t.Errorf("record size = %d/%d, want 3/3", snap.FailureCount, snap.FailureCapacity)
	}
	if snap.Failures != 5 {
		t.Errorf("failures = %d, want 5: eviction must not lose the count", snap.Failures)
	}
}

// TestRecentHonoursTheLimit checks that a limit narrows to the newest records
// without changing the order.
func TestRecentHonoursTheLimit(t *testing.T) {
	m := NewMetrics(8)
	for i := 0; i < 4; i++ {
		m.Record(Failure{Target: fmt.Sprintf("h%d:1", i), Category: CategoryUnknown})
	}
	got := m.Recent(2)
	if len(got) != 2 || got[0].Target != "h2:1" || got[1].Target != "h3:1" {
		t.Fatalf("recent(2) = %+v", got)
	}
	if count := m.Snapshot().FailureCount; count != 4 {
		t.Fatalf("count = %d, want 4: the limit is a view, not an eviction", count)
	}
}

// TestRejectionsAreCountedApart makes sure a blocked destination is visible
// without being counted as a fault.
func TestRejectionsAreCountedApart(t *testing.T) {
	m := NewMetrics(8)
	m.Record(Failure{Target: "ads.example:443", Stage: StageDial, Category: CategoryRejected})
	m.Record(Failure{Target: "dead.example:443", Stage: StageDial, Category: CategoryRefused})

	snap := m.Snapshot()
	if snap.Rejected != 1 || snap.Failures != 1 {
		t.Fatalf("counters = rejected %d failures %d, want 1 and 1", snap.Rejected, snap.Failures)
	}
	if snap.FailureCount != 2 {
		t.Fatalf("record count = %d, want both kinds kept", snap.FailureCount)
	}
}

// TestNilMetricsIsSafe keeps the nil receiver a supported state: a listener
// built without metrics must behave exactly as before.
func TestNilMetricsIsSafe(t *testing.T) {
	var m *Metrics
	m.listen(protocolHTTP)
	m.connectionOpened(protocolHTTP)
	m.connectionClosed(protocolHTTP)
	m.datagramOpened()
	m.datagramClosed()
	m.Record(Failure{Category: CategoryRefused})

	if snap := m.Snapshot(); len(snap.Protocols) != 0 || snap.FailureCount != 0 {
		t.Fatalf("a nil Metrics produced %+v", snap)
	}
	if got := m.Recent(0); got != nil {
		t.Fatalf("Recent on a nil Metrics = %+v", got)
	}

	// The zero value is the other half of the same promise: it records
	// nothing, but it must not panic.
	zero := &Metrics{}
	zero.Record(Failure{Category: CategoryRefused})
	zero.connectionOpened(protocolHTTP)
	if snap := zero.Snapshot(); snap.FailureCount != 0 || len(snap.Protocols) != 0 {
		t.Fatalf("a zero Metrics produced %+v", snap)
	}
	if got := zero.Recent(0); got != nil {
		t.Fatalf("Recent on a zero Metrics = %+v", got)
	}
}

// timeoutError is a net.Error that reports a timeout, which is how a dial
// deadline reaches the categoriser.
type timeoutError struct{}

func (timeoutError) Error() string   { return "fake timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestCategorise pins the mapping from an error to the category the API
// reports. The categories are the contract an operator reads.
func TestCategorise(t *testing.T) {
	tests := []struct {
		name  string
		stage string
		err   error
		want  string
	}{
		{name: "nil", stage: StageDial, err: nil, want: CategoryUnknown},
		{name: "rejected", stage: StageDial, err: outbound.ErrRejected, want: CategoryRejected},
		{
			name:  "wrapped rejection",
			stage: StageDial,
			err:   fmt.Errorf("dial: %w", outbound.ErrRejected),
			want:  CategoryRejected,
		},
		{name: "unsupported", stage: StageDial, err: outbound.ErrUnsupported, want: CategoryUnsupported},
		{name: "no dialer", stage: StageDial, err: outbound.ErrUnknownDialer, want: CategoryUnsupported},
		{name: "deadline", stage: StageDial, err: context.DeadlineExceeded, want: CategoryTimeout},
		{name: "cancelled", stage: StageDial, err: context.Canceled, want: CategoryCancelled},
		{name: "dns sentinel", stage: StageDial, err: dns.ErrNotFound, want: CategoryResolve},
		{
			name:  "dns error",
			stage: StageDial,
			err:   fmt.Errorf("dial: %w", &net.DNSError{Err: "no such host", IsNotFound: true}),
			want:  CategoryResolve,
		},
		{
			name:  "refused",
			stage: StageDial,
			err:   fmt.Errorf("dial: %w", syscall.ECONNREFUSED),
			want:  CategoryRefused,
		},
		{name: "host unreachable", stage: StageDial, err: syscall.EHOSTUNREACH, want: CategoryUnreachable},
		{name: "net timeout", stage: StageDial, err: timeoutError{}, want: CategoryTimeout},
		{
			name:  "route failure",
			stage: StageRoute,
			err:   errors.New("inbound: no rule matched"),
			want:  CategoryUnroutable,
		},
		{
			name:  "route sees an unsupported target",
			stage: StageRoute,
			err:   outbound.ErrUnknownDialer,
			want:  CategoryUnsupported,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := categorize(tc.stage, tc.err); got != tc.want {
				t.Fatalf("categorize(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestServiceCountsConnectionsAndFailures drives real connections through an
// HTTP inbound and checks the counters and the record they leave behind.
func TestServiceCountsConnectionsAndFailures(t *testing.T) {
	echo := startEcho(t)
	dead := deadAddress(t)
	metrics := NewMetrics(8)
	env := newTestEnv(t, envOptions{
		rules:   []string{"FINAL,DIRECT"},
		leaves:  map[string]outbound.Dialer{"DIRECT": outbound.NewDirect()},
		metrics: metrics,
	})
	srv := startHTTPService(t, env, func(o *HTTPOptions) { o.Metrics = metrics })

	conn, _ := httpConnect(t, srv.Addr(), echo)
	_ = conn.Close()
	if code := connectStatus(t, srv.Addr(), dead); code != http.StatusBadGateway {
		t.Fatalf("CONNECT to a dead address answered %d, want 502", code)
	}

	waitFor(t, "both connections to be counted", func() bool {
		p := protocolStats(t, metrics, protocolHTTP)
		return p.Accepted == 2 && p.Open == 0
	})

	snap := metrics.Snapshot()
	if snap.Failures != 1 || snap.Rejected != 0 {
		t.Fatalf("counters = failures %d rejected %d, want 1 and 0", snap.Failures, snap.Rejected)
	}
	records := metrics.Recent(0)
	if len(records) != 1 {
		t.Fatalf("record = %+v, want one failure", records)
	}
	rec := records[0]
	if rec.Target != dead || rec.Network != networkTCP || rec.Stage != StageDial {
		t.Fatalf("record = %+v, want the dead destination over tcp at the dial stage", rec)
	}
	if rec.Category != CategoryRefused {
		t.Fatalf("category = %q, want %q", rec.Category, CategoryRefused)
	}
	if rec.Time.IsZero() {
		t.Error("the record carries no timestamp")
	}
	if rec.Policy != "DIRECT" {
		t.Errorf("policy = %q, want the rule target", rec.Policy)
	}
}

// TestRouteFailureIsRecorded covers the stage before a dial: a destination no
// policy can be chosen for is a routing failure, not a network one.
func TestRouteFailureIsRecorded(t *testing.T) {
	metrics := NewMetrics(4)
	env := newTestEnv(t, envOptions{
		rules:   []string{"FINAL,nowhere"},
		leaves:  map[string]outbound.Dialer{"DIRECT": outbound.NewDirect()},
		metrics: metrics,
	})
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	if _, _, err := env.handler.Stream(ctx, Request{
		Target:  outbound.Target{Host: "example.test", Port: 443},
		Network: networkTCP,
	}); err == nil {
		t.Fatal("a request for an unknown policy succeeded")
	}
	records := metrics.Recent(0)
	if len(records) != 1 {
		t.Fatalf("records = %+v, want one", records)
	}
	got := records[0]
	if got.Stage != StageRoute || got.Category != CategoryUnroutable || got.Policy != "nowhere" {
		t.Fatalf("record = %+v, want a route failure for the declared policy", got)
	}
	if got.Target != "example.test:443" {
		t.Fatalf("target = %q", got.Target)
	}
	if snap := metrics.Snapshot(); snap.Failures != 1 || snap.Rejected != 0 {
		t.Fatalf("counters = %+v, want one failure and no rejection", snap)
	}
}

// TestRejectionIsRecordedWithoutBeingAFailure keeps the two apart: a rule that
// blocks a destination did its job, but the record still has to say so.
func TestRejectionIsRecordedWithoutBeingAFailure(t *testing.T) {
	metrics := NewMetrics(4)
	env := newTestEnv(t, envOptions{
		rules:   []string{"FINAL,REJECT"},
		leaves:  map[string]outbound.Dialer{"REJECT": outbound.NewReject()},
		metrics: metrics,
	})
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	_, _, err := env.handler.Stream(ctx, Request{
		Target:  outbound.Target{Host: "ads.example", Port: 443},
		Network: networkTCP,
	})
	if !errors.Is(err, outbound.ErrRejected) {
		t.Fatalf("error = %v, want ErrRejected", err)
	}
	records := metrics.Recent(0)
	if len(records) != 1 || records[0].Category != CategoryRejected {
		t.Fatalf("records = %+v, want one rejection", records)
	}
	snap := metrics.Snapshot()
	if snap.Rejected != 1 || snap.Failures != 0 {
		t.Fatalf("counters = rejected %d failures %d, want 1 and 0", snap.Rejected, snap.Failures)
	}
}

// TestServiceSurvivesAPanickingHandler checks the worst path of the counter
// lifecycle: a handler that panics must leave the connection count at zero and
// must not stop the listener.
func TestServiceSurvivesAPanickingHandler(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	metrics := NewMetrics(4)
	srv := newService(protocolHTTP, listener, func(context.Context, net.Conn) {
		panic("handler exploded")
	}, metrics, testLogger())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
		defer cancel()
		_ = srv.Close(ctx)
	})

	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", srv.Addr())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		_ = conn.Close()
	}
	waitFor(t, "the panicking connections to be released", func() bool {
		p := protocolStats(t, metrics, protocolHTTP)
		return p.Accepted == 2 && p.Open == 0
	})
}

// TestAssociationCountersFollowTheControlConnection checks that an association
// is counted while it is open and released when the client goes away.
func TestAssociationCountersFollowTheControlConnection(t *testing.T) {
	metrics := NewMetrics(4)
	proxy := startSOCKS5Service(t, directEnv(t), func(o *SOCKS5Options) { o.Metrics = metrics })
	client := dialRaw(t, proxy.Addr())
	if got := client.greet(t, methodNoAuth); got != methodNoAuth {
		t.Fatalf("selected method = %#x, want none", got)
	}
	code, bound := client.request(t, commandUDPAssociate, outbound.Target{Host: "0.0.0.0"})
	if code != replySucceeded || bound.Port == 0 {
		t.Fatalf("association reply = %#x bound %v", code, bound)
	}
	waitFor(t, "the association to be counted", func() bool {
		return protocolStats(t, metrics, protocolSOCKS5).Datagrams == 1
	})

	_ = client.conn.Close()
	waitFor(t, "the association to be released", func() bool {
		return protocolStats(t, metrics, protocolSOCKS5).Datagrams == 0
	})
	if got := protocolStats(t, metrics, protocolSOCKS5).DatagramTotal; got != 1 {
		t.Fatalf("association total = %d, want 1", got)
	}
}
