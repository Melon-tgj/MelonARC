package inbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
	"github.com/melon-tgj/melonarc/internal/policy"
	"github.com/melon-tgj/melonarc/internal/rules"
)

// testDeadline bounds every test connection so a broken expectation fails the
// test instead of hanging it.
const testDeadline = 10 * time.Second

// newTestProgram compiles rule lines the way the daemon compiles a
// configuration.
func newTestProgram(t *testing.T, lines ...string) *rules.Program {
	t.Helper()
	parsed := make([]*rules.Rule, 0, len(lines))
	for i, line := range lines {
		rule, err := rules.ParseRule(line)
		if err != nil {
			t.Fatalf("rule %q: %v", line, err)
		}
		rule.Source = "test"
		rule.Line = i + 1
		parsed = append(parsed, rule)
	}
	program, err := rules.Compile(rules.Options{Rules: parsed})
	if err != nil {
		t.Fatalf("compile %v: %v", lines, err)
	}
	return program
}

// testEnv is a routing pipeline wired the way the daemon wires it: a compiled
// program, a policy registry and a set of dialers.
type testEnv struct {
	handler  *Handler
	router   *PolicyRouter
	registry *policy.Registry
	dialers  *outbound.Set
	program  *rules.Program
}

// envOptions describes the pieces of a testEnv.
type envOptions struct {
	// rules are the rule lines of the program.
	rules []string
	// leaves maps a name to the dialer registered under it.
	leaves map[string]outbound.Dialer
	// groups are added after the leaves.
	groups []policy.Group
	// resolver answers name destinations. Nil leaves local resolution off, as
	// a daemon without a DNS layer would.
	resolver Resolver
	// metrics records the requests the pipeline could not carry. Nil keeps no
	// record.
	metrics *Metrics
}

// newTestEnv builds a pipeline from the options and fails the test when any
// part of the wiring does.
func newTestEnv(t *testing.T, opts envOptions) *testEnv {
	t.Helper()
	dialers := outbound.NewSet()
	registry := policy.NewRegistry()

	names := make([]string, 0, len(opts.leaves))
	for name := range opts.leaves {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := dialers.Add(name, opts.leaves[name]); err != nil {
			t.Fatalf("add dialer %q: %v", name, err)
		}
		if err := registry.AddLeaf(name); err != nil {
			t.Fatalf("add leaf %q: %v", name, err)
		}
	}
	for _, group := range opts.groups {
		if err := registry.AddGroup(group); err != nil {
			t.Fatalf("add group %q: %v", group.Name(), err)
		}
	}
	router, err := NewPolicyRouter(registry, dialers)
	if err != nil {
		t.Fatalf("NewPolicyRouter: %v", err)
	}
	program := newTestProgram(t, opts.rules...)
	handler, err := NewHandler(HandlerOptions{
		Matcher:  program,
		Router:   router,
		Resolver: opts.resolver,
		Metrics:  opts.metrics,
		Logger:   testLogger(),
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return &testEnv{handler: handler, router: router, registry: registry, dialers: dialers, program: program}
}

// failingProber is a prober that never reports a healthy member.
func failingProber() policy.Prober {
	return policy.ProbeFunc(func(context.Context, string) (time.Duration, error) {
		return 0, errors.New("probing is disabled in this test")
	})
}

// testLogger discards the pipeline log lines.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeDialer is an outbound dialer whose results a test scripts. Every address
// it was asked for is recorded, which is how a test proves which path a request
// took.
type fakeDialer struct {
	mu       sync.Mutex
	streams  []string
	packets  []string
	streamFn func(address string) (net.Conn, error)
	packetFn func(address string) (outbound.PacketConn, error)
}

// DialContext implements outbound.Dialer.
func (d *fakeDialer) DialContext(_ context.Context, address string) (net.Conn, error) {
	d.mu.Lock()
	d.streams = append(d.streams, address)
	fn := d.streamFn
	d.mu.Unlock()
	if fn == nil {
		return nil, fmt.Errorf("fakeDialer: no stream scripted for %s", address)
	}
	return fn(address)
}

// DialPacket implements outbound.Dialer.
func (d *fakeDialer) DialPacket(_ context.Context, address string) (outbound.PacketConn, error) {
	d.mu.Lock()
	d.packets = append(d.packets, address)
	fn := d.packetFn
	d.mu.Unlock()
	if fn == nil {
		return nil, fmt.Errorf("fakeDialer: no packet scripted for %s", address)
	}
	return fn(address)
}

// Streams lists the addresses dialed as streams.
func (d *fakeDialer) Streams() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.streams...)
}

// Packets lists the addresses dialed as datagrams.
func (d *fakeDialer) Packets() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.packets...)
}

// packetPipe is an in-memory outbound.PacketConn: the test reads what was
// written and feeds the replies back.
type packetPipe struct {
	dest    outbound.Target
	written chan []byte
	replies chan []byte
	closed  chan struct{}
	once    sync.Once
}

// newPacketPipe returns a pipe for one destination.
func newPacketPipe(dest outbound.Target) *packetPipe {
	return &packetPipe{
		dest:    dest,
		written: make(chan []byte, 16),
		replies: make(chan []byte, 16),
		closed:  make(chan struct{}),
	}
}

// Read implements outbound.PacketConn.
func (p *packetPipe) Read(b []byte) (int, error) {
	select {
	case reply := <-p.replies:
		return copy(b, reply), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

// Write implements outbound.PacketConn.
func (p *packetPipe) Write(b []byte) (int, error) {
	select {
	case p.written <- append([]byte(nil), b...):
		return len(b), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

// Close implements outbound.PacketConn.
func (p *packetPipe) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

// LocalAddr implements net.Conn.
func (p *packetPipe) LocalAddr() net.Addr { return outbound.Target{Host: "127.0.0.1", Port: 40000} }

// RemoteAddr implements net.Conn.
func (p *packetPipe) RemoteAddr() net.Addr { return p.dest }

// SetDeadline implements net.Conn.
func (p *packetPipe) SetDeadline(time.Time) error { return nil }

// SetReadDeadline implements net.Conn.
func (p *packetPipe) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline implements net.Conn.
func (p *packetPipe) SetWriteDeadline(time.Time) error { return nil }

// startTCPServer serves every accepted connection with handle and returns the
// address it listens on.
func startTCPServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(testDeadline))
				handle(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		wg.Wait()
	})
	return listener.Addr().String()
}

// startEcho serves a TCP echo endpoint.
func startEcho(t *testing.T) string {
	t.Helper()
	return startTCPServer(t, func(conn net.Conn) {
		_, _ = io.Copy(conn, conn)
	})
}

// startHTTPOrigin serves body at every path over plain HTTP.
func startHTTPOrigin(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// hostPort returns the host:port of a server URL.
func hostPort(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		t.Fatalf("%q is not a URL: %v", rawURL, err)
	}
	return u.Host
}

// startHTTPService starts an HTTP inbound wired to env.
func startHTTPService(t *testing.T, env *testEnv, opts ...func(*HTTPOptions)) *Service {
	t.Helper()
	options := HTTPOptions{Addr: "127.0.0.1:0", Handler: env.handler, Logger: testLogger()}
	for _, apply := range opts {
		apply(&options)
	}
	srv, err := NewHTTP(options)
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	t.Cleanup(func() { closeQuietly(t, srv) })
	return srv
}

// startSOCKS5Service starts a SOCKS5 inbound wired to env.
func startSOCKS5Service(t *testing.T, env *testEnv, opts ...func(*SOCKS5Options)) *Service {
	t.Helper()
	options := SOCKS5Options{Addr: "127.0.0.1:0", Handler: env.handler, Logger: testLogger()}
	for _, apply := range opts {
		apply(&options)
	}
	srv, err := NewSOCKS5(options)
	if err != nil {
		t.Fatalf("NewSOCKS5: %v", err)
	}
	t.Cleanup(func() { closeQuietly(t, srv) })
	return srv
}

// closeQuietly stops a service with a bounded wait.
func closeQuietly(t *testing.T, srv *Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	if err := srv.Close(ctx); err != nil {
		t.Errorf("close %s: %v", srv.Protocol(), err)
	}
}

// datagramSendAllowed reports whether this environment lets a datagram socket
// send to an address it is not connected to, which every UDP relay needs. Some
// sandboxes deny sendto outright; there the datagram round trip tests skip
// instead of failing for a reason that has nothing to do with the code.
func datagramSendAllowed(t *testing.T) bool {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Logf("skipping datagram test: cannot bind a udp socket: %v", err)
		return false
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Logf("skipping datagram test: cannot dial a udp socket: %v", err)
		return false
	}
	defer client.Close()
	from := client.LocalAddr().(*net.UDPAddr)
	if _, err := server.WriteToUDP([]byte("probe"), from); err != nil {
		t.Logf("skipping datagram test: this environment denies sendto to an unconnected peer: %v", err)
		return false
	}
	return true
}
