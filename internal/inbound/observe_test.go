package inbound

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// recordingObserver collects what the pipeline reports.
type recordingObserver struct {
	mu       sync.Mutex
	streams  []ConnectionRecord
	failures []Failure
}

func (o *recordingObserver) Connection(rec ConnectionRecord) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.streams = append(o.streams, rec)
}

func (o *recordingObserver) Failure(f Failure) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.failures = append(o.failures, f)
}

// connections returns what was reported so far.
func (o *recordingObserver) connections() []ConnectionRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]ConnectionRecord(nil), o.streams...)
}

// errorList returns the failures reported so far.
func (o *recordingObserver) errorList() []Failure {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]Failure(nil), o.failures...)
}

// halfCloseConn records CloseWrite and Close separately, which is what a
// connection that supports a half close looks like to the relay.
type halfCloseConn struct {
	net.Conn

	mu           sync.Mutex
	closeWriteIn int
	closed       bool
}

func (c *halfCloseConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeWriteIn++
	return nil
}

func (c *halfCloseConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *halfCloseConn) state() (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeWriteIn, c.closed
}

// TestStreamIsReportedWhenItEnds checks the record a carried connection produces:
// the bytes in both directions, the rule and policy that chose it, and the
// listener it came in on.
func TestStreamIsReportedWhenItEnds(t *testing.T) {
	observer := &recordingObserver{}
	metrics := NewMetrics(0, observer)

	// The dialer hands back one end of a pipe; the test plays the peer on the
	// other end. Writing through the returned connection therefore arrives at
	// server, and what server writes is read back through it.
	upstream, server := net.Pipe()
	defer server.Close()

	wrapped := &halfCloseConn{Conn: upstream}
	leaf := &fakeDialer{streamFn: func(string) (net.Conn, error) {
		return wrapped, nil
	}}
	env := newTestEnv(t, envOptions{
		rules:   []string{"DOMAIN-SUFFIX,example.com,alpha", "FINAL,DIRECT"},
		leaves:  map[string]outbound.Dialer{"alpha": leaf, "DIRECT": leaf},
		metrics: metrics,
	})

	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	conn, sel, err := env.handler.Stream(ctx, Request{
		Target:   outbound.Target{Host: "example.com", Port: 443},
		Network:  networkTCP,
		Protocol: protocolHTTP,
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if sel.Target != "alpha" {
		t.Fatalf("selection = %+v, want alpha", sel)
	}

	// The upstream side: consume the request and answer it.
	go func() {
		buf := make([]byte, 64)
		n, _ := server.Read(buf)
		_, _ = server.Write([]byte("answer:" + string(buf[:n])))
	}()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	answer := make([]byte, 64)
	n, err := conn.Read(answer)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(answer[:n]) != "answer:ping" {
		t.Fatalf("read %q", answer[:n])
	}
	// Nothing is reported while the connection is open.
	if got := observer.connections(); len(got) != 0 {
		t.Fatalf("%d connections were reported before the connection ended", len(got))
	}

	// CloseWrite must reach the connection underneath instead of tearing it
	// down: the relay depends on that to half close a tunnel.
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("the connection returned by Stream does not support CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if written, closed := wrapped.state(); written != 1 || closed {
		t.Fatalf("after CloseWrite the underlying connection saw closeWrite=%d closed=%v", written, closed)
	}
	if got := observer.connections(); len(got) != 0 {
		t.Fatalf("a half close reported the connection: %+v", got)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	records := observer.connections()
	if len(records) != 1 {
		t.Fatalf("%d records after close, want 1", len(records))
	}
	rec := records[0]
	if rec.Protocol != protocolHTTP || rec.Network != networkTCP {
		t.Errorf("record = %+v, want the http listener over tcp", rec)
	}
	if rec.Target.Host != "example.com" || rec.Target.Port != 443 {
		t.Errorf("record target = %v", rec.Target)
	}
	if rec.Rule != "DOMAIN-SUFFIX,example.com,alpha" || rec.Policy != "alpha" || rec.Outbound != "alpha" {
		t.Errorf("record = %+v, want the rule and the policy that carried it", rec)
	}
	if rec.Up != 4 || rec.Down != 11 {
		t.Errorf("record carried up=%d down=%d, want 4 and 11", rec.Up, rec.Down)
	}
	if rec.Duration <= 0 {
		t.Errorf("record duration = %v", rec.Duration)
	}
	if up, down := metrics.Traffic(); up != 4 || down != 11 {
		t.Errorf("traffic totals = %d/%d, want 4/11", up, down)
	}

	// A second close must not report the connection twice.
	_ = conn.Close()
	if got := observer.connections(); len(got) != 1 {
		t.Fatalf("%d records after a second close", len(got))
	}
}

// TestPacketIsReportedWhenItEnds covers the datagram path: an association is a
// connection with a lifetime too, and its bytes belong in the same history.
func TestPacketIsReportedWhenItEnds(t *testing.T) {
	observer := &recordingObserver{}
	metrics := NewMetrics(0, observer)
	pipe := newPacketPipe(outbound.Target{Host: "198.51.100.9", Port: 53})
	leaf := &fakeDialer{packetFn: func(string) (outbound.PacketConn, error) { return pipe, nil }}
	env := newTestEnv(t, envOptions{
		rules:   []string{"FINAL,DIRECT"},
		leaves:  map[string]outbound.Dialer{"DIRECT": leaf},
		metrics: metrics,
	})

	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	conn, _, err := env.handler.Packet(ctx, Request{
		Target:   outbound.Target{Host: "198.51.100.9", Port: 53},
		Network:  networkUDP,
		Protocol: protocolSOCKS5,
	})
	if err != nil {
		t.Fatalf("Packet: %v", err)
	}
	if _, err := conn.Write([]byte("query")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := <-pipe.written; string(got) != "query" {
		t.Fatalf("the association received %q", got)
	}
	go func() { pipe.replies <- []byte("reply!") }()
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "reply!" {
		t.Fatalf("read %q, %v", buf[:n], err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	records := observer.connections()
	if len(records) != 1 {
		t.Fatalf("%d records, want 1", len(records))
	}
	rec := records[0]
	if rec.Network != networkUDP || rec.Protocol != protocolSOCKS5 {
		t.Errorf("record = %+v, want udp from the socks5 listener", rec)
	}
	if rec.Up != 5 || rec.Down != 6 {
		t.Errorf("record carried up=%d down=%d, want 5 and 6", rec.Up, rec.Down)
	}
}

// TestFailureIsReportedToTheObserver checks that the persistent history sees the
// same failures the in-memory ring holds, with the category and nothing else.
func TestFailureIsReportedToTheObserver(t *testing.T) {
	observer := &recordingObserver{}
	metrics := NewMetrics(0, observer)
	leaf := &fakeDialer{streamFn: func(string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}}
	env := newTestEnv(t, envOptions{
		rules:   []string{"FINAL,alpha"},
		leaves:  map[string]outbound.Dialer{"alpha": leaf},
		metrics: metrics,
	})

	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	if _, _, err := env.handler.Stream(ctx, Request{
		Target:   outbound.Target{Host: "example.com", Port: 443},
		Network:  networkTCP,
		Protocol: protocolHTTP,
	}); err == nil {
		t.Fatal("Stream succeeded although the dial failed")
	}

	failures := observer.errorList()
	if len(failures) != 1 {
		t.Fatalf("%d failures reported, want 1", len(failures))
	}
	if failures[0].Category == "" || failures[0].Stage != StageDial {
		t.Errorf("failure = %+v, want a dial failure with a category", failures[0])
	}
	if failures[0].Policy != "alpha" || failures[0].Target != "example.com:443" {
		t.Errorf("failure = %+v", failures[0])
	}
	if records := observer.connections(); len(records) != 0 {
		t.Errorf("a failed dial was reported as a carried connection: %+v", records)
	}
	if up, down := metrics.Traffic(); up != 0 || down != 0 {
		t.Errorf("a failed dial moved the traffic totals: %d/%d", up, down)
	}
}

// TestMetricsWithoutAnObserverStillCounts keeps the optional wiring honest: a
// daemon without a history still reports how much it moved, and recording
// through a nil observer does not panic.
func TestMetricsWithoutAnObserverStillCounts(t *testing.T) {
	metrics := NewMetrics(0)
	metrics.observeConnection(ConnectionRecord{Up: 10, Down: 25})
	if up, down := metrics.Traffic(); up != 10 || down != 25 {
		t.Fatalf("traffic = %d/%d, want 10/25", up, down)
	}
	// A nil Metrics and a zero one are both valid receivers.
	var nilMetrics *Metrics
	nilMetrics.observeConnection(ConnectionRecord{Up: 1})
	if up, down := nilMetrics.Traffic(); up != 0 || down != 0 {
		t.Errorf("a nil Metrics reported %d/%d", up, down)
	}
	var zero Metrics
	zero.observeConnection(ConnectionRecord{Up: 2, Down: 3})
	if up, down := zero.Traffic(); up != 2 || down != 3 {
		t.Errorf("the zero Metrics reported %d/%d, want 2/3", up, down)
	}
}
