package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingLookup is a LookupFunc that records what it was asked for.
type countingLookup struct {
	mu     sync.Mutex
	names  []string
	answer func(host string) ([]net.IP, error)
}

// lookup implements LookupFunc.
func (l *countingLookup) lookup(_ context.Context, host string) ([]net.IP, error) {
	l.mu.Lock()
	l.names = append(l.names, host)
	l.mu.Unlock()
	return l.answer(host)
}

// count returns how many lookups were made.
func (l *countingLookup) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.names)
}

// TestDirectResolvesThroughTheInjectedLookup checks that a name destination goes
// through the resolver the daemon injected, which is what makes the cache and the
// [Host] table apply to DIRECT traffic.
func TestDirectResolvesThroughTheInjectedLookup(t *testing.T) {
	echo := startTCPEcho(t)
	echoTarget, err := ParseTarget(echo)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	lookup := &countingLookup{answer: func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}}
	direct := &Direct{Timeout: testServerDeadline, Lookup: lookup.lookup}

	conn, err := direct.DialContext(context.Background(), net.JoinHostPort("pinned.test", strconv.Itoa(int(echoTarget.Port))))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q, want %q", buf, "hello")
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("lookups = %d, want 1", got)
	}
	if names := lookup.names; len(names) != 1 || names[0] != "pinned.test" {
		t.Fatalf("looked up %v, want pinned.test", names)
	}
}

// TestDirectTriesEveryAddress checks that a name whose first address does not
// answer still connects through the next one: a resolution result is a list, not
// a single guess.
func TestDirectTriesEveryAddress(t *testing.T) {
	echo := startTCPEcho(t)
	echoTarget, err := ParseTarget(echo)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	lookup := &countingLookup{answer: func(string) ([]net.IP, error) {
		// The echo endpoint listens on IPv4 only, so the first address cannot
		// answer and the dial has to move on to the second one.
		return []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")}, nil
	}}
	direct := &Direct{Timeout: 150 * time.Millisecond, Lookup: lookup.lookup}

	conn, err := direct.DialContext(context.Background(), net.JoinHostPort("multi.test", strconv.Itoa(int(echoTarget.Port))))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != echo {
		t.Fatalf("connected to %s, want %s", got, echo)
	}
}

// TestDirectReportsAFailedLookup checks that a name with no address fails with
// the lookup error and is never dialed.
func TestDirectReportsAFailedLookup(t *testing.T) {
	lookup := &countingLookup{answer: func(string) ([]net.IP, error) {
		return nil, errors.New("no such host")
	}}
	direct := &Direct{Timeout: testServerDeadline, Lookup: lookup.lookup}

	_, err := direct.DialContext(context.Background(), "missing.test:443")
	if err == nil {
		t.Fatal("DialContext succeeded, want a lookup failure")
	}
	if !strings.Contains(err.Error(), "no such host") {
		t.Fatalf("error = %v, want it to carry the lookup failure", err)
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("lookups = %d, want 1", got)
	}
}

// TestDirectPacketUsesTheInjectedLookup checks the datagram path, which has to
// resolve the same way the stream path does.
func TestDirectPacketUsesTheInjectedLookup(t *testing.T) {
	lookup := &countingLookup{answer: func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}}
	direct := &Direct{Timeout: testServerDeadline, Lookup: lookup.lookup}

	conn, err := direct.DialPacket(context.Background(), "pinned.test:5353")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != "127.0.0.1:5353" {
		t.Fatalf("remote address = %s, want 127.0.0.1:5353", got)
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("lookups = %d, want 1", got)
	}
}

// TestDirectLeavesLiteralsAlone checks that an address the client supplied is
// dialed directly, with no lookup at all.
func TestDirectLeavesLiteralsAlone(t *testing.T) {
	echo := startTCPEcho(t)
	lookup := &countingLookup{answer: func(string) ([]net.IP, error) {
		return nil, errors.New("the lookup must not run")
	}}
	direct := &Direct{Timeout: testServerDeadline, Lookup: lookup.lookup}

	conn, err := direct.DialContext(context.Background(), echo)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if got := lookup.count(); got != 0 {
		t.Fatalf("lookups = %d, want 0", got)
	}
}

// TestDirectWithoutLookupStillDials checks that the zero value keeps the old
// behaviour: net.Dialer resolves the name, there is no injected resolver.
func TestDirectWithoutLookupStillDials(t *testing.T) {
	echo := startTCPEcho(t)
	direct := &Direct{Timeout: testServerDeadline}
	if _, err := direct.DialContext(context.Background(), echo); err != nil {
		t.Fatalf("DialContext: %v", err)
	}
}
