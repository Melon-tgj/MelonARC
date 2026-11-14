package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// sessionTestPeer starts a QUIC peer that reports when it has taken the
// connection and when the connection ends, plus the address to dial with the
// roots its certificate needs.
//
// The accepted signal is what makes these tests deterministic. A client can
// finish its handshake and close before the server's Accept has returned, and a
// close that arrives first is simply dropped: there is no connection object yet
// to end. Waiting for the peer to hold the connection turns "the peer never saw
// the close" from a race into an impossible state.
func sessionTestPeer(t *testing.T) (addr string, roots *x509.CertPool, accepted, closed func() <-chan struct{}) {
	t.Helper()
	acceptedCh := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	addr, roots = startTestQUIC(t, "h3", true, func(conn *quic.Conn) {
		once.Do(func() { close(acceptedCh) })
		<-conn.Context().Done()
		close(done)
	})
	return addr, roots,
		func() <-chan struct{} { return acceptedCh },
		func() <-chan struct{} { return done }
}

// waitSignal reports whether ch was signalled within d.
func waitSignal(ch <-chan struct{}, d time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

// waitClosed reports whether the peer saw the connection end within d.
func waitClosed(closed <-chan struct{}, d time.Duration) bool {
	return waitSignal(closed, d)
}

// closeDeadline bounds how long the peer may take to report a closed
// connection. It is deliberately generous: the assertion is about the
// connection being released at all, and race-instrumented builds on a loaded
// machine stretch scheduling far beyond what a quiet run shows.
const closeDeadline = 20 * time.Second

// TestQUICSessionDisownReleasesAnIdleConnection checks the case a reload hits
// most often: nothing is in flight, so the socket goes away at once instead of
// waiting for the idle timeout.
func TestQUICSessionDisownReleasesAnIdleConnection(t *testing.T) {
	addr, roots, accepted, closed := sessionTestPeer(t)
	session := newTestQUICSession(t, addr, roots)

	conn, release, err := session.acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if conn == nil {
		t.Fatal("acquire returned no connection")
	}
	release()
	if !waitSignal(accepted(), closeDeadline) {
		t.Fatal("the peer never took the connection")
	}

	session.Disown()
	if !waitClosed(closed(), closeDeadline) {
		t.Fatal("the peer still has the connection after Disown")
	}
}

// TestQUICSessionDisownKeepsAConnectionInFlight checks the promise Disown makes
// to a reload: a connection that is still carrying traffic is not cut.
func TestQUICSessionDisownKeepsAConnectionInFlight(t *testing.T) {
	addr, roots, accepted, closed := sessionTestPeer(t)
	session := newTestQUICSession(t, addr, roots)

	_, release, err := session.acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !waitSignal(accepted(), closeDeadline) {
		t.Fatal("the peer never took the connection")
	}
	session.Disown()
	if waitClosed(closed(), 300*time.Millisecond) {
		t.Fatal("Disown cut a connection that was still in use")
	}
	release()
	if !waitClosed(closed(), closeDeadline) {
		t.Fatal("the peer still has the connection after the last reference was released")
	}
}

// newTestQUICSession wraps one connection to addr in a session.
func newTestQUICSession(t *testing.T, addr string, roots *x509.CertPool) *quicSession {
	t.Helper()
	dial := func(ctx context.Context) (*quic.Conn, error) {
		return dialQUICAddr(ctx, addr,
			&tls.Config{RootCAs: roots, NextProtos: []string{"h3"}},
			&quic.Config{EnableDatagrams: true})
	}
	session := newQUICSession(dial, newDatagramMux(func([]byte) (uint32, bool) { return 0, false }), time.Minute)
	t.Cleanup(func() { _ = session.Close() })
	return session
}
