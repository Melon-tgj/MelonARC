package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// sessionTestPeer starts a QUIC peer that reports when the connection ends and
// returns the address to dial with the roots its certificate needs.
func sessionTestPeer(t *testing.T) (addr string, roots *x509.CertPool, closed func() <-chan struct{}) {
	t.Helper()
	done := make(chan struct{})
	addr, roots = startTestQUIC(t, "h3", true, func(conn *quic.Conn) {
		<-conn.Context().Done()
		close(done)
	})
	return addr, roots, func() <-chan struct{} { return done }
}

// waitClosed reports whether the peer saw the connection end within d.
func waitClosed(closed <-chan struct{}, d time.Duration) bool {
	select {
	case <-closed:
		return true
	case <-time.After(d):
		return false
	}
}

// TestQUICSessionDisownReleasesAnIdleConnection checks the case a reload hits
// most often: nothing is in flight, so the socket goes away at once instead of
// waiting for the idle timeout.
func TestQUICSessionDisownReleasesAnIdleConnection(t *testing.T) {
	addr, roots, closed := sessionTestPeer(t)
	session := newTestQUICSession(t, addr, roots)

	conn, release, err := session.acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if conn == nil {
		t.Fatal("acquire returned no connection")
	}
	release()

	session.Disown()
	if !waitClosed(closed(), 5*time.Second) {
		t.Fatal("the peer still has the connection after Disown")
	}
}

// TestQUICSessionDisownKeepsAConnectionInFlight checks the promise Disown makes
// to a reload: a connection that is still carrying traffic is not cut.
func TestQUICSessionDisownKeepsAConnectionInFlight(t *testing.T) {
	addr, roots, closed := sessionTestPeer(t)
	session := newTestQUICSession(t, addr, roots)

	_, release, err := session.acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	session.Disown()
	if waitClosed(closed(), 300*time.Millisecond) {
		t.Fatal("Disown cut a connection that was still in use")
	}
	release()
	if !waitClosed(closed(), 5*time.Second) {
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
