package inbound

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startReplyAfterEOF serves a backend that reads its peer to the end before
// answering. Such a backend only ever answers if the client's half close
// arrived as an end of stream and the reply direction stayed open.
func startReplyAfterEOF(t *testing.T) string {
	t.Helper()
	return startTCPServer(t, func(conn net.Conn) {
		data, _ := io.ReadAll(conn)
		_, _ = fmt.Fprintf(conn, "read %d bytes", len(data))
	})
}

// testHalfClose writes a payload through one proxied stream, closes only the
// write direction and expects the answer that follows.
func testHalfClose(t *testing.T, dial func(backend string) (net.Conn, io.Reader)) {
	t.Helper()
	backend := startReplyAfterEOF(t)
	conn, reader := dial(backend)

	payload := bytes.Repeat([]byte("x"), 4096)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	halfCloser, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("the client connection is %T and cannot half close", conn)
	}
	if err := halfCloser.CloseWrite(); err != nil {
		t.Fatalf("half close: %v", err)
	}
	reply, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	want := fmt.Sprintf("read %d bytes", len(payload))
	if got := strings.TrimSpace(string(reply)); got != want {
		t.Fatalf("reply = %q, want %q: the half close did not propagate", got, want)
	}
}

// tcpPair returns the two ends of one loopback TCP connection, which is the
// shortest way to have two connections that support a half close.
func tcpPair(t *testing.T) (near, far net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	far, err = net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	near, ok := <-accepted
	if !ok {
		far.Close()
		t.Fatal("the pair was not accepted")
	}
	t.Cleanup(func() {
		_ = near.Close()
		_ = far.Close()
	})
	return near, far
}

// TestRelayHalfClose isolates the relay from any protocol: one direction ends,
// the other must keep carrying bytes.
func TestRelayHalfClose(t *testing.T) {
	backend := startReplyAfterEOF(t)
	upstream, err := net.Dial("tcp", backend)
	if err != nil {
		t.Fatalf("dial backend: %v", err)
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(testDeadline))

	near, far := tcpPair(t)
	relayed := make(chan struct{})
	go func() {
		relay(near, upstream)
		close(relayed)
	}()

	payload := []byte("half close")
	if _, err := far.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := far.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("close the write direction: %v", err)
	}
	reply, err := io.ReadAll(far)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if want := fmt.Sprintf("read %d bytes", len(payload)); string(reply) != want {
		t.Fatalf("reply = %q, want %q", reply, want)
	}
	select {
	case <-relayed:
	case <-time.After(testDeadline):
		t.Fatal("the relay did not finish after both directions ended")
	}
}
