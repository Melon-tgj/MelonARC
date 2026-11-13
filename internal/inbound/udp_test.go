package inbound

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// fakeDatagram is one datagram crossing the client socket.
type fakeDatagram struct {
	payload []byte
	addr    net.Addr
}

// fakeSocket is an in-memory datagramSocket: the test pushes what the client
// sent and reads what the association writes back. The association itself is
// unchanged, which is the point: the datagram path can be exercised without a
// real socket and without depending on what the sandbox allows.
type fakeSocket struct {
	in     chan fakeDatagram
	out    chan fakeDatagram
	closed chan struct{}
	once   sync.Once
	addr   *net.UDPAddr
}

// newFakeSocket returns a socket that reports addr as its own.
func newFakeSocket(addr *net.UDPAddr) *fakeSocket {
	return &fakeSocket{
		in:     make(chan fakeDatagram, 64),
		out:    make(chan fakeDatagram, 64),
		closed: make(chan struct{}),
		addr:   addr,
	}
}

// ReadFrom implements datagramSocket.
func (s *fakeSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case d := <-s.in:
		return copy(p, d.payload), d.addr, nil
	case <-s.closed:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo implements datagramSocket.
func (s *fakeSocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case s.out <- fakeDatagram{payload: append([]byte(nil), p...), addr: addr}:
		return len(p), nil
	case <-s.closed:
		return 0, net.ErrClosed
	}
}

// Close implements datagramSocket.
func (s *fakeSocket) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

// receive takes one value or fails the test after the deadline.
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testDeadline):
		t.Fatal("timed out waiting for the association")
	}
	var zero T
	return zero
}

// clientAddr is the endpoint the fake client sends from.
func clientAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001}
}

// startAssociation wires the datagram path with a scripted outbound and returns
// the association, its socket and the pipe of the single destination.
func startAssociation(t *testing.T, rules ...string) (*association, *fakeSocket, *packetPipe) {
	t.Helper()
	dest := outbound.Target{Host: "203.0.113.9", Port: 53}
	pipe := newPacketPipe(dest)
	dialer := &fakeDialer{packetFn: func(string) (outbound.PacketConn, error) { return pipe, nil }}
	env := newTestEnv(t, envOptions{
		rules:  rules,
		leaves: map[string]outbound.Dialer{"fake": dialer},
	})
	socket := newFakeSocket(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000})
	assoc := newAssociation(associationOptions{
		ctx:     t.Context(),
		handler: env.handler,
		logger:  testLogger(),
		socket:  socket,
	})
	t.Cleanup(func() { _ = assoc.Close() })
	return assoc, socket, pipe
}

// TestAssociationRelaysDatagram walks one datagram through the association:
// framing in, the routed dial, the payload out, the answer back, framing out
// with the source address the client matches on.
func TestAssociationRelaysDatagram(t *testing.T) {
	assoc, socket, pipe := startAssociation(t, "FINAL,fake")
	dest := outbound.Target{Host: "203.0.113.9", Port: 53}
	client := clientAddr()

	socket.in <- fakeDatagram{
		payload: outbound.AppendUDPDatagram(nil, dest, []byte("query")),
		addr:    client,
	}
	if got := receive(t, pipe.written); !bytes.Equal(got, []byte("query")) {
		t.Fatalf("destination received %q, want the payload", got)
	}

	pipe.replies <- []byte("answer")
	reply := receive(t, socket.out)
	if reply.addr.String() != client.String() {
		t.Fatalf("reply went to %s, want the client %s", reply.addr, client)
	}
	payload, from, frag, err := outbound.DecodeUDPDatagram(reply.payload)
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if frag != 0 {
		t.Fatalf("reply carries fragment %d", frag)
	}
	if !bytes.Equal(payload, []byte("answer")) {
		t.Fatalf("reply payload = %q", payload)
	}
	if from.String() != dest.String() {
		t.Fatalf("reply source = %s, want the destination %s", from, dest)
	}

	assoc.mu.Lock()
	entries := len(assoc.entries)
	assoc.mu.Unlock()
	if entries != 1 {
		t.Fatalf("open destinations = %d, want one", entries)
	}
}

// TestAssociationIgnoresOtherClients checks that an association serves one
// endpoint: a datagram from anywhere else must not be relayed.
func TestAssociationIgnoresOtherClients(t *testing.T) {
	_, socket, pipe := startAssociation(t, "FINAL,fake")
	dest := outbound.Target{Host: "203.0.113.9", Port: 53}

	socket.in <- fakeDatagram{
		payload: outbound.AppendUDPDatagram(nil, dest, []byte("first")),
		addr:    clientAddr(),
	}
	if got := receive(t, pipe.written); !bytes.Equal(got, []byte("first")) {
		t.Fatalf("destination received %q", got)
	}

	socket.in <- fakeDatagram{
		payload: outbound.AppendUDPDatagram(nil, dest, []byte("intruder")),
		addr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40002},
	}
	select {
	case got := <-pipe.written:
		t.Fatalf("a datagram from another endpoint was relayed as %q", got)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestAssociationDropsUnusableDatagrams checks that a fragmented or malformed
// datagram is dropped and that a client which only sends those is cut off
// instead of being served forever.
func TestAssociationDropsUnusableDatagrams(t *testing.T) {
	assoc, socket, pipe := startAssociation(t, "FINAL,fake")
	dest := outbound.Target{Host: "203.0.113.9", Port: 53}

	// A fragmented datagram: the header is well formed but the payload cannot
	// be reassembled, so it must not be delivered.
	fragmented := outbound.AppendUDPDatagram(nil, dest, []byte("fragment"))
	fragmented[2] = 0x01
	socket.in <- fakeDatagram{payload: fragmented, addr: clientAddr()}
	// A datagram that is not even a header.
	socket.in <- fakeDatagram{payload: []byte{0x05}, addr: clientAddr()}
	select {
	case got := <-pipe.written:
		t.Fatalf("an unusable datagram was relayed as %q", got)
	case <-time.After(50 * time.Millisecond):
	}

	for i := 0; i < maxSkippedDatagrams; i++ {
		socket.in <- fakeDatagram{payload: []byte{0x05}, addr: clientAddr()}
	}
	select {
	case <-socket.closed:
	case <-time.After(testDeadline):
		t.Fatal("the association kept reading unusable datagrams")
	}
	assoc.mu.Lock()
	closed := assoc.closed
	assoc.mu.Unlock()
	if !closed {
		t.Fatal("the association did not mark itself closed")
	}
}

// TestAssociationEvictsIdleDestinations checks the bound on open destination
// sockets: the one idle longest gives way.
func TestAssociationEvictsIdleDestinations(t *testing.T) {
	// The association dials on its own goroutine, so the pipes are handed back
	// through a channel rather than a slice the test would have to lock.
	pipes := make(chan *packetPipe, maxDatagramDestinations+1)
	dialer := &fakeDialer{packetFn: func(address string) (outbound.PacketConn, error) {
		target, err := outbound.ParseTarget(address)
		if err != nil {
			t.Fatalf("parse %q: %v", address, err)
		}
		pipe := newPacketPipe(target)
		pipes <- pipe
		return pipe, nil
	}}
	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,fake"},
		leaves: map[string]outbound.Dialer{"fake": dialer},
	})
	socket := newFakeSocket(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000})
	assoc := newAssociation(associationOptions{
		ctx:     t.Context(),
		handler: env.handler,
		logger:  testLogger(),
		socket:  socket,
	})
	t.Cleanup(func() { _ = assoc.Close() })

	var first *packetPipe
	for i := 0; i < maxDatagramDestinations+1; i++ {
		dest := outbound.Target{Host: "198.51.100.1", Port: uint16(1000 + i)}
		socket.in <- fakeDatagram{
			payload: outbound.AppendUDPDatagram(nil, dest, []byte("payload")),
			addr:    clientAddr(),
		}
		pipe := receive(t, pipes)
		if first == nil {
			first = pipe
		}
		receive(t, pipe.written)
	}

	assoc.mu.Lock()
	entries := len(assoc.entries)
	assoc.mu.Unlock()
	if entries != maxDatagramDestinations {
		t.Fatalf("open destinations = %d, want the cap of %d", entries, maxDatagramDestinations)
	}
	// The very first destination is the one that was idle longest.
	select {
	case <-first.closed:
	default:
		t.Fatal("the idle destination was not closed when the cap was reached")
	}
}

// TestAssociationCloseReleasesDestinations checks that closing the association
// closes every destination socket it opened.
func TestAssociationCloseReleasesDestinations(t *testing.T) {
	assoc, socket, pipe := startAssociation(t, "FINAL,fake")
	dest := outbound.Target{Host: "203.0.113.9", Port: 53}
	socket.in <- fakeDatagram{
		payload: outbound.AppendUDPDatagram(nil, dest, []byte("query")),
		addr:    clientAddr(),
	}
	receive(t, pipe.written)

	if err := assoc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-pipe.closed:
	case <-time.After(testDeadline):
		t.Fatal("the destination socket outlived the association")
	}
	if err := assoc.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
