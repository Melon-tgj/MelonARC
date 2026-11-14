package outbound

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
)

// disownProbe is a dialer that records whether it was retired.
type disownProbe struct {
	disowned atomic.Bool
}

func (d *disownProbe) DialContext(context.Context, string) (net.Conn, error) {
	return nil, ErrUnsupported
}

func (d *disownProbe) DialPacket(context.Context, string) (PacketConn, error) {
	return nil, ErrUnsupported
}

func (d *disownProbe) Disown() { d.disowned.Store(true) }

// plainProbe is a dialer with nothing to release: Disown must skip it without
// panicking.
type plainProbe struct{}

func (plainProbe) DialContext(context.Context, string) (net.Conn, error) {
	return nil, ErrUnsupported
}

func (plainProbe) DialPacket(context.Context, string) (PacketConn, error) {
	return nil, ErrUnsupported
}

// TestSetDisownRetiresOnlyStatefulDialers checks the contract a reload relies
// on: the set walks its dialers and retires the ones that keep something
// between connections, leaving the rest alone.
func TestSetDisownRetiresOnlyStatefulDialers(t *testing.T) {
	set := NewSet()
	stateful := &disownProbe{}
	if err := set.Add("stateful", stateful); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := set.Add("plain", plainProbe{}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	set.Disown()
	if !stateful.disowned.Load() {
		t.Fatal("Disown did not reach a dialer that holds state")
	}
	// Calling it twice is harmless: a reload may retire a set that was already
	// retired through another path.
	set.Disown()
}
