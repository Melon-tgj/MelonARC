package outbound

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// TestDirectSharedUDPCarriesSeveralDestinations checks that one association
// object serves two different destinations and reports which one answered.
func TestDirectSharedUDPCarriesSeveralDestinations(t *testing.T) {
	if !datagramSendAllowed(t) {
		t.Skip("this environment denies sendto to an unconnected peer")
	}
	first := startUDPEcho(t)
	second := startUDPEcho(t)
	targets := make([]Target, 0, 2)
	for _, address := range []string{first, second} {
		target, err := ParseTarget(address)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", address, err)
		}
		targets = append(targets, target)
	}

	relay, err := NewDirect().DialSharedUDP(context.Background())
	if err != nil {
		t.Fatalf("DialSharedUDP: %v", err)
	}
	defer relay.Close()
	for i, target := range targets {
		if _, err := relay.WriteTo([]byte(strconv.Itoa(i)), target); err != nil {
			t.Fatalf("WriteTo %s: %v", target, err)
		}
	}
	seen := map[string]bool{}
	for i := 0; i < len(targets); i++ {
		if err := relay.(*directRelay).waitForReply(t, 2*time.Second); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, from, err := relay.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		seen[from.String()+":"+string(buf[:n])] = true
	}
	if len(seen) != 2 {
		t.Fatalf("replies = %v, want one per destination", seen)
	}
}

// TestDirectSharedUDPResolvesNamesThroughLookup proves the injected lookup (in
// the daemon, the DNS resolver's Lookup) is what turns a name destination into
// an address for a shared association.
func TestDirectSharedUDPResolvesNamesThroughLookup(t *testing.T) {
	if !datagramSendAllowed(t) {
		t.Skip("this environment denies sendto to an unconnected peer")
	}
	echo := startUDPEcho(t)
	host, portText, err := net.SplitHostPort(echo)
	if err != nil {
		t.Fatalf("split %q: %v", echo, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	var asked []string
	direct := &Direct{Lookup: func(_ context.Context, name string) ([]net.IP, error) {
		asked = append(asked, name)
		return []net.IP{net.ParseIP(host)}, nil
	}}
	relay, err := direct.DialSharedUDP(context.Background())
	if err != nil {
		t.Fatalf("DialSharedUDP: %v", err)
	}
	defer relay.Close()

	dest := Target{Host: "local.test", Port: uint16(port)}
	if _, err := relay.WriteTo([]byte("named"), dest); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if len(asked) != 1 || asked[0] != "local.test" {
		t.Fatalf("lookup calls = %v, want one for local.test", asked)
	}
	if err := relay.(*directRelay).waitForReply(t, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, from, err := relay.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "named" || from.String() != dest.String() {
		t.Fatalf("reply = %q from %s, want named from %s", buf[:n], from, dest)
	}
}

// waitForReply waits until the relay has queued a reply. It keeps the assertions
// above from racing the echo server's goroutine.
func (r *directRelay) waitForReply(t *testing.T, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if len(r.incoming) > 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		time.Sleep(5 * time.Millisecond)
	}
}
