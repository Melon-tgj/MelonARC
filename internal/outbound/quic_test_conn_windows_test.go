//go:build windows

package outbound

import (
	"net"
	"testing"
)

// On Windows the default QUIC dial and the listener below use ordinary
// datagram sockets: nothing here has to work around a sandbox.

func testQUICPacketConn(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	return pc
}
