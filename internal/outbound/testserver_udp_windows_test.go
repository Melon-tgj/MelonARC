//go:build windows

package outbound

import (
	"errors"
	"net"
	"testing"
)

func connectUDPPeer(*net.UDPConn, *net.UDPAddr) error {
	return errors.New("connected udp test peer is not available on windows")
}

func startConnectedUDPEcho(t *testing.T, _ func([]byte) []byte) string {
	t.Helper()
	t.Skip("datagram echo test needs a connected udp peer, which is unix-only")
	return ""
}
