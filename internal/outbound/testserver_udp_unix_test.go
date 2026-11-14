//go:build !windows

package outbound

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// connectUDPPeer connects a bound datagram socket to the first peer that
// writes to it, so replies use send() on a connected socket rather than
// sendto() on an unconnected one. Some sandboxes deny the latter; a pair of
// mutually connected sockets still carries real kernel datagrams.
//
// This is a test-only helper. It is deliberately in a non-Windows file:
// Windows datagram round trips use the companion stub that skips them.
func connectUDPPeer(pc *net.UDPConn, from *net.UDPAddr) error {
	ip := from.IP.To4()
	if ip == nil {
		return errors.New("peer is not ipv4")
	}
	raw, err := pc.SyscallConn()
	if err != nil {
		return err
	}
	var connErr error
	if err := raw.Control(func(fd uintptr) {
		addr := &syscall.SockaddrInet4{Port: from.Port}
		copy(addr.Addr[:], ip)
		connErr = syscall.Connect(int(fd), addr)
	}); err != nil {
		return err
	}
	return connErr
}

// startConnectedUDPEcho binds a datagram socket and answers each incoming
// packet through handle. The socket is connected to the first peer, which is
// what makes a reply possible in a sandbox that blocks unconnected sendto.
func startConnectedUDPEcho(t *testing.T, handle func([]byte) []byte) string {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	done := make(chan struct{})
	var connectErr error
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		connected := false
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !connected {
				connectErr = connectUDPPeer(pc, from)
				connected = true
			}
			if connectErr != nil {
				return
			}
			reply := handle(append([]byte(nil), buf[:n]...))
			if reply == nil {
				continue
			}
			if _, err := pc.Write(reply); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = pc.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		if connectErr != nil {
			t.Logf("datagram echo unavailable in this environment: %v", connectErr)
		}
	})
	return pc.LocalAddr().String()
}
