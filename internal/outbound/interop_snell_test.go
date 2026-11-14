//go:build !windows

package outbound

import (
	"fmt"
	"testing"
)

// Snell v4 and v5 differ in two places the client has to get right: v5 uses a
// different connect command and pads the first frame into an initial segment.
// The reference server is configured for one version at a time, so each version
// gets its own server instance rather than one server answering both.
func TestInteropSnell(t *testing.T) {
	server := interopBinary(t, "snell")

	for _, version := range []string{"4", "5"} {
		t.Run("v"+version, func(t *testing.T) {
			dir := t.TempDir()
			port := freePort(t, "tcp")
			config := fmt.Sprintf("[snell-server]\nlisten = 127.0.0.1:%d\npsk = interop-password\nobfs = off\nversion = %s\n", port, version)
			cfgFile := writeInteropFile(t, dir, "snell.conf", config)
			srv := startReference(t, "snell server", server, "-c", cfgFile)
			srv.waitForLog(t, "snell server")
			waitForTCP(t, fmt.Sprintf("127.0.0.1:%d", port))

			dialer := mustInteropDialer(t, Spec{
				Name: "snell v" + version, Type: "snell", Server: "127.0.0.1", Port: port,
				Args: []string{"127.0.0.1", fmt.Sprint(port), "interop-password", "version=" + version},
			})

			t.Run("tcp", func(t *testing.T) {
				echo := startTCPEcho(t)
				conn := dialThrough(t, dialer, echo)
				echoRoundTrip(t, conn, payload(16<<10))
			})

			// Snell carries datagrams inside the same framed TCP stream, so
			// this exercises our frame writer rather than a socket. It is
			// still gated: the reference server forwards each datagram from
			// an unconnected UDP socket, and this environment denies that
			// send with EPERM (the reference server logs it itself).
			t.Run("udp", func(t *testing.T) {
				if !datagramSendAllowed(t) {
					t.Skip("the reference server's UDP egress is denied in this environment (sendto: operation not permitted)")
				}
				echo := startUDPEcho(t)
				datagramRoundTrip(t, dialer, echo, []byte("interop datagram"))
			})
		})
	}
}

// TestInteropSnellRejectsAWrongPSK checks that the pre-shared key is really
// used: the frame header of a wrongly keyed client fails to authenticate, so
// the server closes instead of tunnelling.
func TestInteropSnellRejectsAWrongPSK(t *testing.T) {
	server := interopBinary(t, "snell")
	dir := t.TempDir()
	port := freePort(t, "tcp")
	config := fmt.Sprintf("[snell-server]\nlisten = 127.0.0.1:%d\npsk = the-right-psk\nobfs = off\nversion = 4\n", port)
	cfgFile := writeInteropFile(t, dir, "snell.conf", config)
	srv := startReference(t, "snell server", server, "-c", cfgFile)
	srv.waitForLog(t, "snell server")
	waitForTCP(t, fmt.Sprintf("127.0.0.1:%d", port))

	dialer := mustInteropDialer(t, Spec{
		Name: "wrong", Type: "snell", Server: "127.0.0.1", Port: port,
		Args: []string{"127.0.0.1", fmt.Sprint(port), "the-wrong-psk"},
	})
	expectNoEcho(t, dialer, startTCPEcho(t))
}
