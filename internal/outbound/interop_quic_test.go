//go:build !windows

package outbound

import (
	"fmt"
	"strconv"
	"testing"
)

// The QUIC protocols are the ones this environment can least accommodate: a
// QUIC server answers from a listening socket it never connected, and the
// sandbox this suite usually runs in denies that sendto. The tests therefore
// probe the capability first and skip with the reason instead of reporting a
// failure that says nothing about the client. Where the capability exists they
// run in full, which is the point: a client that has never met another
// implementation has only been tested against itself.

func TestInteropHysteria2(t *testing.T) {
	server := interopBinary(t, "hysteria2")
	if !datagramSendAllowed(t) {
		t.Skip("this environment denies sendto on an unconnected datagram socket, which a QUIC server needs to answer")
	}
	dir := t.TempDir()
	certFile, keyFile, pool := interopCertificate(t, dir)
	port := freePort(t, "udp")
	cfg := writeInteropFile(t, dir, "hysteria2.yaml", fmt.Sprintf(`listen: 127.0.0.1:%d
tls:
  cert: %s
  key: %s
auth:
  type: password
  password: %s
`, port, certFile, keyFile, interopPassword))
	srv := startReference(t, "hysteria2 server", server, "server", "-c", cfg)
	srv.waitForLog(t, "server up and running")

	dialer := mustInteropDialer(t, Spec{
		Name: "hysteria2", Type: "hysteria2", Server: "127.0.0.1", Port: port,
		Args: []string{"127.0.0.1", strconv.Itoa(port), "password=" + interopPassword, "sni=localhost"},
	})
	trustDialer(t, dialer).Config = trustPool(pool)

	t.Run("tcp", func(t *testing.T) {
		conn := dialThrough(t, dialer, startTCPEcho(t))
		echoRoundTrip(t, conn, payload(32<<10))
	})

	t.Run("udp", func(t *testing.T) {
		datagramRoundTrip(t, dialer, startUDPEcho(t), []byte("hysteria2 datagram"))
	})
}

func TestInteropTUIC(t *testing.T) {
	server := interopBinary(t, "tuic")
	if !datagramSendAllowed(t) {
		t.Skip("this environment denies sendto on an unconnected datagram socket, which a QUIC server needs to answer")
	}
	dir := t.TempDir()
	certFile, keyFile, pool := interopCertificate(t, dir)
	port := freePort(t, "udp")
	cfg := writeInteropFile(t, dir, "tuic.json", fmt.Sprintf(`{
  "server": "127.0.0.1:%d",
  "users": {%q: %q},
  "certificate": %q,
  "private_key": %q,
  "congestion_control": "cubic",
  "alpn": ["h3"],
  "zero_rtt_handshake": false
}`, port, interopUUID, interopPassword, certFile, keyFile))
	srv := startReference(t, "tuic server", server, "-c", cfg)
	srv.waitForLog(t, "server started")

	dialer := mustInteropDialer(t, Spec{
		Name: "tuic", Type: "tuic", Server: "127.0.0.1", Port: port,
		Args: []string{"127.0.0.1", strconv.Itoa(port), "uuid=" + interopUUID, "password=" + interopPassword, "sni=localhost"},
	})
	trustDialer(t, dialer).Config = trustPool(pool)

	t.Run("tcp", func(t *testing.T) {
		conn := dialThrough(t, dialer, startTCPEcho(t))
		echoRoundTrip(t, conn, payload(32<<10))
	})

	t.Run("udp", func(t *testing.T) {
		datagramRoundTrip(t, dialer, startUDPEcho(t), []byte("tuic datagram"))
	})
}
