//go:build !windows

package outbound

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"testing"
)

// Shadowsocks is where a wrong guess about the wire format is easiest to
// detect: the AEAD tag of the very first chunk fails, so a mismatched key or
// nonce derivation shows up as an authentication error rather than as a
// timeout. Both cipher families are checked, because the legacy methods derive
// their session key with HKDF-SHA1 from a password while the 2022 methods take
// a fixed-length key and use BLAKE3's derive-key mode.
func TestInteropShadowsocks(t *testing.T) {
	server := interopBinary(t, "shadowsocks")

	cases := []struct {
		name     string
		method   string
		password string
	}{
		{name: "legacy AEAD", method: "aes-256-gcm", password: "interop-legacy-password"},
		{name: "2022 AES-128", method: "2022-blake3-aes-128-gcm", password: base64.RawStdEncoding.EncodeToString(interopKey(16))},
		{name: "2022 AES-256", method: "2022-blake3-aes-256-gcm", password: base64.RawStdEncoding.EncodeToString(interopKey(32))},
		{name: "2022 ChaCha20", method: "2022-blake3-chacha20-poly1305", password: base64.RawStdEncoding.EncodeToString(interopKey(32))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			port := freePort(t, "tcp")
			config := fmt.Sprintf(`{
  "server": "127.0.0.1",
  "server_port": %d,
  "password": %q,
  "method": %q,
  "mode": "tcp_and_udp"
}`, port, tc.password, tc.method)
			cfgFile := writeInteropFile(t, dir, "ss.json", config)
			srv := startReference(t, "shadowsocks server", server, "-c", cfgFile)
			srv.waitForLog(t, "tcp server listening")

			dialer := mustInteropDialer(t, Spec{
				Name: tc.method, Type: "ss", Server: "127.0.0.1", Port: port,
				Args: []string{"127.0.0.1", strconv.Itoa(port), tc.method, tc.password},
			})

			t.Run("tcp", func(t *testing.T) {
				echo := startTCPEcho(t)
				conn := dialThrough(t, dialer, echo)
				echoRoundTrip(t, conn, payload(16<<10))
			})

			t.Run("udp", func(t *testing.T) {
				if !datagramSendAllowed(t) {
					t.Skip("the reference server needs to answer from an unconnected datagram socket, which this environment denies")
				}
				echo := startUDPEcho(t)
				datagramRoundTrip(t, dialer, echo, []byte("interop datagram"))
			})

		})
	}
}

// TestInteropShadowsocksRejectsAWrongPassword is the negative half: a server
// that answered a wrongly keyed client would mean the client is not really
// encrypting, which would make the positive cases meaningless.
func TestInteropShadowsocksRejectsAWrongPassword(t *testing.T) {
	server := interopBinary(t, "shadowsocks")
	dir := t.TempDir()
	port := freePort(t, "tcp")
	cfgFile := writeInteropFile(t, dir, "ss.json", fmt.Sprintf(`{
  "server": "127.0.0.1",
  "server_port": %d,
  "password": "the-right-password",
  "method": "aes-256-gcm",
  "mode": "tcp_only"
}`, port))
	srv := startReference(t, "shadowsocks server", server, "-c", cfgFile)
	srv.waitForLog(t, "tcp server listening")

	dialer := mustInteropDialer(t, Spec{
		Name: "wrong", Type: "ss", Server: "127.0.0.1", Port: port,
		Args: []string{"127.0.0.1", strconv.Itoa(port), "aes-256-gcm", "the-wrong-password"},
	})
	expectNoEcho(t, dialer, startTCPEcho(t))
}

// interopKey returns a deterministic pre-shared key of the given length. The
// 2022 methods take raw bytes, so a readable password would be a length error;
// a fixed pattern keeps failures reproducible.
func interopKey(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(0x11 * (i + 1))
	}
	return out
}
