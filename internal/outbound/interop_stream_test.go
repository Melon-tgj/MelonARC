//go:build !windows

package outbound

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"
)

// One reference server answers VMess, Trojan, VLESS and REALITY from a single
// binary and a single configuration format, so the four tests below share the
// fixture builders at the bottom of this file. Each one checks a different wire
// format: VMess's request header and body chunks, Trojan's password hash on a
// TLS hop, VLESS's own request header on TLS, and VLESS on REALITY, where the
// handshake itself is the authentication.
//
// Each test looks for $MELONARC_INTEROP_DIR/<protocol>/server, so the slot names
// the protocol under test rather than the implementation behind it. One binary
// that speaks several protocols is linked into several slots; the configuration
// builders below stay specific to its format, which is a property of the
// download and not of the code.

// interopFreedom is the outbound of every inbound these tests start. It allows
// loopback destinations explicitly: a current build of the reference server
// refuses private addresses unless a final rule names them, which is a sensible
// default for a deployed server and an obstacle only for a test that keeps every
// party on 127.0.0.1.
const interopFreedom = `{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1"]}]}}`

// interopUUID is the client identity of every inbound these tests start.
const interopUUID = "2dd61f16-2f34-4b9e-9d5e-0d3a1b4c5d6e"

// interopPassword is the shared secret of the password protocols.
const interopPassword = "interop-password"

func TestInteropVMess(t *testing.T) {
	server := interopBinary(t, "vmess")
	dir := t.TempDir()
	port := freePort(t, "tcp")
	cfg := writeInteropFile(t, dir, "vmess.json", fmt.Sprintf(`{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "vmess",
    "settings": {"clients": [{"id": %q, "security": "aes-128-gcm"}]}
  }],
  "outbounds": [%s]
}`, port, interopUUID, interopFreedom))
	startReference(t, "vmess inbound", server, "run", "-c", cfg)
	waitForTCP(t, "127.0.0.1:"+strconv.Itoa(port))

	dialer := mustInteropDialer(t, Spec{
		Name: "vmess", Type: "vmess", Server: "127.0.0.1", Port: port,
		Args: []string{"127.0.0.1", strconv.Itoa(port), "uuid=" + interopUUID, "security=aes-128-gcm"},
	})

	t.Run("tcp", func(t *testing.T) {
		conn := dialThrough(t, dialer, startTCPEcho(t))
		echoRoundTrip(t, conn, payload(64<<10))
	})

	t.Run("udp", func(t *testing.T) {
		// The request is accepted (the server routes it), but the reference
		// server forwards the datagram from an unconnected socket, which this
		// environment denies.
		if !datagramSendAllowed(t) {
			t.Skip("this environment denies sendto on an unconnected datagram socket, which the reference server needs to forward a datagram")
		}
		datagramRoundTrip(t, dialer, startUDPEcho(t), []byte("vmess datagram"))
	})
}

func TestInteropTrojan(t *testing.T) {
	server := interopBinary(t, "trojan")
	dir := t.TempDir()
	certFile, keyFile, pool := interopCertificate(t, dir)
	port := freePort(t, "tcp")
	cfg := writeInteropFile(t, dir, "trojan.json", fmt.Sprintf(`{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "trojan",
    "settings": {"clients": [{"password": %q}]},
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {"certificates": [{"certificateFile": %q, "keyFile": %q}]}
    }
  }],
  "outbounds": [%s]
}`, port, interopPassword, certFile, keyFile, interopFreedom))
	startReference(t, "trojan inbound", server, "run", "-c", cfg)
	waitForTCP(t, "127.0.0.1:"+strconv.Itoa(port))

	dialer := mustInteropDialer(t, Spec{
		Name: "trojan", Type: "trojan", Server: "127.0.0.1", Port: port,
		Args: []string{"127.0.0.1", strconv.Itoa(port), "password=" + interopPassword, "sni=localhost"},
	})
	// The certificate is signed by this test, so the dialer trusts that pool
	// instead of a store; everything else goes through the normal path.
	trustDialer(t, dialer).Config = trustPool(pool)

	t.Run("tcp", func(t *testing.T) {
		conn := dialThrough(t, dialer, startTCPEcho(t))
		echoRoundTrip(t, conn, payload(32<<10))
	})

	t.Run("udp", func(t *testing.T) {
		if !datagramSendAllowed(t) {
			t.Skip("this environment denies sendto on an unconnected datagram socket, which the reference server needs to forward a datagram")
		}
		datagramRoundTrip(t, dialer, startUDPEcho(t), []byte("trojan datagram"))
	})
}

func TestInteropVLESS(t *testing.T) {
	server := interopBinary(t, "vless")
	dir := t.TempDir()
	certFile, keyFile, pool := interopCertificate(t, dir)
	port := freePort(t, "tcp")
	cfg := writeInteropFile(t, dir, "vless.json", fmt.Sprintf(`{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "vless",
    "settings": {"clients": [{"id": %q}], "decryption": "none"},
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {"certificates": [{"certificateFile": %q, "keyFile": %q}]}
    }
  }],
  "outbounds": [%s]
}`, port, interopUUID, certFile, keyFile, interopFreedom))
	startReference(t, "vless inbound", server, "run", "-c", cfg)
	waitForTCP(t, "127.0.0.1:"+strconv.Itoa(port))

	dialer := mustInteropDialer(t, Spec{
		Name: "vless", Type: "vless", Server: "127.0.0.1", Port: port,
		Args: []string{"127.0.0.1", strconv.Itoa(port), "uuid=" + interopUUID, "tls=true", "sni=localhost"},
	})
	trustDialer(t, dialer).Config = trustPool(pool)

	t.Run("tcp", func(t *testing.T) {
		conn := dialThrough(t, dialer, startTCPEcho(t))
		echoRoundTrip(t, conn, payload(32<<10))
	})

	t.Run("udp", func(t *testing.T) {
		if !datagramSendAllowed(t) {
			t.Skip("this environment denies sendto on an unconnected datagram socket, which the reference server needs to forward a datagram")
		}
		datagramRoundTrip(t, dialer, startUDPEcho(t), []byte("vless datagram"))
	})
}

// TestInteropVLESSReality is the one that matters most about REALITY: the
// handshake is not a certificate exchange but a shared-key proof, and a client
// that gets any byte of it wrong is not rejected politely, it is handed the
// imitated site.
//
// The test takes about five seconds, and none of that is handshake latency:
// after the client's Finished the reference server refuses to start relaying
// until it has profiled the imitation site it falls back to, and it polls for
// that profile in five-second steps. The first authenticated connection pays
// for the profile, later ones do not. A client-side trace puts the
// ClientHello, the Finished and the request on the wire within milliseconds.
func TestInteropVLESSReality(t *testing.T) {
	server := interopBinary(t, "vless")
	dir := t.TempDir()
	certFile, keyFile, _ := interopCertificate(t, dir)
	dest := startTLSDestination(t, certFile, keyFile)

	privateKey, publicKey := realityKeyPair(t)
	port := freePort(t, "tcp")
	cfg := writeInteropFile(t, dir, "reality.json", fmt.Sprintf(`{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "vless",
    "settings": {"clients": [{"id": %q}], "decryption": "none"},
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": %q,
        "xver": 0,
        "serverNames": ["localhost"],
        "privateKey": %q,
        "shortIds": ["0123456789abcdef"]
      }
    }
  }],
  "outbounds": [%s]
}`, port, interopUUID, dest, privateKey, interopFreedom))
	startReference(t, "vless reality inbound", server, "run", "-c", cfg)
	waitForTCP(t, "127.0.0.1:"+strconv.Itoa(port))

	dialer := mustInteropDialer(t, Spec{
		Name: "reality", Type: "vless", Server: "127.0.0.1", Port: port,
		Args: []string{
			"127.0.0.1", strconv.Itoa(port),
			"uuid=" + interopUUID, "reality=" + publicKey,
			"short-id=0123456789abcdef", "sni=localhost",
		},
	})

	conn := dialThrough(t, dialer, startTCPEcho(t))
	echoRoundTrip(t, conn, payload(16<<10))
}

// trustDialer returns the TLS settings of a protocol whose hop this test has to
// authenticate itself. It is the only white-box step in the interop tests, and
// it exists because the alternative would be a configuration key that disables
// certificate checking, which no user should be encouraged to use.
func trustDialer(t *testing.T, d Dialer) *TLSOptions {
	t.Helper()
	switch v := d.(type) {
	case *Trojan:
		return &v.tls
	case *VLESS:
		return &v.tls
	default:
		t.Fatalf("trustDialer: %T has no TLS settings", d)
		return nil
	}
}

// startTLSDestination serves the site a REALITY handshake imitates. The server
// needs it to answer a probe that did not authenticate, and to have a
// certificate to copy the shape of.
func startTLSDestination(t *testing.T, certFile, keyFile string) string {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(testServerDeadline))
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// realityKeyPair returns the base64 forms of a fresh X25519 key pair: the
// private key for the server, the public key the client authenticates with.
func realityKeyPair(t *testing.T) (private, public string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()),
		base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}
