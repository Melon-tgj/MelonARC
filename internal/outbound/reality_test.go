package outbound

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// realityTestServer is the peer of a REALITY handshake: it reads the
// ClientHello itself to check the sealed session id, then hands the same bytes
// to the standard library's TLS server, which completes a TLS 1.3 handshake
// with a certificate that only a client holding the authentication key can
// accept.
//
// Using the standard library as the TLS half is deliberate: it means the TLS
// record layer and key schedule of the client are checked against an
// implementation written by somebody else, while only the REALITY-specific
// fields are checked against this harness.
type realityTestServer struct {
	addr    string
	shortID []byte
	public  []byte

	mu       sync.Mutex
	sni      string
	alpn     string
	failures []string
}

// startRealityTestServer serves the handshake on a loopback port. When
// authenticate is false the session id is not opened and the certificate is a
// plain one, which is what a client sees when its traffic reaches the imitated
// site instead of the server.
func startRealityTestServer(t *testing.T, authenticate bool) *realityTestServer {
	t.Helper()
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate static key: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &realityTestServer{
		addr:    ln.Addr().String(),
		shortID: []byte{0x01, 0x23, 0x45, 0x67},
		public:  static.PublicKey().Bytes(),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn, static, authenticate)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return s
}

// TLSState returns the SNI and ALPN the standard library server negotiated.
func (s *realityTestServer) TLSState() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sni, s.alpn
}

// Failures returns why connections were dropped.
func (s *realityTestServer) Failures() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.failures...)
}

func (s *realityTestServer) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, err.Error())
}

func (s *realityTestServer) handle(conn net.Conn, static *ecdh.PrivateKey, authenticate bool) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testServerDeadline))

	record, hello, err := readTestClientHello(conn)
	if err != nil {
		s.fail(err)
		return
	}
	random, _, keyShare, err := parseTestClientHello(hello)
	if err != nil {
		s.fail(err)
		return
	}
	clientKey, err := ecdh.X25519().NewPublicKey(keyShare)
	if err != nil {
		s.fail(err)
		return
	}
	shared, err := static.ECDH(clientKey)
	if err != nil {
		s.fail(err)
		return
	}
	authKey := realityAuthKey(shared, random)

	if authenticate {
		plain, err := realityOpenSessionID(hello, realitySessionIDOffset, authKey, random)
		if err != nil {
			s.fail(err)
			return
		}
		if plain[0] != realityVersionMajor || plain[1] != realityVersionMinor {
			s.fail(errors.New("reality test: unexpected client version stamp"))
			return
		}
		stamp := binary.BigEndian.Uint32(plain[4:8])
		if skew := time.Since(time.Unix(int64(stamp), 0)); skew > time.Minute || skew < -time.Minute {
			s.fail(errors.New("reality test: the timestamp is outside the accepted window"))
			return
		}
		if !bytes.Equal(plain[8:8+len(s.shortID)], s.shortID) {
			s.fail(errors.New("reality test: the short id does not match"))
			return
		}
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.fail(err)
		return
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "reality test peer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"reality.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		s.fail(err)
		return
	}
	if authenticate {
		if der, err = realityServerCertificate(template, privateKey, authKey); err != nil {
			s.fail(err)
			return
		}
	}

	replay := &replayConn{Conn: conn, prefix: record}
	server := tls.Server(replay, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := server.Handshake(); err != nil {
		s.fail(err)
		return
	}
	state := server.ConnectionState()
	s.mu.Lock()
	s.sni, s.alpn = state.ServerName, state.NegotiatedProtocol
	s.mu.Unlock()
	// The tunnel on top is VLESS, so the test covers the whole stack: the
	// handshake, the header and the echo.
	if _, _, _, err := vlessOpenRequest(server, testVLESSUUID); err != nil {
		s.fail(err)
		return
	}
	if err := vlessWriteResponse(server); err != nil {
		s.fail(err)
		return
	}
	_, _ = io.Copy(server, server)
}

// replayConn returns the bytes that were already consumed before a second
// reader takes over, then reads from the connection.
type replayConn struct {
	net.Conn
	prefix []byte
	off    int
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(p, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// readTestClientHello reads the first TLS record, which carries the whole
// ClientHello of this client, and returns both the record (header included,
// so it can be replayed to the TLS server) and its payload.
func readTestClientHello(conn net.Conn) (record, payload []byte, err error) {
	head := make([]byte, 5)
	if _, err = io.ReadFull(conn, head); err != nil {
		return nil, nil, err
	}
	if head[0] != peerRecordHandshake {
		return nil, nil, errors.New("reality test: the first record is not a handshake record")
	}
	payload = make([]byte, binary.BigEndian.Uint16(head[3:]))
	if _, err = io.ReadFull(conn, payload); err != nil {
		return nil, nil, err
	}
	record = append(head, payload...)
	return record, payload, nil
}

// parseTestClientHello pulls the fields the handshake check needs out of a
// ClientHello. It is the test peer's own parser on purpose: the client side
// builds these bytes, and a shared builder would hide a layout mistake.
//
// The hello is a browser-shaped one: its key share list starts with a GREASE
// group and its first real entry is the hybrid X25519MLKEM768 group, whose last
// 32 bytes are the X25519 public key. The peer hands the whole ClientHello to
// crypto/tls, which answers the hybrid group properly, so only the classical
// half is extracted here: that is the key REALITY authenticates against.
func parseTestClientHello(hello []byte) (random, sessionID, keyShare []byte, err error) {
	if len(hello) < 39 || hello[0] != peerMsgClientHello {
		return nil, nil, nil, errors.New("reality test: not a client hello")
	}
	random = hello[6:38]
	idLen := int(hello[38])
	if len(hello) < 39+idLen {
		return nil, nil, nil, errors.New("reality test: truncated session id")
	}
	sessionID = hello[39 : 39+idLen]
	rest := hello[39+idLen:]
	if len(rest) < 2 {
		return nil, nil, nil, errors.New("reality test: truncated cipher suites")
	}
	suites := int(binary.BigEndian.Uint16(rest))
	if len(rest) < 2+suites {
		return nil, nil, nil, errors.New("reality test: truncated cipher suites")
	}
	rest = rest[2+suites:]
	if len(rest) < 1 {
		return nil, nil, nil, errors.New("reality test: truncated compression methods")
	}
	rest = rest[1+int(rest[0]):]
	if len(rest) < 2 {
		return nil, nil, nil, errors.New("reality test: truncated extensions")
	}
	extLen := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if len(rest) < extLen {
		return nil, nil, nil, errors.New("reality test: truncated extensions")
	}
	var hybrid []byte
	for extensions := rest[:extLen]; len(extensions) >= 4; {
		typ := binary.BigEndian.Uint16(extensions)
		length := int(binary.BigEndian.Uint16(extensions[2:]))
		extensions = extensions[4:]
		if len(extensions) < length {
			return nil, nil, nil, errors.New("reality test: truncated extension")
		}
		body := extensions[:length]
		extensions = extensions[length:]
		if typ != peerExtKeyShare {
			continue
		}
		if len(body) < 2 {
			return nil, nil, nil, errors.New("reality test: truncated key share list")
		}
		list := body[2:]
		for len(list) >= 4 {
			group := binary.BigEndian.Uint16(list)
			keyLen := int(binary.BigEndian.Uint16(list[2:]))
			list = list[4:]
			if len(list) < keyLen {
				return nil, nil, nil, errors.New("reality test: truncated key share")
			}
			data := list[:keyLen]
			list = list[keyLen:]
			switch group {
			case peerGroupX25519MLKEM768:
				if keyLen != mlkem.EncapsulationKeySize768+32 {
					return nil, nil, nil, errors.New("reality test: the hybrid key share has the wrong length")
				}
				hybrid = data[mlkem.EncapsulationKeySize768:]
			case peerGroupX25519:
				if keyShare == nil && keyLen == 32 {
					keyShare = data
				}
			default:
				// A GREASE group or a group this peer does not speak. It is
				// part of the shape of a browser hello, not an error.
				continue
			}
		}
	}
	// A REALITY server authenticates against the standalone X25519 share, and
	// only falls back to the classical half of the hybrid share for a hello
	// that offers nothing else. The peer has to make the same choice or it
	// would accept a seal the real server refuses.
	if keyShare == nil {
		keyShare = hybrid
	}
	if keyShare == nil {
		return nil, nil, nil, errors.New("reality test: the client hello has no key share")
	}
	return random, sessionID, keyShare, nil
}

// mustRealityVLESS builds a REALITY-secured VLESS dialer pointed at server.
func mustRealityVLESS(t *testing.T, server *realityTestServer, key []byte) *VLESS {
	t.Helper()
	target, err := ParseTarget(server.addr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dialer, err := NewVLESS(VLESSOptions{
		Server: target.Host, Port: int(target.Port), UUID: testVLESSID,
		Reality: &RealityOptions{PublicKey: key, ShortID: server.shortID, ServerName: "reality.example"},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewVLESS: %v", err)
	}
	return dialer
}

func TestRealityRoundTrip(t *testing.T) {
	server := startRealityTestServer(t, true)
	dialer := mustRealityVLESS(t, server, server.public)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "example.test:443")
	if err != nil {
		t.Fatalf("DialContext: %v (server: %v)", err, server.Failures())
	}
	defer conn.Close()
	assertEcho(t, conn, []byte("hello reality"))

	sni, alpn := server.TLSState()
	if sni != "reality.example" {
		t.Fatalf("server name = %q, want the imitation name", sni)
	}
	if alpn != "h2" {
		t.Fatalf("alpn = %q, want the browser default h2", alpn)
	}
}

func TestRealityRejectsPlainCertificate(t *testing.T) {
	// A peer that finishes the handshake with a real certificate is either the
	// imitated site or a middlebox. The client must refuse, not silently trust
	// the chain: the whole point of the handshake is that no authority is
	// involved.
	server := startRealityTestServer(t, false)
	dialer := mustRealityVLESS(t, server, server.public)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := dialer.DialContext(ctx, "example.test:443")
	if err == nil || !strings.Contains(err.Error(), "not sealed with the authentication key") {
		t.Fatalf("err = %v, want a refused certificate", err)
	}
}

func TestRealityWrongPublicKey(t *testing.T) {
	server := startRealityTestServer(t, true)
	wrong := make([]byte, 32)
	for i := range wrong {
		wrong[i] = byte(i + 1)
	}
	dialer := mustRealityVLESS(t, server, wrong)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := dialer.DialContext(ctx, "example.test:443"); err == nil {
		t.Fatal("a handshake sealed with another key succeeded")
	}
	failures := server.Failures()
	if len(failures) == 0 || !strings.Contains(failures[0], "not sealed with this key") {
		t.Fatalf("server failures = %v, want a failed session id check", failures)
	}
}

func TestRealityShortIDMismatch(t *testing.T) {
	server := startRealityTestServer(t, true)
	dialer := mustRealityVLESS(t, server, server.public)
	// A dialer built with another short id opens the session id correctly but
	// names a client the server does not know.
	target, err := ParseTarget(server.addr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	other, err := NewVLESS(VLESSOptions{
		Server: target.Host, Port: int(target.Port), UUID: testVLESSID,
		Reality: &RealityOptions{PublicKey: server.public, ShortID: []byte{0xff}, ServerName: "reality.example"},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewVLESS: %v", err)
	}
	_ = dialer

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := other.DialContext(ctx, "example.test:443"); err == nil {
		t.Fatal("a handshake with another short id succeeded")
	}
	failures := server.Failures()
	if len(failures) == 0 || !strings.Contains(failures[0], "short id does not match") {
		t.Fatalf("server failures = %v, want a short id mismatch", failures)
	}
}

func TestRealityOptions(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tests := []struct {
		name string
		spec Spec
		want string
	}{
		{
			name: "short id is too long",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "reality=" + key, "sni=a.example", "short-id=001122334455667788"}},
			want: "longer than 8 bytes",
		},
		{
			name: "happy path",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "reality=" + key, "sni=a.example", "short-id=0123456789abcdef"}},
			want: "",
		},
		{
			name: "padded base64 key",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "reality=" + base64.URLEncoding.EncodeToString(make([]byte, 32)), "sni=a.example"}},
			want: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialer, err := newVLESSFromSpec(test.spec)
			if test.want == "" {
				if err != nil {
					t.Fatalf("configuration rejected: %v", err)
				}
				if dialer == nil {
					t.Fatal("no dialer")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want %q", err, test.want)
			}
		})
	}
}
