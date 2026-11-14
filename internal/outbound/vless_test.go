package outbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

const testVLESSID = "b831381d-6324-4d53-ad4f-8cda48b30811"

var testVLESSUUID = [16]byte{
	0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53,
	0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
}

// testVLESSRequest is one request a test server received.
type testVLESSRequest struct {
	Command byte
	Addons  []byte
	Target  Target
}

// testVLESS is a self-written VLESS server. It reads the request header,
// answers with the response header and then echoes: bytes for a stream, one
// framed datagram at a time for a datagram request.
type testVLESS struct {
	addr string

	mu       sync.Mutex
	requests []testVLESSRequest
	sni      string
	alpn     string
	rejected int
	failures []string
}

// startTestVLESS serves VLESS on a loopback port, optionally behind TLS.
func startTestVLESS(t *testing.T, uuid string, useTLS bool, tlsConfig *tls.Config) (*testVLESS, *x509.CertPool) {
	t.Helper()
	id, err := parseVMessUUID(uuid)
	if err != nil {
		t.Fatalf("parse uuid: %v", err)
	}
	var (
		ln   net.Listener
		pool *x509.CertPool
	)
	if useTLS {
		cert, roots := testCertificate(t)
		pool = roots
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		tlsConfig = tlsConfig.Clone()
		tlsConfig.Certificates = []tls.Certificate{cert}
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testVLESS{addr: ln.Addr().String()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn, id)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return s, pool
}

// Requests returns the headers the server accepted.
func (s *testVLESS) Requests() []testVLESSRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]testVLESSRequest(nil), s.requests...)
}

// TLSState returns the SNI and ALPN the server negotiated.
func (s *testVLESS) TLSState() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sni, s.alpn
}

// Rejected reports how many requests failed the handshake or the header check.
func (s *testVLESS) Rejected() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rejected
}

// recordFailure notes why a connection was dropped, so a failing test can say
// what the peer did rather than only that the client saw an EOF.
func (s *testVLESS) recordFailure(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejected++
	s.failures = append(s.failures, err.Error())
}

// Failures returns the reasons the server dropped connections.
func (s *testVLESS) Failures() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.failures...)
}

func (s *testVLESS) handle(conn net.Conn, id [16]byte) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testServerDeadline))
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			s.recordFailure(err)
			return
		}
		state := tlsConn.ConnectionState()
		s.mu.Lock()
		s.sni, s.alpn = state.ServerName, state.NegotiatedProtocol
		s.mu.Unlock()
	}
	target, command, addons, err := vlessOpenRequest(conn, id)
	if err != nil {
		s.recordFailure(err)
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, testVLESSRequest{Command: command, Addons: addons, Target: target})
	s.mu.Unlock()
	if err := vlessWriteResponse(conn); err != nil {
		return
	}
	switch command {
	case vlessCommandTCP:
		_, _ = io.Copy(conn, conn)
	case vlessCommandUDP:
		for {
			var head [2]byte
			if _, err := io.ReadFull(conn, head[:]); err != nil {
				return
			}
			payload := make([]byte, binary.BigEndian.Uint16(head[:]))
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
			if _, err := conn.Write(append(head[:], payload...)); err != nil {
				return
			}
		}
	}
}

// mustVLESS builds a dialer pointed at address.
func mustVLESS(t *testing.T, address string, opts VLESSOptions) *VLESS {
	t.Helper()
	target, err := ParseTarget(address)
	if err != nil {
		t.Fatalf("parse %q: %v", address, err)
	}
	opts.Server, opts.Port, opts.UUID = target.Host, int(target.Port), testVLESSID
	opts.Timeout = 5 * time.Second
	dialer, err := NewVLESS(opts)
	if err != nil {
		t.Fatalf("NewVLESS: %v", err)
	}
	return dialer
}

func TestVLESSRoundTrip(t *testing.T) {
	server, _ := startTestVLESS(t, testVLESSID, false, nil)
	dialer := mustVLESS(t, server.addr, VLESSOptions{TLS: TLSOptions{Enabled: false}})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "example.test:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn, []byte("hello vless"))

	requests := server.Requests()
	if len(requests) != 1 {
		t.Fatalf("server saw %d requests, want 1", len(requests))
	}
	if requests[0].Command != vlessCommandTCP {
		t.Fatalf("command = %#x, want TCP", requests[0].Command)
	}
	if len(requests[0].Addons) != 0 {
		t.Fatalf("addons = %x, want none", requests[0].Addons)
	}
	if requests[0].Target.String() != "example.test:443" {
		t.Fatalf("target = %q", requests[0].Target)
	}
}

func TestVLESSOverTLS(t *testing.T) {
	server, roots := startTestVLESS(t, testVLESSID, true, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	})
	dialer := mustVLESS(t, server.addr, VLESSOptions{
		TLS: TLSOptions{Enabled: true, ALPN: []string{"h2"}, Config: &tls.Config{RootCAs: roots}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "203.0.113.9:8443")
	if err != nil {
		t.Fatalf("DialContext: %v (server: %v)", err, server.Failures())
	}
	defer conn.Close()
	assertEcho(t, conn, []byte("hello over tls"))

	sni, alpn := server.TLSState()
	// The dialled host is an IP literal, and a client sends no SNI for one.
	if sni != "" {
		t.Fatalf("server name = %q, want none for an IP literal", sni)
	}
	if alpn != "h2" {
		t.Fatalf("alpn = %q, want h2", alpn)
	}
	if got := server.Requests()[0].Target.String(); got != "203.0.113.9:8443" {
		t.Fatalf("target = %q", got)
	}
}

func TestVLESSOverTLSServerName(t *testing.T) {
	server, _ := startTestVLESS(t, testVLESSID, true, nil)
	dialer := mustVLESS(t, server.addr, VLESSOptions{
		TLS: TLSOptions{Enabled: true, ServerName: "vless.example", SkipVerify: true},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "example.test:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn, []byte("sni"))

	if sni, _ := server.TLSState(); sni != "vless.example" {
		t.Fatalf("server name = %q, want the override", sni)
	}
}

func TestVLESSUDP(t *testing.T) {
	server, _ := startTestVLESS(t, testVLESSID, false, nil)
	dialer := mustVLESS(t, server.addr, VLESSOptions{TLS: TLSOptions{Enabled: false}})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	packet, err := dialer.DialPacket(ctx, "203.0.113.5:53")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer packet.Close()

	// Each write is one datagram and each read returns exactly one, so a test
	// can send two payloads back to back and see them come back separately.
	for _, payload := range [][]byte{[]byte("first datagram"), []byte("second")} {
		if _, err := packet.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 64)
		n, err := packet.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("read %q, want %q", buf[:n], payload)
		}
	}
	requests := server.Requests()
	if len(requests) != 1 || requests[0].Command != vlessCommandUDP {
		t.Fatalf("requests = %+v, want one UDP request", requests)
	}
}

func TestVLESSWireFormat(t *testing.T) {
	// The request layout is asserted byte by byte: a peer that reads a field
	// in another order would still echo, so a round trip alone is not enough.
	header := make(chan []byte, 1)
	address := startScriptedServer(t, func(conn net.Conn) {
		buf := make([]byte, 1+16+1+1+2+1+1+len("example.test"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			header <- nil
			return
		}
		header <- buf
		_ = vlessWriteResponse(conn)
		_, _ = io.Copy(io.Discard, conn)
	})
	dialer := mustVLESS(t, address, VLESSOptions{TLS: TLSOptions{Enabled: false}})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "example.test:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	got := <-header
	if got == nil {
		t.Fatal("the server read no header")
	}
	want := []byte{vlessVersion}
	want = append(want, testVLESSUUID[:]...)
	want = append(want, 0, vlessCommandTCP)
	want = binary.BigEndian.AppendUint16(want, 443)
	want = append(want, vlessATYPDomain, byte(len("example.test")))
	want = append(want, "example.test"...)
	if !bytes.Equal(got, want) {
		t.Fatalf("header =\n%x\nwant\n%x", got, want)
	}
}

func TestVLESSRejectsUnknownAccount(t *testing.T) {
	server, _ := startTestVLESS(t, testVLESSID, false, nil)
	target, err := ParseTarget(server.addr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dialer, err := NewVLESS(VLESSOptions{
		Server: target.Host, Port: int(target.Port),
		UUID: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
		TLS:  TLSOptions{Enabled: false}, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewVLESS: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := dialer.DialContext(ctx, "example.test:443"); err == nil {
		t.Fatal("a dial with an unknown account succeeded")
	}
	if server.Rejected() != 1 {
		t.Fatalf("server rejected %d requests, want 1", server.Rejected())
	}
}

func TestVLESSVersionMismatchIsAnError(t *testing.T) {
	// A peer that answers with another version number is not speaking this
	// protocol, and the stream must not be handed to the caller.
	address := startScriptedServer(t, func(conn net.Conn) {
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{9, 0})
	})
	dialer := mustVLESS(t, address, VLESSOptions{TLS: TLSOptions{Enabled: false}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := dialer.DialContext(ctx, "example.test:443")
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("err = %v, want a version mismatch", err)
	}
}

func TestNewVLESSOptions(t *testing.T) {
	const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tests := []struct {
		name string
		spec Spec
		want string
	}{
		{
			name: "no transport security",
			spec: Spec{Type: "vless", Server: "h", Port: 443, Args: []string{"h", "443", testVLESSID}},
			want: "tls=true or reality=",
		},
		{
			name: "vision flow is not implemented",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "tls=true", "flow=xtls-rprx-vision"}},
			want: "record-level padding",
		},
		{
			name: "unknown flow",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "tls=true", "flow=fast"}},
			want: "unknown flow",
		},
		{
			name: "reality and tls together",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "tls=true", "reality=" + key, "sni=a.example"}},
			want: "cannot be combined",
		},
		{
			name: "reality without a name",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "reality=" + key}},
			want: "needs sni=",
		},
		{
			name: "reality key is not base64",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "reality=not base64!", "sni=a.example"}},
			want: "not base64",
		},
		{
			name: "reality key is short",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "reality=AAAA", "sni=a.example"}},
			want: "want 32",
		},
		{
			name: "short id without reality",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "tls=true", "short-id=01"}},
			want: "only means something with reality",
		},
		{
			name: "short id is not hex",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "reality=" + key, "sni=a.example", "short-id=zz"}},
			want: "must be hex",
		},
		{
			name: "bad uuid",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", "not-a-uuid", "tls=true"}},
			want: "uuid",
		},
		{
			name: "unknown option",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "tls=true", "encryption=none"}},
			want: "unknown option",
		},
		{
			name: "extra positional argument",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", testVLESSID, "extra", "tls=true"}},
			want: "unexpected argument",
		},
		{
			name: "missing uuid",
			spec: Spec{Type: "vless", Server: "h", Port: 443,
				Args: []string{"h", "443", "tls=true"}},
			want: "needs a uuid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newVLESSFromSpec(test.spec)
			if err == nil {
				t.Fatal("the configuration was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want %q", err, test.want)
			}
		})
	}
}

// assertEcho writes payload and reads it back.
func assertEcho(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("read %q, want %q", got, payload)
	}
}
