package outbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	testHysteria2Password = "correct horse battery staple"
	testQUICDeadline      = 10 * time.Second
)

// startTestQUIC serves QUIC on a loopback port and runs handle on every
// connection. The TLS certificate is the same one the TCP tests use.
func startTestQUIC(t *testing.T, alpn string, datagrams bool, handle func(*quic.Conn)) (string, *x509.CertPool) {
	t.Helper()
	cert, roots := testCertificate(t)
	ln, err := quic.Listen(testQUICPacketConn(t), &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpn},
	}, &quic.Config{
		MaxIdleTimeout:  time.Minute,
		EnableDatagrams: datagrams,
	})
	if err != nil {
		t.Fatalf("listen quic: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String(), roots
}

// testTLSOptions is the client side of those servers: trust their certificate.
func testTLSOptions(_ *testing.T, alpn string, roots *x509.CertPool) TLSOptions {
	return TLSOptions{Enabled: true, ALPN: []string{alpn}, Config: &tls.Config{RootCAs: roots}}
}

// hysteria2TestServer is a self-written Hysteria2 peer: it authenticates over
// an HTTP/3 request, echoes TCP streams and echoes datagrams back to their
// session.
type hysteria2TestServer struct {
	addr  string
	roots *x509.CertPool

	mu       sync.Mutex
	auths    []string
	requests []Target
	failures []string
}

func startHysteria2Server(t *testing.T, password string) *hysteria2TestServer {
	t.Helper()
	s := &hysteria2TestServer{}
	s.addr, s.roots = startTestQUIC(t, "h3", true, func(conn *quic.Conn) {
		s.serve(conn, password)
	})
	return s
}

func (s *hysteria2TestServer) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, err.Error())
}

func (s *hysteria2TestServer) Failures() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.failures...)
}

func (s *hysteria2TestServer) Requests() []Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Target(nil), s.requests...)
}

func (s *hysteria2TestServer) Auths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auths...)
}

func (s *hysteria2TestServer) serve(conn *quic.Conn, password string) {
	defer conn.CloseWithError(0, "done")
	// Unidirectional streams are the HTTP/3 control stream, which this peer can
	// ignore, so they are drained to keep the stream limit from filling up.
	go func() {
		for {
			stream, err := conn.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, stream) }()
		}
	}()
	go s.echoDatagrams(conn)

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.handleStream(stream, password)
	}
}

func (s *hysteria2TestServer) handleStream(stream *quic.Stream, password string) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(testQUICDeadline))
	reader := bufio.NewReader(stream)
	first, err := reader.Peek(1)
	if err != nil {
		return
	}
	// An auth request starts with a HEADERS frame, whose type is the one-byte
	// varint 0x01. A proxy request starts with the two-byte varint 0x401,
	// which begins with 0x45.
	if first[0] == h3FrameHeaders {
		if err := s.handleAuth(stream, reader, password); err != nil {
			s.fail(err)
		}
		return
	}
	frameType, err := quicvarint.Read(reader)
	if err != nil || frameType != hysteria2FrameTCPRequest {
		s.fail(errors.New("hysteria2 test: unexpected request frame"))
		return
	}
	addressLen, err := quicvarint.Read(reader)
	if err != nil {
		s.fail(err)
		return
	}
	address := make([]byte, addressLen)
	if _, err := io.ReadFull(reader, address); err != nil {
		s.fail(err)
		return
	}
	padding, err := quicvarint.Read(reader)
	if err != nil {
		s.fail(err)
		return
	}
	if _, err := io.CopyN(io.Discard, reader, int64(padding)); err != nil {
		s.fail(err)
		return
	}
	target, err := ParseTarget(string(address))
	if err != nil {
		s.fail(err)
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, target)
	s.mu.Unlock()

	// The answer is a status, an empty message and no padding.
	response := []byte{hysteria2StatusOK}
	response = quicvarint.Append(response, 0)
	response = quicvarint.Append(response, 0)
	if _, err := stream.Write(response); err != nil {
		return
	}
	_, _ = io.Copy(stream, reader) // echo
}

// handleAuth answers the HTTP/3 request. Only the fields the client must send
// are checked; the rest of the block is decoded and ignored.
func (s *hysteria2TestServer) handleAuth(stream *quic.Stream, reader *bufio.Reader, password string) error {
	typ, payload, err := readH3Frame(reader)
	if err != nil {
		return err
	}
	if typ != h3FrameHeaders {
		return errors.New("hysteria2 test: the request does not start with headers")
	}
	fields, err := h3DecodeHeaderBlock(payload)
	if err != nil {
		return err
	}
	path, auth := "", ""
	for _, field := range fields {
		switch field[0] {
		case ":path":
			path = field[1]
		case "hysteria-auth":
			auth = field[1]
		}
	}
	if path != hysteria2AuthPath {
		return errors.New("hysteria2 test: the request is not for the auth path")
	}
	s.mu.Lock()
	s.auths = append(s.auths, auth)
	s.mu.Unlock()

	status := "233"
	if auth != password {
		status = "404"
	}
	block := h3AppendField(h3AppendFieldSectionPrefix(nil), ":status", status)
	if _, err := stream.Write(appendH3Frame(nil, h3FrameHeaders, block)); err != nil {
		return err
	}
	return stream.Close()
}

// echoDatagrams returns every datagram to the session that sent it.
func (s *hysteria2TestServer) echoDatagrams(conn *quic.Conn) {
	for {
		payload, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			return
		}
		if len(payload) < 9 {
			continue
		}
		if err := conn.SendDatagram(payload); err != nil {
			return
		}
	}
}

func mustHysteria2(t *testing.T, address, password string, roots *x509.CertPool, obfs bool) *Hysteria2 {
	t.Helper()
	target, err := ParseTarget(address)
	if err != nil {
		t.Fatalf("parse %q: %v", address, err)
	}
	options := Hysteria2Options{
		Server: target.Host, Port: int(target.Port), Password: password,
		TLS: testTLSOptions(t, "h3", roots), Timeout: 5 * time.Second,
	}
	if obfs {
		options.Obfs, options.ObfsPassword = "salamander", "an obfuscation secret"
	}
	dialer, err := NewHysteria2(options)
	if err != nil {
		t.Fatalf("NewHysteria2: %v", err)
	}
	t.Cleanup(func() { _ = dialer.Close() })
	return dialer
}

func TestHysteria2RoundTrip(t *testing.T) {
	server := startHysteria2Server(t, testHysteria2Password)
	dialer := mustHysteria2(t, server.addr, testHysteria2Password, server.roots, false)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "example.test:443")
	if err != nil {
		t.Fatalf("DialContext: %v (server: %v)", err, server.Failures())
	}
	defer conn.Close()
	assertEcho(t, conn, []byte("hello hysteria2"))

	requests := server.Requests()
	if len(requests) != 1 || requests[0].String() != "example.test:443" {
		t.Fatalf("requests = %v", requests)
	}
	if auths := server.Auths(); len(auths) != 1 || auths[0] != testHysteria2Password {
		t.Fatalf("auth values = %v", auths)
	}
}

func TestHysteria2UDP(t *testing.T) {
	server := startHysteria2Server(t, testHysteria2Password)
	dialer := mustHysteria2(t, server.addr, testHysteria2Password, server.roots, false)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	packet, err := dialer.DialPacket(ctx, "203.0.113.5:53")
	if err != nil {
		t.Fatalf("DialPacket: %v (server: %v)", err, server.Failures())
	}
	defer packet.Close()

	for _, payload := range [][]byte{[]byte("small datagram"), bytes.Repeat([]byte("fragment "), 400)} {
		if _, err := packet.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, len(payload)+16)
		_ = packet.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := packet.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("read %d bytes, want %d", n, len(payload))
		}
	}
}

func TestHysteria2RejectedCredentials(t *testing.T) {
	server := startHysteria2Server(t, testHysteria2Password)
	dialer := mustHysteria2(t, server.addr, "wrong password", server.roots, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := dialer.DialContext(ctx, "example.test:443")
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("err = %v, want a rejected authentication", err)
	}
}

func TestHysteria2Options(t *testing.T) {
	tests := []struct {
		name string
		spec Spec
		want string
	}{
		{
			name: "password is required",
			spec: Spec{Type: "hysteria2", Server: "h", Port: 443, Args: []string{"h", "443"}},
			want: "password is required",
		},
		{
			name: "obfs password without obfs",
			spec: Spec{Type: "hysteria2", Server: "h", Port: 443,
				Args: []string{"h", "443", "pw", "obfs-password=secret"}},
			want: "obfs-password without obfs",
		},
		{
			name: "unknown obfs",
			spec: Spec{Type: "hysteria2", Server: "h", Port: 443,
				Args: []string{"h", "443", "pw", "obfs=rot13", "obfs-password=secret"}},
			want: "unsupported obfs",
		},
		{
			name: "obfs needs a password",
			spec: Spec{Type: "hysteria2", Server: "h", Port: 443,
				Args: []string{"h", "443", "pw", "obfs=salamander"}},
			want: "obfs-password is required",
		},
		{
			name: "bad rate",
			spec: Spec{Type: "hysteria2", Server: "h", Port: 443,
				Args: []string{"h", "443", "pw", "up=fast"}},
			want: "not a number",
		},
		{
			name: "tls keys are not configurable",
			spec: Spec{Type: "hysteria2", Server: "h", Port: 443,
				Args: []string{"h", "443", "pw", "tls=false"}},
			want: "tls= is not accepted",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newHysteria2FromSpec(test.spec)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseRate(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
		bad  bool
	}{
		{in: "", want: 0},
		{in: "1000000", want: 1000000},
		{in: "100mbps", want: 100 * 1000 * 1000 / 8},
		{in: "800kbps", want: 800 * 1000 / 8},
		{in: "500bps", want: 500},
		{in: "-1", bad: true},
		{in: "lots", bad: true},
	}
	for _, test := range tests {
		got, err := parseRate(test.in)
		if test.bad {
			if err == nil {
				t.Fatalf("parseRate(%q) = %d, want an error", test.in, got)
			}
			continue
		}
		if err != nil || got != test.want {
			t.Fatalf("parseRate(%q) = %d, %v, want %d", test.in, got, err, test.want)
		}
	}
}

func TestSalamanderRoundTrip(t *testing.T) {
	obfs, err := newSalamander("salamander", "shared secret")
	if err != nil {
		t.Fatalf("newSalamander: %v", err)
	}
	left, right := net.Pipe()
	wrapped, err := obfs.wrap(newPipePacketConn(left, right))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	plain := []byte("a datagram that must not appear on the wire")
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := wrapped.WriteTo(plain, &net.UDPAddr{}); err != nil {
			t.Errorf("write: %v", err)
		}
	}()
	raw := make([]byte, 256)
	n, err := right.Read(raw)
	if err != nil {
		t.Fatalf("read the raw side: %v", err)
	}
	<-done
	if n != 8+len(plain) {
		t.Fatalf("raw length = %d, want %d", n, 8+len(plain))
	}
	if bytes.Contains(raw[:n], plain) {
		t.Fatal("the payload appeared in the clear")
	}
	// The same key and salt must recover the payload.
	recovered := append([]byte(nil), raw[8:n]...)
	salamanderXOR([]byte("shared secret"), raw[:8], recovered)
	if !bytes.Equal(recovered, plain) {
		t.Fatalf("recovered %q, want %q", recovered, plain)
	}
}

// pipePacketConn adapts a pair of net.Pipe connections to a packet connection,
// which is enough to check the obfuscation without a real socket.
type pipePacketConn struct {
	write net.Conn
	read  net.Conn
}

func newPipePacketConn(write, read net.Conn) *pipePacketConn {
	return &pipePacketConn{write: write, read: read}
}

func (p *pipePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.read.Read(b)
	return n, &net.UDPAddr{}, err
}

func (p *pipePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return p.write.Write(b) }
func (p *pipePacketConn) Close() error                              { return p.write.Close() }
func (p *pipePacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (p *pipePacketConn) SetDeadline(t time.Time) error {
	_ = p.read.SetDeadline(t)
	return p.write.SetDeadline(t)
}
func (p *pipePacketConn) SetReadDeadline(t time.Time) error  { return p.read.SetDeadline(t) }
func (p *pipePacketConn) SetWriteDeadline(t time.Time) error { return p.write.SetDeadline(t) }

func TestHysteria2HeaderBlockRoundTrip(t *testing.T) {
	// The header encoder and decoder are a pair; a mistake in one of them is
	// invisible in an end-to-end test when the peer uses the same code, so the
	// pair is checked against the field it was given.
	block := h3EncodeRequestHeaders("hysteria", "/auth", [][2]string{
		{"hysteria-auth", "a password with spaces"},
		{"hysteria-cc-rx", "0"},
		{"hysteria-padding", strings.Repeat("x", 200)},
	})
	fields, err := h3DecodeHeaderBlock(block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := [][2]string{
		{":method", "POST"},
		{":scheme", "https"},
		{":authority", "hysteria"},
		{":path", "/auth"},
		{"hysteria-auth", "a password with spaces"},
		{"hysteria-cc-rx", "0"},
		{"hysteria-padding", strings.Repeat("x", 200)},
	}
	if len(fields) != len(want) {
		t.Fatalf("fields = %v", fields)
	}
	for i := range want {
		if fields[i] != want[i] {
			t.Fatalf("field %d = %v, want %v", i, fields[i], want[i])
		}
	}
}

// TestHysteria2AuthHeadersAreValidFields fixes an incompatibility with mature
// HTTP/3 peers: padding built from raw random bytes is not a valid field value,
// and a whole request block carrying it can be rejected before QPACK decoding.
func TestHysteria2AuthHeadersAreValidFields(t *testing.T) {
	headers := hysteria2AuthHeaders(testHysteria2Password, 1024)
	if len(headers) != 3 {
		t.Fatalf("auth headers = %v, want three fields", headers)
	}
	for _, field := range headers {
		for i := 0; i < len(field[1]); i++ {
			c := field[1][i]
			if (c < 0x20 && c != '\t') || c == 0x7f {
				t.Fatalf("field %q has a control byte at %d: %x", field[0], i, field[1])
			}
		}
	}
	if headers[2][0] != "hysteria-padding" {
		t.Fatalf("third field = %q, want hysteria-padding", headers[2][0])
	}
	if _, err := hex.DecodeString(headers[2][1]); err != nil {
		t.Fatalf("padding %q is not hex: %v", headers[2][1], err)
	}
	// The complete request block must still be a spec-conformant QPACK section.
	block := h3EncodeRequestHeaders(hysteria2AuthHost, hysteria2AuthPath, headers)
	fields, err := h3DecodeHeaderBlock(block)
	if err != nil {
		t.Fatalf("decode the auth request block: %v", err)
	}
	if fields[len(fields)-1] != headers[2] {
		t.Fatalf("last decoded field = %v, want %v", fields[len(fields)-1], headers[2])
	}
}

func TestH3DecodeIndexedStatus(t *testing.T) {
	// A peer that answers with a static-table status sends one indexed field
	// line; the decoder has to resolve it without any literal bytes.
	if status, err := h3ReadStatus(strings.NewReader(string(appendH3Frame(nil, h3FrameHeaders, []byte{0x00, 0x00, 0xd9})))); err != nil || status != 200 {
		t.Fatalf("status = %d, %v, want 200", status, err)
	}
	// 0x50 is a literal field line whose name refers to the static table entry
	// for :authority (index 0), with the value that follows inline.
	fields, err := h3DecodeHeaderBlock([]byte{0x00, 0x00, 0xd9, 0x50, 0x03, 'a', 'b', 'c'})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(fields) != 2 || fields[1] != [2]string{":authority", "abc"} {
		t.Fatalf("fields = %v", fields)
	}
}

func TestDatagramReassembler(t *testing.T) {
	r := newDatagramReassembler()
	if got, err := r.add(1, 0, 1, []byte("whole")); err != nil || string(got) != "whole" {
		t.Fatalf("single fragment = %q, %v", got, err)
	}
	if got, err := r.add(2, 0, 2, []byte("a")); err != nil || got != nil {
		t.Fatalf("first fragment = %q, %v, want nothing yet", got, err)
	}
	if got, err := r.add(2, 1, 2, []byte("b")); err != nil || string(got) != "ab" {
		t.Fatalf("second fragment = %q, %v", got, err)
	}
	// A fragment count that changes mid-datagram is a broken peer, not a
	// reason to grow the map.
	if _, err := r.add(3, 0, 2, []byte("a")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := r.add(3, 1, 3, []byte("b")); err == nil {
		t.Fatal("a mismatched fragment count was accepted")
	}
	if _, err := r.add(4, 2, 2, []byte("x")); err == nil {
		t.Fatal("an out-of-range fragment index was accepted")
	}
}
