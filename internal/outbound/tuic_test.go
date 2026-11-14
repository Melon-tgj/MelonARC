package outbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	testTUICUUID     = "b831381d-6324-4d53-ad4f-8cda48b30811"
	testTUICPassword = "tuic shared secret"
)

// tuicTestServer is a self-written TUIC peer: it checks the derived token,
// echoes Connect streams and returns datagrams to their association.
type tuicTestServer struct {
	addr  string
	roots *x509.CertPool

	mu       sync.Mutex
	targets  []Target
	failures []string
	assocs   int
}

func startTUICServer(t *testing.T, password string) *tuicTestServer {
	t.Helper()
	s := &tuicTestServer{}
	s.addr, s.roots = startTestQUIC(t, "h3", true, func(conn *quic.Conn) {
		s.serve(conn, password)
	})
	return s
}

func (s *tuicTestServer) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, err.Error())
}

func (s *tuicTestServer) Failures() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.failures...)
}

func (s *tuicTestServer) Targets() []Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Target(nil), s.targets...)
}

func (s *tuicTestServer) serve(conn *quic.Conn, password string) {
	defer conn.CloseWithError(0, "done")
	authed := make(chan struct{})
	go s.acceptUniStreams(conn, password, authed)
	go s.echoDatagrams(conn)
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.handleStream(stream, authed)
	}
}

// acceptUniStreams reads the Authenticate command. Its token is derived from
// the TLS session on both sides, so the peer has to compute it the same way.
func (s *tuicTestServer) acceptUniStreams(conn *quic.Conn, password string, authed chan struct{}) {
	id, err := parseVMessUUID(testTUICUUID)
	if err != nil {
		s.fail(err)
		return
	}
	state := conn.ConnectionState()
	want, err := state.TLS.ExportKeyingMaterial(testTUICUUID, []byte(password), tuicTokenLen)
	if err != nil {
		s.fail(err)
		return
	}
	for {
		stream, err := conn.AcceptUniStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			command := make([]byte, 2+16+tuicTokenLen)
			if _, err := io.ReadFull(stream, command); err != nil {
				s.fail(err)
				return
			}
			if command[0] != tuicVersion || command[1] != tuicCommandAuthenticate {
				s.fail(errors.New("tuic test: the first command is not an authentication"))
				return
			}
			if !bytes.Equal(command[2:18], id[:]) {
				s.fail(errors.New("tuic test: unknown account"))
				_ = conn.CloseWithError(0x100, "unknown account")
				return
			}
			if !bytes.Equal(command[18:], want) {
				s.fail(errors.New("tuic test: the token does not match"))
				_ = conn.CloseWithError(0x100, "authentication failed")
				return
			}
			close(authed)
		}()
	}
}

func (s *tuicTestServer) handleStream(stream *quic.Stream, authed <-chan struct{}) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(testQUICDeadline))
	// A peer holds stream commands until the connection is authenticated,
	// which is what the protocol says a server should do.
	select {
	case <-authed:
	case <-time.After(5 * time.Second):
		return
	}
	reader := bufio.NewReader(stream)
	var head [2]byte
	if _, err := io.ReadFull(reader, head[:]); err != nil {
		s.fail(err)
		return
	}
	if head[0] != tuicVersion || head[1] != tuicCommandConnect {
		s.fail(errors.New("tuic test: the stream does not start with a connect command"))
		return
	}
	target, err := readTUICAddress(reader)
	if err != nil {
		s.fail(err)
		return
	}
	s.mu.Lock()
	s.targets = append(s.targets, target)
	s.mu.Unlock()
	_, _ = io.Copy(stream, reader)
}

func (s *tuicTestServer) echoDatagrams(conn *quic.Conn) {
	for {
		payload, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			return
		}
		if len(payload) < 10 {
			continue
		}
		if err := conn.SendDatagram(payload); err != nil {
			return
		}
	}
}

func mustTUIC(t *testing.T, address, uuid, password string, roots *x509.CertPool) *TUIC {
	t.Helper()
	target, err := ParseTarget(address)
	if err != nil {
		t.Fatalf("parse %q: %v", address, err)
	}
	dialer, err := NewTUIC(TUICOptions{
		Server: target.Host, Port: int(target.Port),
		UUID: uuid, Password: password,
		TLS: testTLSOptions(t, "h3", roots), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewTUIC: %v", err)
	}
	t.Cleanup(func() { _ = dialer.Close() })
	return dialer
}

func TestTUICRoundTrip(t *testing.T) {
	server := startTUICServer(t, testTUICPassword)
	dialer := mustTUIC(t, server.addr, testTUICUUID, testTUICPassword, server.roots)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "example.test:443")
	if err != nil {
		t.Fatalf("DialContext: %v (server: %v)", err, server.Failures())
	}
	defer conn.Close()
	assertEcho(t, conn, []byte("hello tuic"))

	if targets := server.Targets(); len(targets) != 1 || targets[0].String() != "example.test:443" {
		t.Fatalf("targets = %v", targets)
	}
}

func TestTUICUDP(t *testing.T) {
	server := startTUICServer(t, testTUICPassword)
	dialer := mustTUIC(t, server.addr, testTUICUUID, testTUICPassword, server.roots)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	packet, err := dialer.DialPacket(ctx, "198.51.100.7:5353")
	if err != nil {
		t.Fatalf("DialPacket: %v (server: %v)", err, server.Failures())
	}
	defer packet.Close()

	for _, payload := range [][]byte{[]byte("one datagram"), bytes.Repeat([]byte("tuic "), 500)} {
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

func TestTUICRejectsWrongToken(t *testing.T) {
	server := startTUICServer(t, testTUICPassword)
	dialer := mustTUIC(t, server.addr, testTUICUUID, "another password", server.roots)

	// The protocol has no authentication answer, so the failure shows up on
	// the first exchange: the peer drops the connection once its check fails.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "example.test:443")
	if err == nil {
		defer conn.Close()
		_, err = conn.Write([]byte("does it echo?"))
		if err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Read(make([]byte, 32))
		}
	}
	if err == nil {
		t.Fatal("a connection with a wrong token carried traffic")
	}
	failures := server.Failures()
	if len(failures) == 0 || !strings.Contains(failures[0], "token does not match") {
		t.Fatalf("server failures = %v", failures)
	}
}

func TestTUICOptions(t *testing.T) {
	tests := []struct {
		name string
		spec Spec
		want string
	}{
		{
			name: "uuid is required",
			spec: Spec{Type: "tuic", Server: "h", Port: 443, Args: []string{"h", "443"}},
			want: "needs a uuid",
		},
		{
			name: "password is required",
			spec: Spec{Type: "tuic", Server: "h", Port: 443, Args: []string{"h", "443", testTUICUUID}},
			want: "needs a password",
		},
		{
			name: "bad uuid",
			spec: Spec{Type: "tuic", Server: "h", Port: 443, Args: []string{"h", "443", "nope", "pw"}},
			want: "uuid",
		},
		{
			name: "tls keys are not configurable",
			spec: Spec{Type: "tuic", Server: "h", Port: 443,
				Args: []string{"h", "443", testTUICUUID, "pw", "tls=true"}},
			want: "tls= is not accepted",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newTUICFromSpec(test.spec)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want %q", err, test.want)
			}
		})
	}
}
