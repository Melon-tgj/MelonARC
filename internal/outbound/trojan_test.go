package outbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

const testTrojanPassword = "phase9-trojan-secret"

type testTrojanServer struct {
	addr      string
	pool      *x509.CertPool
	mu        sync.Mutex
	snapshots []string

	negotiated string
	serverName string
}

// startTestTrojan is a self-written TLS Trojan server. It checks the password
// hash and the request framing, relays CONNECT to a real loopback echo and
// answers UDP ASSOCIATE packets in the protocol's datagram framing.
func startTestTrojan(t *testing.T, password string, protocols []string) *testTrojanServer {
	t.Helper()
	cert, pool := testCertificate(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   protocols,
	})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	s := &testTrojanServer{addr: ln.Addr().String(), pool: pool}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(testServerDeadline))
				if secured, ok := c.(*tls.Conn); ok {
					// The handshake is lazy on the server side; drive it
					// before reading the negotiated state.
					if err := secured.Handshake(); err != nil {
						return
					}
					state := secured.ConnectionState()
					s.record(state.NegotiatedProtocol, state.ServerName)
				}
				serveTestTrojan(c, password)
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	return s
}

func (s *testTrojanServer) record(negotiated, serverName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.negotiated, s.serverName = negotiated, serverName
	s.snapshots = append(s.snapshots, negotiated+"|"+serverName)
}

func (s *testTrojanServer) recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.snapshots...)
}

func trojanPasswordHash(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
}

func serveTestTrojan(conn net.Conn, password string) {
	r := bufio.NewReader(conn)
	hash := make([]byte, 56)
	if _, err := io.ReadFull(r, hash); err != nil {
		return
	}
	if string(hash) != trojanPasswordHash(password) {
		return
	}
	var crlf [2]byte
	if _, err := io.ReadFull(r, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
		return
	}
	var command [1]byte
	if _, err := io.ReadFull(r, command[:]); err != nil {
		return
	}
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return
	}
	host, err := readAddress(r, atyp[0])
	if err != nil {
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return
	}
	if _, err := io.ReadFull(r, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
		return
	}
	target := Target{Host: host, Port: binary.BigEndian.Uint16(port[:])}
	switch command[0] {
	case trojanCommandConnect:
		remote, err := net.DialTimeout("tcp", target.String(), 2*time.Second)
		if err != nil {
			return
		}
		defer remote.Close()
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(remote, r)
			_ = remote.Close()
			close(done)
		}()
		_, _ = io.Copy(conn, remote)
		<-done
	case trojanCommandUDPAssociate:
		for {
			var t [1]byte
			if _, err := io.ReadFull(r, t[:]); err != nil {
				return
			}
			from, err := readAddress(r, t[0])
			if err != nil {
				return
			}
			var tail [4]byte // source port and payload length
			if _, err := io.ReadFull(r, tail[:]); err != nil {
				return
			}
			if _, err := io.ReadFull(r, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
				return
			}
			length := int(binary.BigEndian.Uint16(tail[2:]))
			payload := make([]byte, length)
			if _, err := io.ReadFull(r, payload); err != nil {
				return
			}
			reply := AppendAddress(nil, Target{Host: from, Port: binary.BigEndian.Uint16(tail[:2])})
			reply = binary.BigEndian.AppendUint16(reply, uint16(len(payload)))
			reply = append(reply, trojanCRLF...)
			reply = append(reply, payload...)
			if _, err := conn.Write(reply); err != nil {
				return
			}
		}
	}
}

func mustTrojan(t *testing.T, address, password string, opts TLSOptions) *Trojan {
	t.Helper()
	target, err := ParseTarget(address)
	if err != nil {
		t.Fatalf("parse %q: %v", address, err)
	}
	d, err := NewTrojan(TrojanOptions{
		Server: target.Host, Port: int(target.Port), Password: password,
		TLS: opts, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewTrojan: %v", err)
	}
	return d
}

func trojanTestTLSOptions(t *testing.T, server *testTrojanServer) TLSOptions {
	t.Helper()
	return TLSOptions{Config: &tls.Config{RootCAs: server.pool}}
}

func TestTrojanTCPRoundTrip(t *testing.T) {
	echo := startTCPEcho(t)
	server := startTestTrojan(t, testTrojanPassword, nil)
	d := mustTrojan(t, server.addr, testTrojanPassword, trojanTestTLSOptions(t, server))
	conn := dialThrough(t, d, echo)
	payload := bytes.Repeat([]byte("trojan-over-tls "), 300)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo payload differs from what was written")
	}
}

func TestTrojanUDPRoundTrip(t *testing.T) {
	server := startTestTrojan(t, testTrojanPassword, nil)
	d := mustTrojan(t, server.addr, testTrojanPassword, trojanTestTLSOptions(t, server))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, err := d.DialPacket(ctx, "example.com:5353")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("trojan datagram echo")
	if _, err := pc.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 512)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("echo = %q, want %q", buf[:n], payload)
	}
}

func TestTrojanWrongPasswordFails(t *testing.T) {
	echo := startTCPEcho(t)
	server := startTestTrojan(t, testTrojanPassword, nil)
	d := mustTrojan(t, server.addr, "not-the-password", trojanTestTLSOptions(t, server))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, echo)
	if err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Write([]byte("probe"))
		if err == nil {
			var one [1]byte
			_, err = io.ReadFull(conn, one[:])
		}
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("a wrong password was accepted")
	}
}

func TestTrojanTLSBaseSNIAndALPN(t *testing.T) {
	echo := startTCPEcho(t)
	server := startTestTrojan(t, testTrojanPassword, []string{"h2"})
	opts := TLSOptions{
		Config:     &tls.Config{RootCAs: server.pool},
		ServerName: "proxy.example",
		SkipVerify: true, // the test certificate only carries the loopback IP SAN
		ALPN:       []string{"h2"},
	}
	d := mustTrojan(t, server.addr, testTrojanPassword, opts)
	conn := dialThrough(t, d, echo)
	if _, err := conn.Write([]byte("sni-alpn")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len("sni-alpn"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	// The server records what the TLS handshake actually negotiated.
	found := false
	seen := server.recorded()
	for _, snapshot := range seen {
		parts := strings.Split(snapshot, "|")
		if len(parts) == 2 && parts[0] == "h2" && parts[1] == "proxy.example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("server saw %v, want an h2 / proxy.example handshake", seen)
	}
}

func TestTrojanRejectsBadConfiguration(t *testing.T) {
	if _, err := NewTrojan(TrojanOptions{Server: "p.example", Port: 443}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("missing password error = %v, want ErrInvalidOption", err)
	}
	if _, err := New(Spec{Type: "trojan", Server: "p.example", Port: 443,
		Args: []string{"p.example", "443", "secret", "tls=true"}}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("tls= on a tls-always type error = %v, want ErrInvalidOption", err)
	}
	spec, err := New(Spec{Type: "trojan", Server: "p.example", Port: 443,
		Args: []string{"p.example", "443", "password=secret", "sni=proxy.example", "alpn=h2|http/1.1"}})
	if err != nil {
		t.Fatalf("tls options: %v", err)
	}
	tr, ok := spec.(*Trojan)
	if !ok {
		t.Fatalf("New returned %T", spec)
	}
	if !tr.tls.Enabled || tr.tls.ServerName != "proxy.example" || len(tr.tls.ALPN) != 2 {
		t.Fatalf("TLS base = %+v", tr.tls)
	}
	if tr.authHash != trojanPasswordHash("secret") {
		t.Fatal("password hash does not match the SHA-224 definition")
	}
}
