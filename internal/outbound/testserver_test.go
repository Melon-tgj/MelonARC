package outbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// testServerDeadline bounds every test connection so a broken expectation fails
// the test instead of hanging it.
const testServerDeadline = 10 * time.Second

// testSOCKSRequest is one command a test server received.
type testSOCKSRequest struct {
	Command byte
	Target  Target
}

// testSOCKS5 is a minimal SOCKS5 server for the loopback tests. It implements
// both authentication modes, CONNECT and UDP ASSOCIATE, and records the wire
// details so a test can check what the client actually sent.
type testSOCKS5 struct {
	addr     string
	username string
	password string

	mu       sync.Mutex
	greeting []byte
	user     string
	pass     string
	requests []testSOCKSRequest
}

// startTestSOCKS5 serves SOCKS5 on a loopback port. A non-empty username makes
// username and password authentication mandatory.
func startTestSOCKS5(t *testing.T, username, password string) *testSOCKS5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testSOCKS5{addr: ln.Addr().String(), username: username, password: password}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return s
}

// Greeting returns the method negotiation the client sent.
func (s *testSOCKS5) Greeting() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.greeting...)
}

// Credentials returns the username and password the client sent, if any.
func (s *testSOCKS5) Credentials() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.user, s.pass
}

// Requests returns the commands the client sent.
func (s *testSOCKS5) Requests() []testSOCKSRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]testSOCKSRequest(nil), s.requests...)
}

func (s *testSOCKS5) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testServerDeadline))
	if err := s.handshake(conn); err != nil {
		return
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return
	}
	host, err := readAddress(conn, head[3])
	if err != nil {
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return
	}
	target := Target{Host: host, Port: binary.BigEndian.Uint16(port[:])}
	s.mu.Lock()
	s.requests = append(s.requests, testSOCKSRequest{Command: head[1], Target: target})
	s.mu.Unlock()

	switch head[1] {
	case cmdConnect:
		s.handleConnect(conn, target)
	case cmdUDPAssociate:
		s.handleAssociate(conn)
	default:
		s.reply(conn, 0x07, nil)
	}
}

func (s *testSOCKS5) handshake(conn net.Conn) error {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	if head[0] != socks5Version {
		return errors.New("unexpected version")
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	s.mu.Lock()
	s.greeting = append([]byte{head[0], head[1]}, methods...)
	s.mu.Unlock()

	selected := byte(methodNoAuth)
	if s.username != "" {
		if !bytes.Contains(methods, []byte{methodUserPassword}) {
			_, _ = conn.Write([]byte{socks5Version, methodNoAcceptable})
			return errors.New("client did not offer username and password")
		}
		selected = methodUserPassword
	}
	if _, err := conn.Write([]byte{socks5Version, selected}); err != nil {
		return err
	}
	if selected == methodNoAuth {
		return nil
	}

	var version [2]byte
	if _, err := io.ReadFull(conn, version[:]); err != nil {
		return err
	}
	user := make([]byte, int(version[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	var passwordLen [1]byte
	if _, err := io.ReadFull(conn, passwordLen[:]); err != nil {
		return err
	}
	pass := make([]byte, int(passwordLen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}
	var status byte
	if string(user) != s.username || string(pass) != s.password {
		status = 1
	}
	s.mu.Lock()
	s.user, s.pass = string(user), string(pass)
	s.mu.Unlock()
	if _, err := conn.Write([]byte{authVersion, status}); err != nil {
		return err
	}
	if status != 0 {
		return errors.New("bad credentials")
	}
	return nil
}

func (s *testSOCKS5) reply(conn net.Conn, code byte, bound net.Addr) {
	out := []byte{socks5Version, code, 0x00}
	if udp, ok := bound.(*net.UDPAddr); ok {
		out = AppendAddress(out, Target{Host: udp.IP.String(), Port: uint16(udp.Port)})
	} else {
		out = AppendAddress(out, Target{Host: "0.0.0.0"})
	}
	_, _ = conn.Write(out)
}

func (s *testSOCKS5) handleConnect(conn net.Conn, target Target) {
	remote, err := net.DialTimeout("tcp", target.String(), 2*time.Second)
	if err != nil {
		s.reply(conn, 0x05, nil)
		return
	}
	defer remote.Close()
	s.reply(conn, 0x00, nil)
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(remote, conn)
		_ = remote.Close()
		close(done)
	}()
	_, _ = io.Copy(conn, remote)
	_ = remote.Close()
	<-done
}

func (s *testSOCKS5) handleAssociate(conn net.Conn) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		s.reply(conn, 0x01, nil)
		return
	}
	defer udp.Close()
	s.reply(conn, 0x00, udp.LocalAddr())
	// The association lives as long as the control connection.
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		_ = udp.Close()
	}()

	var client *net.UDPAddr
	buf := make([]byte, 65535)
	for {
		n, from, err := udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if client == nil {
			client = from
		}
		if from.String() == client.String() {
			payload, dest, frag, err := DecodeUDPDatagram(buf[:n])
			if err != nil || frag != 0 {
				continue
			}
			remote, err := net.ResolveUDPAddr("udp", dest.String())
			if err != nil {
				continue
			}
			_, _ = udp.WriteToUDP(payload, remote)
			continue
		}
		// A reply from a destination travels back to the client with the
		// source address in the SOCKS5 UDP header.
		out := make([]byte, 0, MaxUDPHeaderLen+len(buf[:n]))
		out = append(out, 0, 0, 0)
		out = AppendAddress(out, Target{Host: from.IP.String(), Port: uint16(from.Port)})
		out = append(out, buf[:n]...)
		_, _ = udp.WriteToUDP(out, client)
	}
}

// testHTTPRequest is one request a test proxy received.
type testHTTPRequest struct {
	Method     string
	Host       string
	AuthHeader string
}

// testHTTPProxy is a minimal HTTP CONNECT proxy for the loopback tests, with
// optional basic authentication.
type testHTTPProxy struct {
	addr     string
	username string
	password string

	mu       sync.Mutex
	requests []testHTTPRequest
}

// startTestHTTPProxy serves plain HTTP CONNECT on a loopback port.
func startTestHTTPProxy(t *testing.T, username, password string) *testHTTPProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return serveTestHTTPProxy(t, ln, username, password)
}

// startTestHTTPSProxy serves HTTP CONNECT behind TLS, which is the HTTPS
// variant of the outbound, and returns the pool that trusts its certificate.
func startTestHTTPSProxy(t *testing.T, username, password string) (*testHTTPProxy, *x509.CertPool) {
	t.Helper()
	cert, pool := testCertificate(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	return serveTestHTTPProxy(t, ln, username, password), pool
}

func serveTestHTTPProxy(t *testing.T, ln net.Listener, username, password string) *testHTTPProxy {
	t.Helper()
	p := &testHTTPProxy{addr: ln.Addr().String(), username: username, password: password}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return p
}

// Requests returns the requests the client sent.
func (p *testHTTPProxy) Requests() []testHTTPRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]testHTTPRequest(nil), p.requests...)
}

func (p *testHTTPProxy) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testServerDeadline))
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.requests = append(p.requests, testHTTPRequest{
		Method:     req.Method,
		Host:       req.Host,
		AuthHeader: req.Header.Get("Proxy-Authorization"),
	})
	p.mu.Unlock()

	if p.username != "" {
		user, pass, ok := parseTestProxyAuth(req.Header.Get("Proxy-Authorization"))
		if !ok || user != p.username || pass != p.password {
			_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
				"Proxy-Authenticate: Basic realm=\"melonarc test\"\r\nContent-Length: 0\r\n\r\n")
			return
		}
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	remote, err := net.DialTimeout("tcp", req.Host, 2*time.Second)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer remote.Close()
	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	go func() {
		// The buffered reader may already hold tunnel bytes.
		_, _ = io.Copy(remote, reader)
		_ = remote.Close()
	}()
	_, _ = io.Copy(conn, remote)
}

// parseTestProxyAuth decodes a Proxy-Authorization header.
func parseTestProxyAuth(header string) (user, pass string, ok bool) {
	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", "", false
	}
	user, pass, found = strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return user, pass, true
}

// startTCPEcho serves an echo endpoint on a loopback port.
func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(testServerDeadline))
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// startUDPEcho serves a datagram echo endpoint on a loopback port.
func startUDPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

// startScriptedServer accepts one connection and runs fn on it, which is how a
// test drives a dialer against exact bytes.
func startScriptedServer(t *testing.T, fn func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(testServerDeadline))
		fn(conn)
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// mustSocks5 builds a SOCKS5 dialer pointed at address.
func mustSocks5(t *testing.T, address, username, password string) *SOCKS5 {
	t.Helper()
	target, err := ParseTarget(address)
	if err != nil {
		t.Fatalf("parse %q: %v", address, err)
	}
	dialer, err := NewSOCKS5(SOCKS5Options{
		Server:   target.Host,
		Port:     int(target.Port),
		Username: username,
		Password: password,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5: %v", err)
	}
	return dialer
}

// mustHTTPProxy builds an HTTP CONNECT dialer pointed at address.
func mustHTTPProxy(t *testing.T, address, username, password string, useTLS bool, cfg *tls.Config) *HTTPProxy {
	t.Helper()
	target, err := ParseTarget(address)
	if err != nil {
		t.Fatalf("parse %q: %v", address, err)
	}
	dialer, err := NewHTTPProxy(HTTPProxyOptions{
		Server:    target.Host,
		Port:      int(target.Port),
		Username:  username,
		Password:  password,
		TLS:       useTLS,
		TLSConfig: cfg,
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTPProxy: %v", err)
	}
	return dialer
}

// testCertificate builds a self-signed certificate for 127.0.0.1 plus the pool
// that trusts it.
func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "melonarc test proxy"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return cert, pool
}

// datagramSendAllowed reports whether this environment lets a datagram socket
// send to an address it is not connected to, which is what every UDP relay
// server has to do. Some sandboxes deny sendto outright; there the UDP relay
// tests skip instead of failing for a reason unrelated to the code.
func datagramSendAllowed(t *testing.T) bool {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Logf("skipping datagram test: cannot bind a udp socket: %v", err)
		return false
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Logf("skipping datagram test: cannot dial a udp socket: %v", err)
		return false
	}
	defer client.Close()
	from := client.LocalAddr().(*net.UDPAddr)
	if _, err := server.WriteToUDP([]byte("probe"), from); err != nil {
		t.Logf("skipping datagram test: this environment denies sendto to an unconnected peer: %v", err)
		return false
	}
	return true
}

// dialThrough opens a stream through d within a bounded context.
func dialThrough(t *testing.T, d Dialer, address string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	conn, err := d.DialContext(ctx, address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
