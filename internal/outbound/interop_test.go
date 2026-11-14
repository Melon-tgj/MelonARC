//go:build !windows

package outbound

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The interop tests dial a reference implementation of each protocol instead of
// the test peers in testserver_test.go, so a passing protocol does not only
// interoperate with itself. The reference binaries are deliberately outside the
// repository: they come from their projects' release pages, are checked against
// the checksums those releases publish, and are pointed at with
// MELONARC_INTEROP_DIR. Every test here skips when that variable is unset, so a
// checkout without the downloads still builds and passes.
//
// What a test proves: our client completed the protocol's real handshake
// against code we did not write, and carried bytes through it to an echo
// endpoint. What it does not prove: any behaviour the two implementations both
// choose not to exercise, and anything about a protocol whose reference server
// needs a capability this environment denies (see the UDP and QUIC notes).
const interopDirEnv = "MELONARC_INTEROP_DIR"

// interopBinary resolves the reference server for a protocol. The directory is
// keyed by protocol, not by implementation: a test needs some server that
// speaks the protocol, and which implementation provides it is a property of
// the machine rather than of the code. The expected layout is
//
//	$MELONARC_INTEROP_DIR/<protocol>/server
//
// A missing binary is a skip rather than a failure, so a checkout without the
// downloads still builds and passes.
func interopBinary(t *testing.T, protocol string) string {
	t.Helper()
	dir := strings.TrimSpace(os.Getenv(interopDirEnv))
	if dir == "" {
		t.Skipf("%s is not set; interop needs a reference server for this protocol", interopDirEnv)
	}
	path := filepath.Join(dir, protocol, "server")
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		t.Skipf("%s/server is missing under %s; no reference server was provided for this protocol", protocol, dir)
	}
	return path
}

// lockedBuffer collects a server's output so a failure can show what the other
// side said.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// refServer is a reference implementation running as a test server.
type refServer struct {
	name string
	cmd  *exec.Cmd
	logs *lockedBuffer
}

// startReference runs a reference server with args and arranges for it to be
// killed when the test ends. Its output is printed only when the test failed,
// so a passing run stays quiet.
func startReference(t *testing.T, name, bin string, args ...string) *refServer {
	t.Helper()
	s := &refServer{name: name, logs: &lockedBuffer{}}
	s.cmd = exec.Command(bin, args...)
	s.cmd.Stdout = s.logs
	s.cmd.Stderr = s.logs
	if err := s.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
		if t.Failed() {
			t.Logf("%s output:\n%s", name, s.logs.String())
		}
	})
	return s
}

// waitForLog blocks until the server prints marker. Servers that listen on UDP
// cannot be probed with a connect, so their readiness signal is the line they
// print after binding.
func (s *refServer) waitForLog(t *testing.T, marker string) {
	t.Helper()
	deadline := time.Now().Add(interopStartTimeout)
	for time.Now().Before(deadline) {
		if strings.Contains(s.logs.String(), marker) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s did not report %q within %s; output:\n%s", s.name, marker, interopStartTimeout, s.logs.String())
}

// interopStartTimeout bounds how long a reference server may take to become
// ready. A cold start of a 30 MB binary is well under a second here.
const interopStartTimeout = 15 * time.Second

// waitForTCP blocks until addr accepts a connection, which is how a server that
// listens on TCP reports readiness.
func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(interopStartTimeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s did not start listening within %s", addr, interopStartTimeout)
}

// freePort reserves a loopback port for a reference server. The listener is
// closed before the server starts, so the port is free by the time it binds;
// the window between the two is a few statements wide and a collision only
// means the server fails to start, which the test reports.
func freePort(t *testing.T, network string) int {
	t.Helper()
	switch network {
	case "tcp":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve a tcp port: %v", err)
		}
		defer ln.Close()
		return ln.Addr().(*net.TCPAddr).Port
	case "udp":
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve a udp port: %v", err)
		}
		defer pc.Close()
		return pc.LocalAddr().(*net.UDPAddr).Port
	default:
		t.Fatalf("freePort: unsupported network %q", network)
		return 0
	}
}

// writeInteropFile writes one generated fixture below dir and returns its path.
// The fixtures are built here rather than kept as files so a template cannot
// drift from the values the test dials with.
func writeInteropFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// interopCertificate writes a self-signed certificate for 127.0.0.1 and
// localhost and returns the two file paths a reference server needs plus a pool
// that trusts it. The certificate is its own authority, so the pool is what the
// client would otherwise get from a system store.
func interopCertificate(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "melonarc interop"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
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
	certFile = writeInteropFile(t, dir, "cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	keyFile = writeInteropFile(t, dir, "key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(parsed)
	return certFile, keyFile, pool
}

// trustPool is the TLS escape hatch every secured interop test uses: the
// reference server presents a certificate this test signed, and the dialer
// trusts exactly that.
func trustPool(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// mustInteropDialer builds the dialer of a [Proxy] line through the same
// registry the daemon uses, so the options a link or a configuration would
// produce are what the reference server sees.
func mustInteropDialer(t *testing.T, spec Spec) Dialer {
	t.Helper()
	d, err := New(spec)
	if err != nil {
		t.Fatalf("build %s dialer: %v", spec.Type, err)
	}
	return d
}

// datagramRoundTrip sends one payload to target through a datagram association
// and checks it comes back unchanged.
func datagramRoundTrip(t *testing.T, d Dialer, target string, want []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), interopDialTimeout)
	defer cancel()
	packet, err := d.DialPacket(ctx, target)
	if err != nil {
		t.Fatalf("DialPacket %s: %v", target, err)
	}
	defer packet.Close()
	if err := packet.SetDeadline(time.Now().Add(interopDialTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := packet.Write(want); err != nil {
		t.Fatalf("write datagram: %v", err)
	}
	buf := make([]byte, len(want)+64)
	n, err := packet.Read(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("datagram echo = %q, want %q", buf[:n], want)
	}
}

// expectNoEcho checks that a dialer whose credentials the server rejects does
// not get an echo back. Some protocols fail at dial time and some fail on the
// first byte; both are accepted here, a successful round trip is not.
func expectNoEcho(t *testing.T, d Dialer, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), interopDialTimeout)
	defer cancel()
	conn, err := d.DialContext(ctx, target)
	if err != nil {
		return
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		return
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err == nil {
		t.Fatalf("the server echoed to a client it should have rejected")
	}
}

// interopDialTimeout bounds one dial or round trip against a reference server.
const interopDialTimeout = 10 * time.Second
