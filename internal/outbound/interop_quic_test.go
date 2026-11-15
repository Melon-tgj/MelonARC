//go:build !windows

package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// The QUIC protocols are the ones this environment can least accommodate: a
// QUIC server answers from a listening socket it never connected, and the
// sandbox this suite usually runs in denies that sendto. Where the capability
// exists the tests run in full against a reference server; where it does not,
// they still prove that the fixture reaches the production dial path and stops
// at the sandbox boundary rather than aborting inside the fixture.
//
// Two of the tests below need no reference server at all, and they are named
// TestQUICFixture* rather than TestInterop* for that reason. The gate in
// scripts/check-interop.sh counts a skipped TestInterop* case as a failure,
// because a skip there means "this protocol was not verified"; a test that
// passes on any machine with a TLS stack must not be able to make that
// judgement wrong. The TestInterop* names stay reserved for the tests that
// carry a real server's traffic.
//
// A QUIC outbound compiles its TLS options into a *tls.Config while it is
// built, so the trust roots of a locally issued certificate must be supplied
// on the spec. An older fixture changed a dialer field afterwards (which only
// worked for the stream transports) and worked around the missing roots by
// replacing the default dial function for the whole package. Neither is done
// here: dialQUICAddr is restored to the production function for these tests.

// trustSpec puts a fixture's trust roots on a spec before New builds the
// outbound. Only the QUIC constructors consume Spec.TLSConfig.
func trustSpec(spec Spec, pool *x509.CertPool) Spec {
	spec.TLSConfig = trustPool(pool)
	return spec
}

// useProductQUICDial puts the production dial function back for one test. The
// in-process QUIC tests replace it at package init to work around the same
// sandbox restriction; interop must not inherit that substitute.
func useProductQUICDial(t *testing.T) {
	t.Helper()
	original := dialQUICAddr
	dialQUICAddr = dialQUICDefault
	t.Cleanup(func() { dialQUICAddr = original })
}

// errFixtureStop is returned by the dial spy that records the TLS config.
var errFixtureStop = errors.New("fixture stopped the dial")

// quicFixtureSpecs are the two QUIC [Proxy] lines the interop tests build.
func quicFixtureSpecs(port int) []Spec {
	return []Spec{
		{
			Name: "hysteria2", Type: "hysteria2", Server: "127.0.0.1", Port: port,
			Args: []string{"127.0.0.1", strconv.Itoa(port), "password=" + interopPassword, "sni=localhost"},
		},
		{
			Name: "tuic", Type: "tuic", Server: "127.0.0.1", Port: port,
			Args: []string{"127.0.0.1", strconv.Itoa(port), "uuid=" + interopUUID, "password=" + interopPassword, "sni=localhost"},
		},
	}
}

// TestQUICFixtureInjectsTrustAtConstruction proves that the roots a fixture
// supplies on the spec arrive in the *tls.Config the product dial function
// receives. It needs no reference server.
func TestQUICFixtureInjectsTrustAtConstruction(t *testing.T) {
	dir := t.TempDir()
	_, _, pool := interopCertificate(t, dir)
	for _, spec := range quicFixtureSpecs(4443) {
		t.Run(spec.Type, func(t *testing.T) {
			d := mustInteropDialer(t, trustSpec(spec, pool))
			defer closeInteropDialer(d)

			var got *tls.Config
			original := dialQUICAddr
			dialQUICAddr = func(_ context.Context, _ string, cfg *tls.Config, _ *quic.Config) (*quic.Conn, error) {
				got = cfg
				return nil, errFixtureStop
			}
			t.Cleanup(func() { dialQUICAddr = original })

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err := d.DialContext(ctx, "127.0.0.1:9")
			if !errors.Is(err, errFixtureStop) {
				t.Fatalf("DialContext did not reach the QUIC dial hook: %v", err)
			}
			if got == nil {
				t.Fatal("the dial hook received no TLS config")
			}
			if got.RootCAs != pool {
				t.Fatal("the injected trust roots did not reach the dial hook")
			}
			if got.MinVersion != tls.VersionTLS13 {
				t.Fatalf("QUIC TLS floor = %d, want TLS 1.3", got.MinVersion)
			}
			if got.InsecureSkipVerify {
				t.Fatal("the fixture disabled certificate verification")
			}
		})
	}
}

// assertQUICDialReachesSendtoBoundary dials with the production QUIC function
// and asserts that the only failure left is the sandbox denying sendto on an
// unconnected socket. This is the failure mode that used to be a fixture abort.
func assertQUICDialReachesSendtoBoundary(t *testing.T, d Dialer, target string) error {
	t.Helper()
	useProductQUICDial(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := d.DialContext(ctx, target)
	if err == nil {
		t.Fatal("QUIC dial succeeded without a server")
	}
	if errors.Is(err, errFixtureStop) || strings.Contains(err.Error(), "has no TLS settings") {
		t.Fatalf("the fixture aborted before dialling: %v", err)
	}
	if !errors.Is(err, os.ErrPermission) &&
		!strings.Contains(err.Error(), "operation not permitted") &&
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("the dial stopped before the sendto boundary: %v", err)
	}
	return err
}

// TestQUICFixtureReachesSendtoBoundary is the local, binary-free evidence that
// the fixture is wired: with the product dial path restored, a dial fails at
// sendto EPERM instead of at trustDialer.
func TestQUICFixtureReachesSendtoBoundary(t *testing.T) {
	if datagramSendAllowed(t) {
		t.Skip("this environment permits unconnected sendto, so the sandbox boundary does not apply")
	}
	dir := t.TempDir()
	_, _, pool := interopCertificate(t, dir)
	for _, spec := range quicFixtureSpecs(4443) {
		t.Run(spec.Type, func(t *testing.T) {
			d := mustInteropDialer(t, trustSpec(spec, pool))
			defer closeInteropDialer(d)
			err := assertQUICDialReachesSendtoBoundary(t, d, "127.0.0.1:4443")
			t.Logf("%s dial stopped at the sandbox boundary: %v", spec.Type, err)
		})
	}
}

func closeInteropDialer(d Dialer) {
	if c, ok := d.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

func TestInteropHysteria2(t *testing.T) {
	server := interopBinary(t, "hysteria2")
	dir := t.TempDir()
	certFile, keyFile, pool := interopCertificate(t, dir)
	port := freePort(t, "udp")
	spec := quicFixtureSpecs(port)[0]
	dialer := mustInteropDialer(t, trustSpec(spec, pool))
	if !datagramSendAllowed(t) {
		// Build the whole fixture first so the failure point is the dial,
		// not the trust injection that used to abort here.
		assertQUICDialReachesSendtoBoundary(t, dialer, fmt.Sprintf("127.0.0.1:%d", port))
		t.Skip("this environment denies sendto on an unconnected datagram socket, which a QUIC server needs to answer")
	}
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
	useProductQUICDial(t)

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
	dir := t.TempDir()
	certFile, keyFile, pool := interopCertificate(t, dir)
	port := freePort(t, "udp")
	spec := quicFixtureSpecs(port)[1]
	dialer := mustInteropDialer(t, trustSpec(spec, pool))
	if !datagramSendAllowed(t) {
		assertQUICDialReachesSendtoBoundary(t, dialer, fmt.Sprintf("127.0.0.1:%d", port))
		t.Skip("this environment denies sendto on an unconnected datagram socket, which a QUIC server needs to answer")
	}
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
	useProductQUICDial(t)

	t.Run("tcp", func(t *testing.T) {
		conn := dialThrough(t, dialer, startTCPEcho(t))
		echoRoundTrip(t, conn, payload(32<<10))
	})

	t.Run("udp", func(t *testing.T) {
		datagramRoundTrip(t, dialer, startUDPEcho(t), []byte("tuic datagram"))
	})
}
