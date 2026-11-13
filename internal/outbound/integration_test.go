package outbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/policy"
)

// echoRoundTrip writes and reads a payload over an established stream. Writing
// happens in the background so a payload larger than the socket buffers cannot
// deadlock the test.
func echoRoundTrip(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(testServerDeadline)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeDone <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo differs: got %d bytes, want %d", len(got), len(payload))
	}
}

// payload builds a deterministic block of the given size.
func payload(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

func TestSOCKS5CarriesBulkTCP(t *testing.T) {
	server := startTestSOCKS5(t, "", "")
	echo := startTCPEcho(t)
	conn := dialThrough(t, mustSocks5(t, server.addr, "", ""), echo)
	echoRoundTrip(t, conn, payload(64<<10))
}

func TestSOCKS5CarriesBulkTCPWithAuthentication(t *testing.T) {
	server := startTestSOCKS5(t, "alice", "s3cret")
	echo := startTCPEcho(t)
	conn := dialThrough(t, mustSocks5(t, server.addr, "alice", "s3cret"), echo)
	echoRoundTrip(t, conn, payload(16<<10))
}

func TestSOCKS5RejectsAClientWithoutCredentials(t *testing.T) {
	server := startTestSOCKS5(t, "alice", "s3cret")
	dialer := mustSocks5(t, server.addr, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := dialer.DialContext(ctx, "example.com:80"); err == nil {
		t.Fatal("dial without credentials succeeded against a server that requires them")
	}
}

func TestSOCKS5CarriesSeveralDatagrams(t *testing.T) {
	if !datagramSendAllowed(t) {
		t.Skip("the environment does not allow the relay to answer")
	}
	server := startTestSOCKS5(t, "", "")
	echo := startUDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	packet, err := mustSocks5(t, server.addr, "", "").DialPacket(ctx, echo)
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer packet.Close()
	if err := packet.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	for _, want := range []string{"one", "two", "three"} {
		if _, err := packet.Write([]byte(want)); err != nil {
			t.Fatalf("write %q: %v", want, err)
		}
		buf := make([]byte, 64)
		n, err := packet.Read(buf)
		if err != nil {
			t.Fatalf("read %q: %v", want, err)
		}
		if string(buf[:n]) != want {
			t.Fatalf("echo = %q, want %q", buf[:n], want)
		}
	}
}

func TestSOCKS5CarriesDatagramsToAName(t *testing.T) {
	if !datagramSendAllowed(t) {
		t.Skip("the environment does not allow the relay to answer")
	}
	server := startTestSOCKS5(t, "", "")
	echo := startUDPEcho(t)
	target, err := ParseTarget(echo)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	// The name must survive the SOCKS5 UDP header; the server resolves it.
	named := net.JoinHostPort("localhost", strconv.Itoa(int(target.Port)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	packet, err := mustSocks5(t, server.addr, "", "").DialPacket(ctx, named)
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer packet.Close()
	if err := packet.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := packet.Write([]byte("named")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := packet.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "named" {
		t.Fatalf("echo = %q, want named", buf[:n])
	}
}

func TestHTTPProxyCarriesBulkTCP(t *testing.T) {
	server := startTestHTTPProxy(t, "", "")
	echo := startTCPEcho(t)
	conn := dialThrough(t, mustHTTPProxy(t, server.addr, "", "", false, nil), echo)
	echoRoundTrip(t, conn, payload(64<<10))
}

func TestHTTPProxyWithAuthenticationCarriesBulkTCP(t *testing.T) {
	server := startTestHTTPProxy(t, "alice", "s3cret")
	echo := startTCPEcho(t)
	conn := dialThrough(t, mustHTTPProxy(t, server.addr, "alice", "s3cret", false, nil), echo)
	echoRoundTrip(t, conn, payload(16<<10))
}

func TestHTTPProxyRejectsWrongCredentials(t *testing.T) {
	server := startTestHTTPProxy(t, "alice", "s3cret")
	proxy := mustHTTPProxy(t, server.addr, "alice", "wrong", false, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := proxy.DialContext(ctx, "example.com:443"); err == nil {
		t.Fatal("dial with a wrong password succeeded")
	}
}

func TestHTTPSProxySecuresTheHopBeforeConnect(t *testing.T) {
	server, pool := startTestHTTPSProxy(t, "alice", "s3cret")
	echo := startTCPEcho(t)
	proxy := mustHTTPProxy(t, server.addr, "alice", "s3cret", true, &tls.Config{RootCAs: pool})
	conn := dialThrough(t, proxy, echo)
	echoRoundTrip(t, conn, payload(8<<10))
}

func TestHTTPSProxyFailsWithoutTrust(t *testing.T) {
	server, _ := startTestHTTPSProxy(t, "", "")
	echo := startTCPEcho(t)
	proxy := mustHTTPProxy(t, server.addr, "", "", true, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := proxy.DialContext(ctx, echo); err == nil {
		t.Fatal("dial succeeded although the certificate is not trusted")
	}
}

func TestProbeThroughSOCKS5(t *testing.T) {
	server := startTestSOCKS5(t, "", "")
	url := probeURL(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	prober, err := NewProber(url, func(string) (Dialer, error) {
		return mustSocks5(t, server.addr, "", ""), nil
	})
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	latency, err := prober.Probe(context.Background(), "socks")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if latency <= 0 {
		t.Fatalf("latency = %v, want a positive measurement", latency)
	}
	requests := server.Requests()
	if len(requests) != 1 || requests[0].Command != cmdConnect {
		t.Fatalf("requests = %+v, want one CONNECT", requests)
	}
}

func TestProbeThroughHTTPProxy(t *testing.T) {
	server := startTestHTTPProxy(t, "", "")
	url := probeURL(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	prober, err := NewProber(url, func(string) (Dialer, error) {
		return mustHTTPProxy(t, server.addr, "", "", false, nil), nil
	})
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	if _, err := prober.Probe(context.Background(), "http"); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if requests := server.Requests(); len(requests) != 1 || requests[0].Method != http.MethodConnect {
		t.Fatalf("requests = %+v, want one CONNECT", requests)
	}
}

func TestProbeThroughHTTPSProxy(t *testing.T) {
	server, pool := startTestHTTPSProxy(t, "", "")
	url := probeURL(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	prober, err := NewProber(url, func(string) (Dialer, error) {
		return mustHTTPProxy(t, server.addr, "", "", true, &tls.Config{RootCAs: pool}), nil
	})
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	if _, err := prober.Probe(context.Background(), "https"); err != nil {
		t.Fatalf("Probe: %v", err)
	}
}

func TestProbeFailsThroughAProxyWhenTheTargetIsDown(t *testing.T) {
	server := startTestSOCKS5(t, "", "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := listener.Addr().String()
	_ = listener.Close()

	prober, err := NewProber("http://"+dead+"/", func(string) (Dialer, error) {
		return mustSocks5(t, server.addr, "", ""), nil
	})
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	if _, err := prober.Probe(context.Background(), "socks"); err == nil {
		t.Fatal("Probe succeeded although the target is down")
	}
}

func TestFallbackMovesAwayFromAnUnusableMember(t *testing.T) {
	url := probeURL(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	prober, err := NewProber(url, func(member string) (Dialer, error) {
		if member == "future" {
			return &Unsupported{Protocol: "vmess"}, nil
		}
		return NewDirect(), nil
	})
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	group, err := policy.NewFallback("failover", []string{"future", "DIRECT"}, prober, time.Hour, 5*time.Second)
	if err != nil {
		t.Fatalf("NewFallback: %v", err)
	}
	defer group.Close()
	group.Check(context.Background())
	if got := group.Active(); got != "DIRECT" {
		t.Fatalf("active = %q, want DIRECT: the probe did not mark the unusable member down", got)
	}
	status := group.Status()
	if len(status.Members) != 2 || status.Members[0].Healthy {
		t.Fatalf("status = %+v, want the first member unhealthy", status)
	}
	if !status.Members[1].Healthy || status.Members[1].Latency <= 0 {
		t.Fatalf("status = %+v, want the second member healthy with a latency", status)
	}
}

func TestURLTestSkipsAnUnusableMember(t *testing.T) {
	url := probeURL(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	prober, err := NewProber(url, func(member string) (Dialer, error) {
		if member == "future" {
			return &Unsupported{Protocol: "vmess"}, nil
		}
		return NewDirect(), nil
	})
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	group, err := policy.NewURLTest("fastest", []string{"future", "DIRECT"}, prober,
		time.Hour, 5*time.Second, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewURLTest: %v", err)
	}
	defer group.Close()
	group.Check(context.Background())
	if got := group.Active(); got != "DIRECT" {
		t.Fatalf("active = %q, want DIRECT", got)
	}
}
