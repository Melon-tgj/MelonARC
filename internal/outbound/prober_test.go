package outbound

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingDialer records how a probe reached the network.
type countingDialer struct {
	inner Dialer

	mu      sync.Mutex
	dials   int
	address string
}

func (c *countingDialer) DialContext(ctx context.Context, address string) (net.Conn, error) {
	c.mu.Lock()
	c.dials++
	c.address = address
	c.mu.Unlock()
	return c.inner.DialContext(ctx, address)
}

func (c *countingDialer) DialPacket(ctx context.Context, address string) (PacketConn, error) {
	return c.inner.DialPacket(ctx, address)
}

func (c *countingDialer) count() (int, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dials, c.address
}

// probeURL starts a local HTTP server and returns its URL.
func probeURL(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server.URL
}

func TestProberSucceedsThroughDirect(t *testing.T) {
	url := probeURL(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != probeUserAgent {
			t.Errorf("User-Agent = %q, want %q", r.Header.Get("User-Agent"), probeUserAgent)
		}
		_, _ = w.Write([]byte("ok"))
	})
	prober, err := NewProber(url, func(string) (Dialer, error) { return NewDirect(), nil })
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	latency, err := prober.Probe(ctx, "DIRECT")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if latency <= 0 {
		t.Fatalf("latency = %v, want a positive measurement", latency)
	}
	if latency > 5*time.Second {
		t.Fatalf("latency = %v, want it bounded by the timeout", latency)
	}
}

func TestProberUsesTheMemberDialer(t *testing.T) {
	url := probeURL(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	counter := &countingDialer{inner: NewDirect()}
	prober, err := NewProber(url, func(member string) (Dialer, error) {
		if member != "proxied" {
			t.Errorf("resolver asked for %q, want proxied", member)
		}
		return counter, nil
	})
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	if _, err := prober.Probe(context.Background(), "proxied"); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	dials, address := counter.count()
	if dials != 1 {
		t.Fatalf("dials = %d, want 1: the probe did not go through the member", dials)
	}
	wantHost := strings.TrimPrefix(url, "http://")
	if address != wantHost {
		t.Fatalf("dial address = %q, want %q", address, wantHost)
	}
}

func TestProberFailsOnAnErrorStatus(t *testing.T) {
	url := probeURL(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	prober, err := NewProber(url, func(string) (Dialer, error) { return NewDirect(), nil })
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	latency, err := prober.Probe(context.Background(), "DIRECT")
	if err == nil {
		t.Fatal("Probe succeeded on a 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %v, want the status code", err)
	}
	if latency != 0 {
		t.Fatalf("latency = %v, want zero on failure", latency)
	}
}

func TestProberAcceptsARedirect(t *testing.T) {
	url := probeURL(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(http.StatusFound)
	})
	prober, err := NewProber(url, func(string) (Dialer, error) { return NewDirect(), nil })
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	// A redirect proves the path works; the probe must not chase it.
	if _, err := prober.Probe(context.Background(), "DIRECT"); err != nil {
		t.Fatalf("Probe: %v", err)
	}
}

func TestProberFailsWhenTheDialFails(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()

	prober, err := NewProber("http://"+address+"/", func(string) (Dialer, error) { return NewDirect(), nil })
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	if _, err := prober.Probe(context.Background(), "DIRECT"); err == nil {
		t.Fatal("Probe succeeded against a closed port")
	}
}

func TestProberHonoursTheTimeout(t *testing.T) {
	release := make(chan struct{})
	url := probeURL(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
	})
	t.Cleanup(func() { close(release) })

	prober, err := NewProber(url, func(string) (Dialer, error) { return NewDirect(), nil })
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := prober.Probe(ctx, "DIRECT"); err == nil {
		t.Fatal("Probe succeeded although the server never answered")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("probe took %v, want it bounded by the context", elapsed)
	}
}

func TestProberReportsResolverFailures(t *testing.T) {
	url := probeURL(t, func(w http.ResponseWriter, _ *http.Request) {})
	failure := errors.New("member has no dialer")
	prober, err := NewProber(url, func(string) (Dialer, error) { return nil, failure })
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	if _, err := prober.Probe(context.Background(), "broken"); !errors.Is(err, failure) {
		t.Fatalf("error = %v, want the resolver failure", err)
	}
}

func TestProberRejectsBadInput(t *testing.T) {
	resolver := func(string) (Dialer, error) { return NewDirect(), nil }
	for _, raw := range []string{"", "ftp://example.com/x", "http://", "://bad"} {
		if _, err := NewProber(raw, resolver); err == nil {
			t.Fatalf("NewProber(%q) succeeded", raw)
		}
	}
	if _, err := NewProber("http://example.com", nil); err == nil {
		t.Fatal("NewProber accepted a nil resolver")
	}
	prober, err := NewProber("http://example.com", resolver)
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	if _, err := prober.Probe(context.Background(), ""); err == nil {
		t.Fatal("Probe accepted an empty member name")
	}
}
