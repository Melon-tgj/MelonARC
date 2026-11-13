package inbound

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// recordingProxy is a SOCKS5 server that accepts without authentication,
// records every CONNECT it is asked for and answers the tunnel with a marker
// body instead of dialing. A request that came through it is therefore visible
// twice: the client reads the marker, the test reads the record.
type recordingProxy struct {
	addr string

	mu      sync.Mutex
	targets []outbound.Target
}

// startRecordingProxy serves the recording proxy on a loopback port.
func startRecordingProxy(t *testing.T) *recordingProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &recordingProxy{addr: listener.Addr().String()}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go p.handle(conn)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		wg.Wait()
	})
	return p
}

// Targets returns the CONNECT targets the proxy was asked for.
func (p *recordingProxy) Targets() []outbound.Target {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]outbound.Target(nil), p.targets...)
}

// handle serves one client: negotiation, one request, one marker response.
func (p *recordingProxy) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testDeadline))

	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{socks5Version, methodNoAuth}); err != nil {
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
	target := outbound.Target{Host: host, Port: binary.BigEndian.Uint16(port[:])}
	if head[1] != commandConnect {
		_ = writeReply(conn, replyCommandNotSupported, unspecified)
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, target)
	p.mu.Unlock()

	if err := writeReply(conn, replySucceeded, unspecified); err != nil {
		return
	}
	body := "proxied " + target.String()
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}

// fetchFunc retrieves one URL through an inbound listener.
type fetchFunc func(t *testing.T, serviceAddr, target string) string

// fetchThroughHTTPProxy retrieves a URL with a real HTTP client pointed at the
// HTTP inbound.
func fetchThroughHTTPProxy(t *testing.T, serviceAddr, target string) string {
	t.Helper()
	proxyURL, err := url.Parse("http://" + serviceAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{
		Timeout:   testDeadline,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
	}
	defer client.CloseIdleConnections()
	resp, err := client.Get("http://" + target + "/")
	if err != nil {
		t.Fatalf("GET through the http inbound: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

// fetchThroughSOCKS5 retrieves a URL with a SOCKS5 client pointed at the SOCKS5
// inbound, speaking HTTP inside the tunnel.
func fetchThroughSOCKS5(t *testing.T, serviceAddr, target string) string {
	t.Helper()
	client := mustSOCKS5Client(t, serviceAddr, "", "")
	conn := dialThrough(t, client, target)
	request := "GET / HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

// TestRuleSplitSendsEachDestinationItsOwnWay is the routing proof: two
// destinations, one rule each, and evidence on the far side of each path that
// the request really took that path.
func TestRuleSplitSendsEachDestinationItsOwnWay(t *testing.T) {
	entries := []struct {
		name  string
		fetch fetchFunc
		start func(t *testing.T, env *testEnv) string
	}{
		{
			name:  "http inbound",
			fetch: fetchThroughHTTPProxy,
			start: func(t *testing.T, env *testEnv) string {
				return startHTTPService(t, env).Addr()
			},
		},
		{
			name:  "socks5 inbound",
			fetch: fetchThroughSOCKS5,
			start: func(t *testing.T, env *testEnv) string {
				return startSOCKS5Service(t, env).Addr()
			},
		},
	}
	for _, entry := range entries {
		t.Run(entry.name, func(t *testing.T) {
			directOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "direct origin")
			}))
			defer directOrigin.Close()
			// The proxied origin must never be reached: the recording proxy
			// answers instead. A request that got here would return this body.
			proxiedOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "proxied origin")
			}))
			defer proxiedOrigin.Close()

			directAddr := hostPort(t, directOrigin.URL)
			proxiedAddr := hostPort(t, proxiedOrigin.URL)
			directPort := uint16(portOf(t, directAddr))
			proxiedPort := uint16(portOf(t, proxiedAddr))

			proxy := startRecordingProxy(t)
			dialer, err := outbound.NewSOCKS5(outbound.SOCKS5Options{
				Server:  splitHost(t, proxy.addr),
				Port:    portOf(t, proxy.addr),
				Timeout: testDeadline,
			})
			if err != nil {
				t.Fatalf("NewSOCKS5: %v", err)
			}
			env := newTestEnv(t, envOptions{
				rules: []string{
					fmt.Sprintf("DEST-PORT,%d,DIRECT", directPort),
					fmt.Sprintf("DEST-PORT,%d,via", proxiedPort),
					"FINAL,DIRECT",
				},
				leaves: map[string]outbound.Dialer{
					"DIRECT": outbound.NewDirect(),
					"via":    dialer,
				},
			})
			serviceAddr := entry.start(t, env)

			if got := entry.fetch(t, serviceAddr, directAddr); got != "direct origin" {
				t.Fatalf("direct destination answered %q, want the origin itself", got)
			}
			if got := proxy.Targets(); len(got) != 0 {
				t.Fatalf("the direct destination went through the proxy: %v", got)
			}

			got := entry.fetch(t, serviceAddr, proxiedAddr)
			want := "proxied " + proxiedAddr
			if got != want {
				t.Fatalf("proxied destination answered %q, want %q from the proxy", got, want)
			}
			targets := proxy.Targets()
			if len(targets) != 1 || targets[0].String() != proxiedAddr {
				t.Fatalf("proxy recorded %v, want exactly %s", targets, proxiedAddr)
			}
		})
	}
}

// portOf returns the port of a host:port address.
func portOf(t *testing.T, address string) int {
	t.Helper()
	target, err := outbound.ParseTarget(address)
	if err != nil {
		t.Fatalf("parse %q: %v", address, err)
	}
	return int(target.Port)
}

// splitHost returns the host of a host:port address.
func splitHost(t *testing.T, address string) string {
	t.Helper()
	target, err := outbound.ParseTarget(address)
	if err != nil {
		t.Fatalf("parse %q: %v", address, err)
	}
	return target.Host
}
