package inbound

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// directEnv is a pipeline that sends everything to DIRECT.
func directEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnv(t, envOptions{
		rules:  []string{"FINAL,DIRECT"},
		leaves: map[string]outbound.Dialer{"DIRECT": outbound.NewDirect()},
	})
}

// httpConnect performs a CONNECT handshake against a proxy and returns the
// tunnel together with the reader that already holds whatever arrived with the
// reply.
func httpConnect(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(testDeadline))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200 ") {
		t.Fatalf("CONNECT answered %q, want 200", strings.TrimSpace(status))
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" {
			return conn, reader
		}
	}
}

// TestHTTPConnectTunnel checks the whole CONNECT path: the proxy parses the
// authority, dials it through the pipeline and relays bytes both ways.
func TestHTTPConnectTunnel(t *testing.T) {
	echo := startEcho(t)
	proxy := startHTTPService(t, directEnv(t))

	conn, reader := httpConnect(t, proxy.Addr(), echo)
	payload := bytes.Repeat([]byte("tunnel "), 512)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes differ from what was sent", len(got))
	}
}

// TestHTTPConnectHalfClose checks that an end of stream from the client only
// closes the upstream write direction: the answer that follows the client's
// half close must still arrive.
func TestHTTPConnectHalfClose(t *testing.T) {
	testHalfClose(t, func(backend string) (net.Conn, io.Reader) {
		proxy := startHTTPService(t, directEnv(t))
		return httpConnect(t, proxy.Addr(), backend)
	})
}

// TestHTTPAbsoluteFormRequest checks the plain proxy request path: the request
// line carries the destination, proxy-only headers do not travel upstream, and
// the response is delimited by closing.
func TestHTTPAbsoluteFormRequest(t *testing.T) {
	seen := make(chan http.Header, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		_, _ = io.WriteString(w, "origin body")
	}))
	defer origin.Close()

	proxy := startHTTPService(t, directEnv(t))
	conn, err := net.Dial("tcp", proxy.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testDeadline))

	target := hostPort(t, origin.URL)
	request := "GET http://" + target + "/a/b?c=1 HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"Proxy-Authorization: Basic ZXZpbDplemls\r\n" +
		"X-Kept: yes\r\n\r\n"
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
	if string(body) != "origin body" {
		t.Fatalf("body = %q, want the origin body", body)
	}
	if !resp.Close {
		t.Error("the response does not announce that the connection closes")
	}
	headers := <-seen
	for _, name := range []string{"Proxy-Connection", "Proxy-Authorization"} {
		if value := headers.Get(name); value != "" {
			t.Errorf("%s travelled upstream as %q", name, value)
		}
	}
	if got := headers.Get("X-Kept"); got != "yes" {
		t.Errorf("X-Kept = %q, want the end-to-end header untouched", got)
	}
}

// TestHTTPClientThroughInbound drives both proxy modes with a real client: a
// plain request in absolute form and an HTTPS request tunneled with CONNECT.
func TestHTTPClientThroughInbound(t *testing.T) {
	plain := startHTTPOrigin(t, "plain origin")
	tlsOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secure origin")
	}))
	defer tlsOrigin.Close()

	proxy := startHTTPService(t, directEnv(t))
	proxyURL, err := url.Parse("http://" + proxy.Addr())
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	t.Run("absolute form", func(t *testing.T) {
		client := &http.Client{
			Timeout: testDeadline,
			Transport: &http.Transport{
				Proxy:             http.ProxyURL(proxyURL),
				DisableKeepAlives: true,
			},
		}
		defer client.CloseIdleConnections()
		resp, err := client.Get(plain.URL)
		if err != nil {
			t.Fatalf("GET through proxy: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "plain origin" {
			t.Fatalf("body = %q", body)
		}
	})

	t.Run("connect tunnel", func(t *testing.T) {
		client := tlsOrigin.Client()
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("client transport is %T", client.Transport)
		}
		proxied := transport.Clone()
		proxied.Proxy = http.ProxyURL(proxyURL)
		proxied.DisableKeepAlives = true
		client.Transport = proxied
		client.Timeout = testDeadline
		defer client.CloseIdleConnections()
		resp, err := client.Get(tlsOrigin.URL)
		if err != nil {
			t.Fatalf("GET through the tunnel: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "secure origin" {
			t.Fatalf("body = %q", body)
		}
	})
}

// TestHTTPExpectContinue checks that a client which waits for a go-ahead gets
// one before the body is expected.
func TestHTTPExpectContinue(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "got %s", body)
	}))
	defer origin.Close()

	proxy := startHTTPService(t, directEnv(t))
	conn, err := net.Dial("tcp", proxy.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testDeadline))

	target := hostPort(t, origin.URL)
	head := "POST http://" + target + "/echo HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"Content-Length: 5\r\n" +
		"Expect: 100-continue\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatalf("write head: %v", err)
	}
	reader := bufio.NewReader(conn)
	interim, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read interim response: %v", err)
	}
	interim.Body.Close()
	if interim.StatusCode != http.StatusContinue {
		t.Fatalf("interim status = %d, want 100 Continue", interim.StatusCode)
	}
	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatalf("write body: %v", err)
	}
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "got hello" {
		t.Fatalf("body = %q, want the echoed request body", body)
	}
}

// TestHTTPRequestErrors covers the requests an HTTP proxy must refuse without
// dialing anything.
func TestHTTPRequestErrors(t *testing.T) {
	tests := []struct {
		name    string
		rule    string
		request func(proxyAddr string) string
		want    int
	}{
		{
			name: "origin form request",
			rule: "FINAL,DIRECT",
			request: func(string) string {
				return "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
			},
			want: http.StatusBadRequest,
		},
		{
			name: "connect without a port",
			rule: "FINAL,DIRECT",
			request: func(string) string {
				return "CONNECT example.test HTTP/1.1\r\nHost: example.test\r\n\r\n"
			},
			want: http.StatusBadRequest,
		},
		{
			name: "rejected by a rule",
			rule: "FINAL,REJECT",
			request: func(proxyAddr string) string {
				return "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n"
			},
			want: http.StatusForbidden,
		},
		{
			name: "not http",
			rule: "FINAL,DIRECT",
			request: func(string) string {
				return "GET ftp://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"
			},
			want: http.StatusBadRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, envOptions{
				rules: []string{tc.rule},
				leaves: map[string]outbound.Dialer{
					"DIRECT": outbound.NewDirect(),
					"REJECT": outbound.NewReject(),
				},
			})
			proxy := startHTTPService(t, env)
			conn, err := net.Dial("tcp", proxy.Addr())
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(testDeadline))
			if _, err := io.WriteString(conn, tc.request(proxy.Addr())); err != nil {
				t.Fatalf("write request: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

// TestHTTPServiceCloseStopsAccepting checks that a closed listener releases its
// port instead of lingering until the process ends.
func TestHTTPServiceCloseStopsAccepting(t *testing.T) {
	proxy := startHTTPService(t, directEnv(t))
	addr := proxy.Addr()
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	if err := proxy.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("the listener still accepts connections after Close")
	}
}
