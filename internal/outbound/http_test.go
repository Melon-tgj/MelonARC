package outbound

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWriteConnectRequest(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		want     string
	}{
		{
			name: "without credentials",
			want: "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
		},
		{
			name:     "with credentials",
			username: "alice",
			password: "s3cret",
			want: "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n" +
				"Proxy-Authorization: Basic YWxpY2U6czNjcmV0\r\n\r\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proxy, err := NewHTTPProxy(HTTPProxyOptions{
				Server: "proxy.example", Port: 3128,
				Username: tc.username, Password: tc.password,
			})
			if err != nil {
				t.Fatalf("NewHTTPProxy: %v", err)
			}
			var buf bytes.Buffer
			if err := proxy.writeConnect(&buf, Target{Host: "example.com", Port: 443}); err != nil {
				t.Fatalf("writeConnect: %v", err)
			}
			if got := buf.String(); got != tc.want {
				t.Fatalf("request =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}

func TestReadConnectResponse(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    int
		wantErr bool
	}{
		{name: "established", raw: "HTTP/1.1 200 Connection established\r\n\r\n", want: 200},
		{name: "headers before the blank line",
			raw: "HTTP/1.1 200 OK\r\nProxy-Agent: test\r\nX-Note: yes\r\n\r\n", want: 200},
		{name: "old version", raw: "HTTP/1.0 200 OK\r\n\r\n", want: 200},
		{name: "authentication required", raw: "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", want: 407},
		{name: "gateway failure", raw: "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", want: 502},
		{name: "not http", raw: "SSH-2.0-OpenSSH\r\n\r\n", wantErr: true},
		{name: "missing status", raw: "HTTP/1.1\r\n\r\n", wantErr: true},
		{name: "non numeric status", raw: "HTTP/1.1 nope Bad\r\n\r\n", wantErr: true},
		{name: "status out of range", raw: "HTTP/1.1 999 Weird\r\n\r\n", wantErr: true},
		{name: "truncated", raw: "HTTP/1.1 200 OK\r\n", wantErr: true},
		{name: "huge header", raw: "HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("a", maxReplyHeader) + "\r\n\r\n", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readConnectResponse(bufio.NewReader(strings.NewReader(tc.raw)))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("readConnectResponse = %d, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("readConnectResponse: %v", err)
			}
			if got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestHTTPProxySurfacesA407(t *testing.T) {
	address := startScriptedServer(t, func(conn net.Conn) {
		if _, err := readTestRequestHeaders(conn); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	})
	proxy := mustHTTPProxy(t, address, "alice", "s3cret", false, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := proxy.DialContext(ctx, "example.com:443"); err == nil {
		t.Fatal("dial succeeded although the proxy demanded authentication")
	} else if !strings.Contains(err.Error(), "407") {
		t.Fatalf("error = %v, want the status code", err)
	}
}

func TestHTTPProxyKeepsBytesSentWithTheReply(t *testing.T) {
	address := startScriptedServer(t, func(conn net.Conn) {
		if _, err := readTestRequestHeaders(conn); err != nil {
			return
		}
		// The tunnel starts in the same segment as the reply, which is
		// exactly the case a plain read would lose.
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\nhello")
	})
	proxy := mustHTTPProxy(t, address, "", "", false, nil)
	conn := dialThrough(t, proxy, "example.com:443")
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("early bytes = %q, want hello", buf)
	}
}

func TestHTTPProxyRejectsBadRequests(t *testing.T) {
	address := startScriptedServer(t, func(conn net.Conn) {
		if _, err := readTestRequestHeaders(conn); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
	})
	proxy := mustHTTPProxy(t, address, "", "", false, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := proxy.DialContext(ctx, "example.com:443"); err == nil {
		t.Fatal("dial succeeded although the proxy refused")
	}
}

func TestHTTPProxyHasNoDatagramAssociation(t *testing.T) {
	proxy, err := NewHTTPProxy(HTTPProxyOptions{Server: "proxy.example", Port: 3128})
	if err != nil {
		t.Fatalf("NewHTTPProxy: %v", err)
	}
	if _, err := proxy.DialPacket(context.Background(), "example.com:53"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("DialPacket error = %v, want ErrUnsupported", err)
	}
}

func TestHTTPProxySendsProxyAuthorization(t *testing.T) {
	server := startTestHTTPProxy(t, "alice", "s3cret")
	echo := startTCPEcho(t)
	conn := dialThrough(t, mustHTTPProxy(t, server.addr, "alice", "s3cret", false, nil), echo)
	if _, err := conn.Write([]byte("q")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	requests := server.Requests()
	if len(requests) != 1 {
		t.Fatalf("requests = %+v, want one", requests)
	}
	if requests[0].Method != "CONNECT" || requests[0].Host != echo {
		t.Fatalf("request = %+v, want CONNECT to %s", requests[0], echo)
	}
	if requests[0].AuthHeader != "Basic YWxpY2U6czNjcmV0" {
		t.Fatalf("Proxy-Authorization = %q", requests[0].AuthHeader)
	}
}

// readTestRequestHeaders consumes a request up to the blank line.
func readTestRequestHeaders(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	var b strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return b.String(), err
		}
		b.WriteString(line)
		if line == "\r\n" || line == "\n" {
			return b.String(), nil
		}
	}
}
