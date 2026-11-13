package outbound

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxReplyHeader bounds the bytes accepted before the blank line that ends a
// proxy reply, so a misbehaving proxy cannot exhaust memory with headers.
const maxReplyHeader = 32 << 10

// HTTPProxyOptions configures an HTTP CONNECT outbound.
type HTTPProxyOptions struct {
	Server   string
	Port     int
	Username string
	Password string
	// TLS wraps the connection to the proxy in TLS before the CONNECT request:
	// this is the HTTPS variant of the outbound.
	TLS bool
	// TLSConfig, when set, replaces the TLS settings of that handshake. Tests
	// use it to trust a local certificate; the configuration layer leaves it
	// nil and the proxy host is used as the server name.
	TLSConfig *tls.Config
	// Timeout bounds the dial and the handshake when the context has no
	// deadline. Zero means DefaultTimeout.
	Timeout time.Duration
}

// HTTPProxy is the HTTP CONNECT outbound: the destination and the port are
// carried in the request line, and the connection becomes a tunnel once the
// proxy answers 200. With TLS it first secures the hop to the proxy, which is
// the HTTPS variant.
type HTTPProxy struct {
	server    string
	auth      *basicAuth
	useTLS    bool
	tlsConfig *tls.Config
	timeout   time.Duration
}

// NewHTTPProxy builds an HTTP or HTTPS CONNECT outbound.
func NewHTTPProxy(opts HTTPProxyOptions) (*HTTPProxy, error) {
	if err := validateServer(opts.Server, opts.Port); err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	if (opts.Username == "") != (opts.Password == "") {
		return nil, errors.New("http: username and password must be given together")
	}
	var auth *basicAuth
	if opts.Username != "" {
		auth = &basicAuth{username: opts.Username, password: opts.Password}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &HTTPProxy{
		server:    net.JoinHostPort(opts.Server, strconv.Itoa(opts.Port)),
		auth:      auth,
		useTLS:    opts.TLS,
		tlsConfig: opts.TLSConfig,
		timeout:   timeout,
	}, nil
}

// DialContext implements Dialer with a CONNECT request.
func (p *HTTPProxy) DialContext(ctx context.Context, address string) (net.Conn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	conn, err := p.dialProxy(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := p.tunnel(ctx, conn, target)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return stream, nil
}

// DialPacket implements Dialer. HTTP CONNECT carries streams only, so the
// outbound cannot offer a datagram association.
func (p *HTTPProxy) DialPacket(context.Context, string) (PacketConn, error) {
	return nil, fmt.Errorf("%w: http connect carries streams only", ErrUnsupported)
}

// dialProxy dials the proxy and applies the handshake deadline.
func (p *HTTPProxy) dialProxy(ctx context.Context) (net.Conn, error) {
	dialer := net.Dialer{Timeout: p.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", p.server)
	if err != nil {
		return nil, fmt.Errorf("http: connect to %s: %w", p.server, err)
	}
	setConnDeadline(conn, ctx, p.timeout)
	return conn, nil
}

// tunnel secures the hop if the outbound is the HTTPS variant, sends the
// CONNECT request and hands back the established tunnel.
func (p *HTTPProxy) tunnel(ctx context.Context, conn net.Conn, target Target) (net.Conn, error) {
	if p.useTLS {
		host, _, err := net.SplitHostPort(p.server)
		if err != nil {
			return nil, fmt.Errorf("http: server address %q: %v", p.server, err)
		}
		secured := tls.Client(conn, p.tlsConfigFor(host))
		if err := secured.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("http: tls handshake with %s: %w", p.server, err)
		}
		conn = secured
	}
	release := guardConn(ctx, conn)
	if err := p.writeConnect(conn, target); err != nil {
		release()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	status, err := readConnectResponse(reader)
	if err != nil {
		release()
		return nil, err
	}
	if status != http.StatusOK {
		release()
		return nil, fmt.Errorf("http: proxy %s refused the tunnel to %s: %d %s",
			p.server, target, status, http.StatusText(status))
	}
	if !release() {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	_ = conn.SetDeadline(time.Time{})
	// The proxy may have sent the first tunnel bytes in the same segment as
	// its reply; they are already in the buffer and must not be lost.
	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: reader}, nil
	}
	return conn, nil
}

// tlsConfigFor returns the TLS settings for the hop to the proxy. The proxy host
// is the server name unless the caller supplied one, which is what makes a
// certificate issued to an address verify correctly.
func (p *HTTPProxy) tlsConfigFor(host string) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if p.tlsConfig != nil {
		cfg = p.tlsConfig.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	return cfg
}

// writeConnect writes the CONNECT request, with the proxy credentials when the
// outbound has them.
func (p *HTTPProxy) writeConnect(w io.Writer, target Target) error {
	authority := target.String()
	var b strings.Builder
	b.WriteString("CONNECT " + authority + " HTTP/1.1\r\n")
	b.WriteString("Host: " + authority + "\r\n")
	if p.auth != nil {
		b.WriteString("Proxy-Authorization: " + p.auth.header() + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("http: write CONNECT: %w", err)
	}
	return nil
}

// readConnectResponse reads the status line and the headers of a proxy reply and
// returns the status code.
func readConnectResponse(r *bufio.Reader) (int, error) {
	budget := maxReplyHeader
	line, err := readReplyLine(r, &budget)
	if err != nil {
		return 0, err
	}
	proto, rest, ok := strings.Cut(line, " ")
	if !ok || !strings.HasPrefix(proto, "HTTP/") {
		return 0, fmt.Errorf("http: malformed proxy reply %q", line)
	}
	codeText, _, _ := strings.Cut(rest, " ")
	code, err := strconv.Atoi(codeText)
	if err != nil || code < 100 || code > 599 {
		return 0, fmt.Errorf("http: malformed proxy status %q", line)
	}
	for {
		line, err = readReplyLine(r, &budget)
		if err != nil {
			return 0, err
		}
		if line == "" {
			return code, nil
		}
	}
}

// readReplyLine reads one CRLF terminated line and charges it to the budget.
func readReplyLine(r *bufio.Reader, budget *int) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("http: read proxy reply: %w", err)
	}
	*budget -= len(line)
	if *budget < 0 {
		return "", errors.New("http: proxy reply header is too large")
	}
	line = strings.TrimSuffix(line, "\n")
	return strings.TrimSuffix(line, "\r"), nil
}

// bufferedConn returns a connection whose reads come from the buffered reader
// first, so bytes the proxy sent ahead of the tunnel are not dropped.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read implements net.Conn.
func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
