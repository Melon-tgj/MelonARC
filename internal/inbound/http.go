package inbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// DefaultHandshakeTimeout bounds how long a client may take to send the head of
// a request. Without it a silent peer would hold a connection forever.
const DefaultHandshakeTimeout = 30 * time.Second

// hopByHopHeaders describe one connection rather than the message on it, so
// they are dropped before a request or response crosses this process.
// Content-Length and Transfer-Encoding are not in the list: the writer emits
// both from the parsed message, and connection bookkeeping is rebuilt from the
// Close flag.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// HTTPOptions configures the HTTP inbound.
type HTTPOptions struct {
	// Addr is the listen address, "host:port". Port 0 picks a free port.
	Addr string
	// Handler routes and dials the destination of each request.
	Handler *Handler
	// HandshakeTimeout bounds reading a request head. Zero means
	// DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// Metrics receives the connection counters. Nil records nothing.
	Metrics *Metrics
	// Logger receives the per-request and per-failure lines. Nil discards them.
	Logger *slog.Logger
}

// NewHTTP binds an HTTP inbound listener and starts accepting.
func NewHTTP(opts HTTPOptions) (*Service, error) {
	if opts.Handler == nil {
		return nil, errors.New("inbound: the http listener needs a handler")
	}
	timeout := opts.HandshakeTimeout
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}
	h := &httpHandler{handler: opts.Handler, timeout: timeout, logger: loggerOrDiscard(opts.Logger)}
	listener, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("inbound: http listen on %q: %w", opts.Addr, err)
	}
	return newService(protocolHTTP, listener, h.serve, opts.Metrics, opts.Logger), nil
}

// httpHandler serves the proxy side of HTTP: CONNECT for tunnels and
// absolute-form requests for everything else.
type httpHandler struct {
	handler *Handler
	timeout time.Duration
	logger  *slog.Logger
}

// serve reads one request head and dispatches on its method.
func (h *httpHandler) serve(ctx context.Context, conn net.Conn) {
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(h.timeout))
	req, err := http.ReadRequest(reader)
	if err != nil {
		writeHTTPStatus(conn, http.StatusBadRequest, "malformed request")
		h.logger.Debug("http request rejected", "error", err)
		return
	}
	// The head is in; a tunnel or a response may take as long as it takes.
	_ = conn.SetReadDeadline(time.Time{})
	if req.Method == http.MethodConnect {
		h.tunnel(ctx, conn, req)
		return
	}
	h.forward(ctx, conn, req)
}

// tunnel establishes a CONNECT tunnel and relays it.
func (h *httpHandler) tunnel(ctx context.Context, client net.Conn, req *http.Request) {
	target, err := outbound.ParseTarget(req.Host)
	if err != nil {
		writeHTTPStatus(client, http.StatusBadRequest, "CONNECT needs host:port")
		return
	}
	upstream, sel, err := h.handler.Stream(ctx, Request{Target: target, Network: networkTCP})
	if err != nil {
		h.writeDialError(client, target, sel, err)
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	relay(client, upstream)
}

// forward sends one absolute-form request upstream and streams the response
// back.
//
// One request per client connection is deliberate: the response is delimited by
// the upstream closing, so a second request would need a second destination and
// a second dial anyway. Every response therefore carries Connection: close,
// which tells the client to reconnect.
func (h *httpHandler) forward(ctx context.Context, client net.Conn, req *http.Request) {
	if req.URL == nil || !req.URL.IsAbs() || req.URL.Host == "" {
		writeHTTPStatus(client, http.StatusBadRequest,
			"this is a proxy: the request line must carry an absolute URI")
		return
	}
	if req.URL.Scheme != "http" {
		writeHTTPStatus(client, http.StatusBadRequest,
			fmt.Sprintf("%q is not proxied in absolute form; use CONNECT", req.URL.Scheme))
		return
	}
	target, err := outbound.ParseTarget(authorityOf(req.URL))
	if err != nil {
		writeHTTPStatus(client, http.StatusBadRequest, err.Error())
		return
	}
	// A client that announces a body waits for a go-ahead before sending it.
	if hasToken(req.Header.Get("Expect"), "100-continue") {
		if _, err := io.WriteString(client, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return
		}
		req.Header.Del("Expect")
	}
	for _, name := range hopByHopHeaders {
		req.Header.Del(name)
	}
	// The whole connection belongs to this one exchange.
	req.Close = true

	upstream, sel, err := h.handler.Stream(ctx, Request{Target: target, Network: networkTCP})
	if err != nil {
		h.writeDialError(client, target, sel, err)
		return
	}
	defer upstream.Close()

	if err := req.Write(upstream); err != nil {
		h.logger.Debug("http request could not be forwarded", "target", target.String(), "error", err)
		writeHTTPStatus(client, http.StatusBadGateway, "the request could not be forwarded")
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		h.logger.Debug("http response could not be read", "target", target.String(), "error", err)
		writeHTTPStatus(client, http.StatusBadGateway, "the upstream answered with something unreadable")
		return
	}
	defer resp.Body.Close()
	resp.Close = true
	if err := resp.Write(client); err != nil {
		h.logger.Debug("http response could not be relayed", "target", target.String(), "error", err)
	}
}

// writeDialError answers a dial that failed. A destination a rule rejects is
// forbidden, not a broken gateway: the difference is what the client needs to
// see.
func (h *httpHandler) writeDialError(w io.Writer, target outbound.Target, sel Selection, err error) {
	status, message := http.StatusBadGateway, "the upstream could not be reached"
	if errors.Is(err, outbound.ErrRejected) {
		status, message = http.StatusForbidden, "a rule rejects this destination"
	}
	if sel.Rule != nil {
		h.logger.Warn("http request not carried",
			"target", target.String(), "rule", sel.Rule.String(), "policy", sel.Target, "error", err)
	}
	writeHTTPStatus(w, status, message)
}

// authorityOf renders the host:port of a request URI, filling in the default
// port of the scheme when the client left it out.
func authorityOf(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	port := "80"
	if u.Scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// hasToken reports whether a comma separated header value carries token.
func hasToken(header, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// writeHTTPStatus writes a minimal response that closes the connection.
func writeHTTPStatus(w io.Writer, status int, message string) {
	body := message + "\n"
	_, _ = fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
		status, http.StatusText(status), len(body), body)
}
