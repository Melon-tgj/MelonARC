package inbound

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// Wire constants of the SOCKS5 server side, from RFC 1928 (the protocol) and
// RFC 1929 (username and password authentication). The client side of the same
// protocol lives in internal/outbound; the values are literal protocol numbers,
// while the encoding of an address and a datagram header is shared through the
// helpers that package exports.
const (
	socks5Version = 0x05

	methodNoAuth       = 0x00
	methodUserPassword = 0x02
	methodUnacceptable = 0xFF

	authVersion = 0x01

	commandConnect      = 0x01
	commandBind         = 0x02
	commandUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// Reply codes of a command.
const (
	replySucceeded           = 0x00
	replyGeneralFailure      = 0x01
	replyNotAllowed          = 0x02
	replyNetworkUnreachable  = 0x03
	replyHostUnreachable     = 0x04
	replyConnectionRefused   = 0x05
	replyCommandNotSupported = 0x07
	replyAddressNotSupported = 0x08
)

// unspecified is the address a reply carries when it has none to report.
var unspecified = outbound.Target{Host: "0.0.0.0"}

// errAddressType marks a request whose address type this build cannot read, so
// the caller answers with the matching reply code instead of a general failure.
var errAddressType = errors.New("unsupported address type")

// SOCKS5Options configures the SOCKS5 inbound.
type SOCKS5Options struct {
	// Addr is the listen address, "host:port". Port 0 picks a free port.
	Addr string
	// Username and Password, when both are set, make the listener require
	// username and password authentication. Empty means it accepts without
	// authentication.
	Username string
	Password string
	// Handler routes and dials the destinations of the requests.
	Handler *Handler
	// HandshakeTimeout bounds the greeting, the authentication and the request.
	// Zero means DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// Metrics receives the connection and association counters. Nil records
	// nothing.
	Metrics *Metrics
	// Logger receives the per-request and per-failure lines. Nil discards them.
	Logger *slog.Logger
}

// NewSOCKS5 binds a SOCKS5 inbound listener and starts accepting.
func NewSOCKS5(opts SOCKS5Options) (*Service, error) {
	if opts.Handler == nil {
		return nil, errors.New("inbound: the socks5 listener needs a handler")
	}
	if (opts.Username == "") != (opts.Password == "") {
		return nil, errors.New("inbound: socks5 username and password must be given together")
	}
	if len(opts.Username) > 255 || len(opts.Password) > 255 {
		return nil, errors.New("inbound: socks5 username and password are limited to 255 bytes each")
	}
	timeout := opts.HandshakeTimeout
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}
	h := &socks5Handler{
		handler: opts.Handler,
		timeout: timeout,
		metrics: opts.Metrics,
		logger:  loggerOrDiscard(opts.Logger),
	}
	if opts.Username != "" {
		h.auth = &basicCredentials{username: opts.Username, password: opts.Password}
	}
	listener, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("inbound: socks5 listen on %q: %w", opts.Addr, err)
	}
	return newService(protocolSOCKS5, listener, h.serve, opts.Metrics, opts.Logger), nil
}

// basicCredentials is the username and password pair the listener expects.
type basicCredentials struct {
	username string
	password string
}

// socks5Handler serves the SOCKS5 protocol: negotiation, optional
// authentication, CONNECT and UDP ASSOCIATE.
type socks5Handler struct {
	handler *Handler
	auth    *basicCredentials
	timeout time.Duration
	metrics *Metrics
	logger  *slog.Logger
}

// serve runs one client connection from greeting to shutdown.
func (h *socks5Handler) serve(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(h.timeout))
	if err := h.negotiate(conn); err != nil {
		h.logger.Debug("socks5 negotiation failed", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}
	command, target, err := readRequest(conn)
	if err != nil {
		_ = writeReply(conn, replyForError(err), unspecified)
		h.logger.Debug("socks5 request rejected", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}
	// The handshake is over; the tunnel may stay open as long as it likes.
	_ = conn.SetDeadline(time.Time{})

	switch command {
	case commandConnect:
		h.connect(ctx, conn, target)
	case commandUDPAssociate:
		h.associate(ctx, conn, target)
	default:
		_ = writeReply(conn, replyCommandNotSupported, unspecified)
		h.logger.Debug("socks5 command not supported", "command", command)
	}
}

// negotiate completes the method selection and the authentication.
func (h *socks5Handler) negotiate(conn net.Conn) error {
	methods, err := readMethods(conn)
	if err != nil {
		return err
	}
	// A listener with credentials only accepts the method it can verify. A
	// listener without them has nothing to verify, so it only accepts none.
	wanted := byte(methodNoAuth)
	if h.auth != nil {
		wanted = methodUserPassword
	}
	if !containsByte(methods, wanted) {
		_, _ = conn.Write([]byte{socks5Version, methodUnacceptable})
		return errors.New("client offered none of the accepted authentication methods")
	}
	if _, err := conn.Write([]byte{socks5Version, wanted}); err != nil {
		return fmt.Errorf("write method selection: %w", err)
	}
	if wanted == methodNoAuth {
		return nil
	}
	return h.authenticate(conn)
}

// authenticate performs the username and password exchange of RFC 1929.
func (h *socks5Handler) authenticate(conn net.Conn) error {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("read authentication: %w", err)
	}
	if head[0] != authVersion {
		return fmt.Errorf("authentication has version %d", head[0])
	}
	username := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("read username: %w", err)
	}
	var passwordLen [1]byte
	if _, err := io.ReadFull(conn, passwordLen[:]); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}
	password := make([]byte, int(passwordLen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	// Both halves are always compared, so a wrong username and a wrong password
	// take the same path.
	userOK := subtle.ConstantTimeCompare(username, []byte(h.auth.username)) == 1
	passOK := subtle.ConstantTimeCompare(password, []byte(h.auth.password)) == 1
	status := byte(0x00)
	if !userOK || !passOK {
		status = 0x01
	}
	if _, err := conn.Write([]byte{authVersion, status}); err != nil {
		return fmt.Errorf("write authentication reply: %w", err)
	}
	if status != 0x00 {
		return errors.New("authentication failed")
	}
	return nil
}

// connect opens the stream and relays it.
func (h *socks5Handler) connect(ctx context.Context, client net.Conn, target outbound.Target) {
	upstream, sel, err := h.handler.Stream(ctx, Request{Target: target, Network: networkTCP})
	if err != nil {
		_ = writeReply(client, replyForError(err), unspecified)
		if sel.Rule != nil {
			h.logger.Warn("socks5 connect failed",
				"target", target.String(), "rule", sel.Rule.String(), "policy", sel.Target, "error", err)
		}
		return
	}
	defer upstream.Close()
	if err := writeReply(client, replySucceeded, localTarget(upstream)); err != nil {
		return
	}
	relay(client, upstream)
}

// associate serves a UDP association until the control connection closes.
func (h *socks5Handler) associate(ctx context.Context, client net.Conn, requested outbound.Target) {
	bind := listenerIP(client.LocalAddr())
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: bind})
	if err != nil {
		_ = writeReply(client, replyGeneralFailure, unspecified)
		h.logger.Warn("socks5 udp association could not bind", "error", err)
		return
	}
	assoc := newAssociation(associationOptions{
		ctx:     ctx,
		handler: h.handler,
		logger:  h.logger,
		socket:  sock,
		expect:  expectedClient(requested),
	})
	// The association is counted from the moment it can relay until it is
	// closed, which is exactly the lifetime of this deferred pair.
	h.metrics.datagramOpened()
	defer h.metrics.datagramClosed()
	defer assoc.Close()

	bound, ok := sock.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = writeReply(client, replyGeneralFailure, unspecified)
		return
	}
	if err := writeReply(client, replySucceeded, outbound.Target{
		Host: bound.IP.String(),
		Port: uint16(bound.Port),
	}); err != nil {
		return
	}
	// The association lives exactly as long as the control connection: RFC 1928
	// ties it to that connection, so reading it to the end is the whole job.
	_, _ = io.Copy(io.Discard, client)
}

// expectedClient turns the address of a UDP ASSOCIATE request into the endpoint
// datagrams must come from. An unspecified address or a zero port means the
// client did not say, so the first datagram decides.
func expectedClient(requested outbound.Target) net.Addr {
	ip := net.ParseIP(requested.Host)
	if requested.Port == 0 || ip == nil || ip.IsUnspecified() {
		return nil
	}
	return &net.UDPAddr{IP: ip, Port: int(requested.Port)}
}

// listenerIP is the address the control connection was accepted on, which is
// the address the UDP socket binds to: a client that reached us on loopback is
// answered with a loopback address.
func listenerIP(addr net.Addr) net.IP {
	if tcp, ok := addr.(*net.TCPAddr); ok && tcp.IP != nil {
		return tcp.IP
	}
	return net.IPv4(127, 0, 0, 1)
}

// localTarget reports the address a stream was opened from, so the client sees
// the bound address of its own tunnel rather than an invented one.
func localTarget(conn net.Conn) outbound.Target {
	if addr := conn.LocalAddr(); addr != nil {
		if tcp, ok := addr.(*net.TCPAddr); ok {
			return outbound.Target{Host: tcp.IP.String(), Port: uint16(tcp.Port)}
		}
	}
	return unspecified
}

// readMethods reads the greeting and returns the offered method list.
func readMethods(r io.Reader) ([]byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, fmt.Errorf("read greeting: %w", err)
	}
	if head[0] != socks5Version {
		return nil, fmt.Errorf("greeting has version %d", head[0])
	}
	if head[1] == 0 {
		return nil, errors.New("greeting offers no authentication method")
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, fmt.Errorf("read methods: %w", err)
	}
	return methods, nil
}

// readRequest reads one command request.
func readRequest(r io.Reader) (byte, outbound.Target, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, outbound.Target{}, fmt.Errorf("read request: %w", err)
	}
	if head[0] != socks5Version {
		return 0, outbound.Target{}, fmt.Errorf("request has version %d", head[0])
	}
	if head[2] != 0 {
		return 0, outbound.Target{}, fmt.Errorf("request has reserved byte %#x", head[2])
	}
	host, err := readAddress(r, head[3])
	if err != nil {
		return 0, outbound.Target{}, err
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return 0, outbound.Target{}, fmt.Errorf("read port: %w", err)
	}
	return head[1], outbound.Target{Host: host, Port: binary.BigEndian.Uint16(port[:])}, nil
}

// readAddress reads the ATYP-specific part of a request.
func readAddress(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		var b [net.IPv4len]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", fmt.Errorf("read ipv4 address: %w", err)
		}
		return net.IP(b[:]).String(), nil
	case atypIPv6:
		var b [net.IPv6len]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", fmt.Errorf("read ipv6 address: %w", err)
		}
		return net.IP(b[:]).String(), nil
	case atypDomain:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", fmt.Errorf("read name length: %w", err)
		}
		if length[0] == 0 {
			return "", errors.New("request carries an empty name")
		}
		b := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", fmt.Errorf("read name: %w", err)
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("%w %#x", errAddressType, atyp)
	}
}

// writeReply writes a command reply with the address the server reports as
// bound.
func writeReply(w io.Writer, code byte, bound outbound.Target) error {
	b := make([]byte, 0, 4+len(bound.Host)+2)
	b = append(b, socks5Version, code, 0x00)
	b = outbound.AppendAddress(b, bound)
	_, err := w.Write(b)
	return err
}

// replyForError maps a failure to the reply code that describes it best. A
// destination a rule rejects is "not allowed", which is what the code means.
//
// The errno cases are best effort: they are what makes a refused connection
// distinguishable from a dead host on the platforms that report them this way,
// and anything else falls back to the general failure code.
func replyForError(err error) byte {
	switch {
	case errors.Is(err, errAddressType):
		return replyAddressNotSupported
	case errors.Is(err, outbound.ErrRejected):
		return replyNotAllowed
	case errors.Is(err, syscall.ECONNREFUSED):
		return replyConnectionRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return replyNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ETIMEDOUT):
		return replyHostUnreachable
	}
	return replyGeneralFailure
}

// containsByte reports whether list holds b.
func containsByte(list []byte, b byte) bool {
	for _, v := range list {
		if v == b {
			return true
		}
	}
	return false
}
