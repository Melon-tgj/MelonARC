package outbound

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// SOCKS5 wire constants, from RFC 1928 (the protocol) and RFC 1929
// (username and password authentication).
const (
	socks5Version = 0x05

	methodNoAuth       = 0x00
	methodUserPassword = 0x02
	methodNoAcceptable = 0xFF

	authVersion = 0x01

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	replySucceeded = 0x00
)

// The address and datagram framing below are exported because the inbound
// listener speaks the same wire format from the other side. Keeping one
// implementation is what stops the two halves of the protocol from drifting
// apart.

// MaxUDPHeaderLen is the largest SOCKS5 UDP header: RSV (2), FRAG (1), ATYP (1),
// a 255 byte name plus its length byte, and the port (2).
const MaxUDPHeaderLen = 4 + 1 + 255 + 2

// maxSkippedDatagrams bounds how many fragmented or malformed datagrams a read
// drops before it reports an error instead of looping.
const maxSkippedDatagrams = 32

// SOCKS5Options configures a SOCKS5 outbound: the server to tunnel through and
// the credentials to authenticate with. Empty credentials mean no
// authentication, which is offered alone.
type SOCKS5Options struct {
	Server   string
	Port     int
	Username string
	Password string
	// Timeout bounds the dial and the handshake when the context has no
	// deadline. Zero means DefaultTimeout.
	Timeout time.Duration
}

// SOCKS5 is the SOCKS5 outbound. Streams use CONNECT and datagrams use UDP
// ASSOCIATE; both travel through the same server.
type SOCKS5 struct {
	server  string
	auth    *basicAuth
	timeout time.Duration
}

// NewSOCKS5 builds a SOCKS5 outbound.
func NewSOCKS5(opts SOCKS5Options) (*SOCKS5, error) {
	if err := validateServer(opts.Server, opts.Port); err != nil {
		return nil, fmt.Errorf("socks5: %w", err)
	}
	if (opts.Username == "") != (opts.Password == "") {
		return nil, errors.New("socks5: username and password must be given together")
	}
	var auth *basicAuth
	if opts.Username != "" {
		// One byte carries each length on the wire.
		if len(opts.Username) > 255 || len(opts.Password) > 255 {
			return nil, errors.New("socks5: username and password are limited to 255 bytes each")
		}
		auth = &basicAuth{username: opts.Username, password: opts.Password}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &SOCKS5{
		server:  net.JoinHostPort(opts.Server, strconv.Itoa(opts.Port)),
		auth:    auth,
		timeout: timeout,
	}, nil
}

// DialContext implements Dialer with a CONNECT request.
func (d *SOCKS5) DialContext(ctx context.Context, address string) (net.Conn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	control, err := d.openControl(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := d.connect(ctx, control, target)
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	return stream, nil
}

// DialPacket implements Dialer with a UDP association dedicated to one
// destination.
func (d *SOCKS5) DialPacket(ctx context.Context, address string) (PacketConn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	relay, err := d.DialUDP(ctx)
	if err != nil {
		return nil, err
	}
	return &relayPacketConn{relay: relay, dest: target}, nil
}

// DialUDP opens a UDP association with the server. One association carries
// datagrams for any number of destinations, each framed with the SOCKS5 UDP
// header, which is what an inbound listener or the TUN path needs. The
// association lives as long as the returned relay; closing it also closes the
// control connection that holds it open.
func (d *SOCKS5) DialUDP(ctx context.Context) (*UDPRelay, error) {
	control, err := d.openControl(ctx)
	if err != nil {
		return nil, err
	}
	relay, err := d.associate(ctx, control)
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	return relay, nil
}

// openControl dials the server and applies the handshake deadline.
func (d *SOCKS5) openControl(ctx context.Context) (net.Conn, error) {
	dialer := net.Dialer{Timeout: d.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", d.server)
	if err != nil {
		return nil, fmt.Errorf("socks5: connect to %s: %w", d.server, err)
	}
	setConnDeadline(conn, ctx, d.timeout)
	return conn, nil
}

// connect negotiates and issues CONNECT on an open control connection.
func (d *SOCKS5) connect(ctx context.Context, conn net.Conn, target Target) (net.Conn, error) {
	release := guardConn(ctx, conn)
	if err := d.negotiate(conn); err != nil {
		release()
		return nil, err
	}
	if _, err := d.request(conn, cmdConnect, target); err != nil {
		release()
		return nil, err
	}
	if !release() {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	// The tunnel is established; the caller owns the deadlines from here on.
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// associate negotiates and issues UDP ASSOCIATE on an open control connection,
// then opens the datagram socket to the relay endpoint the server reports.
func (d *SOCKS5) associate(ctx context.Context, control net.Conn) (*UDPRelay, error) {
	release := guardConn(ctx, control)
	if err := d.negotiate(control); err != nil {
		release()
		return nil, err
	}
	// The client does not know which source address it will use yet, so the
	// request carries the unspecified address, as the protocol expects.
	bound, err := d.request(control, cmdUDPAssociate, Target{Host: "0.0.0.0"})
	if err != nil {
		release()
		return nil, err
	}
	relayAddr := bound
	if ip := net.ParseIP(relayAddr.Host); ip != nil && ip.IsUnspecified() {
		// A server that does not know its own reachable address answers with
		// the unspecified one; the address it is reached on is the useful one.
		host, _, splitErr := net.SplitHostPort(d.server)
		if splitErr != nil {
			release()
			return nil, fmt.Errorf("socks5: server address %q: %v", d.server, splitErr)
		}
		relayAddr.Host = host
	}
	dialer := net.Dialer{Timeout: d.timeout}
	conn, err := dialer.DialContext(ctx, "udp", relayAddr.String())
	if err != nil {
		release()
		return nil, fmt.Errorf("socks5: udp relay %s: %w", relayAddr, err)
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		release()
		return nil, errors.New("socks5: udp relay is not a datagram connection")
	}
	if !release() {
		_ = udp.Close()
		return nil, ctx.Err()
	}
	_ = control.SetDeadline(time.Time{})
	return &UDPRelay{control: control, conn: udp, server: relayAddr}, nil
}

// negotiate offers the authentication methods and completes the one the server
// picks.
func (d *SOCKS5) negotiate(conn net.Conn) error {
	methods := []byte{methodNoAuth}
	if d.auth != nil {
		methods = []byte{methodNoAuth, methodUserPassword}
	}
	greeting := append([]byte{socks5Version, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("socks5: write greeting: %w", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("socks5: read greeting reply: %w", err)
	}
	if reply[0] != socks5Version {
		return fmt.Errorf("socks5: server answered with version %d", reply[0])
	}
	switch reply[1] {
	case methodNoAuth:
		// The server may prefer no authentication even when credentials were
		// offered; that is a legitimate answer and means they are not needed.
		return nil
	case methodUserPassword:
		if d.auth == nil {
			return errors.New("socks5: server requires authentication but none is configured")
		}
		return d.authenticate(conn)
	case methodNoAcceptable:
		return errors.New("socks5: server accepted none of the offered authentication methods")
	default:
		return fmt.Errorf("socks5: server selected unsupported method %#x", reply[1])
	}
}

// authenticate performs the username and password exchange of RFC 1929.
func (d *SOCKS5) authenticate(conn net.Conn) error {
	buf := make([]byte, 0, 3+len(d.auth.username)+len(d.auth.password))
	buf = append(buf, authVersion, byte(len(d.auth.username)))
	buf = append(buf, d.auth.username...)
	buf = append(buf, byte(len(d.auth.password)))
	buf = append(buf, d.auth.password...)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks5: write credentials: %w", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("socks5: read authentication reply: %w", err)
	}
	if reply[0] != authVersion {
		return fmt.Errorf("socks5: authentication reply has version %d", reply[0])
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("socks5: authentication failed with status %#x", reply[1])
	}
	return nil
}

// request sends one command and reads the reply, returning the address the
// server reports as bound.
func (d *SOCKS5) request(conn net.Conn, cmd byte, target Target) (Target, error) {
	req := make([]byte, 0, 4+len(target.Host)+2)
	req = append(req, socks5Version, cmd, 0x00)
	req = AppendAddress(req, target)
	if _, err := conn.Write(req); err != nil {
		return Target{}, fmt.Errorf("socks5: write request: %w", err)
	}
	return readReply(conn)
}

// AppendAddress appends ATYP, the address and the port. A name is carried in
// a single length byte, so this is only used for targets that came out of such
// a field: a SOCKS5 request or the destination of a datagram.
func AppendAddress(b []byte, t Target) []byte {
	if ip := net.ParseIP(t.Host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append(b, atypIPv4)
			b = append(b, ip4...)
		} else {
			b = append(b, atypIPv6)
			b = append(b, ip.To16()...)
		}
	} else {
		b = append(b, atypDomain, byte(len(t.Host)))
		b = append(b, t.Host...)
	}
	return append(b, byte(t.Port>>8), byte(t.Port))
}

// readReply reads a command reply. The bound address is consumed even when the
// request succeeded, so the connection is left at the start of the tunnel.
func readReply(r io.Reader) (Target, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Target{}, fmt.Errorf("socks5: read reply: %w", err)
	}
	if head[0] != socks5Version {
		return Target{}, fmt.Errorf("socks5: reply has version %d", head[0])
	}
	if head[1] != replySucceeded {
		return Target{}, replyError(head[1])
	}
	host, err := readAddress(r, head[3])
	if err != nil {
		return Target{}, err
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Target{}, fmt.Errorf("socks5: read bound port: %w", err)
	}
	return Target{Host: host, Port: binary.BigEndian.Uint16(port[:])}, nil
}

// readAddress reads ATYP-specific address bytes.
func readAddress(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		var b [net.IPv4len]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", fmt.Errorf("socks5: read ipv4 address: %w", err)
		}
		return net.IP(b[:]).String(), nil
	case atypIPv6:
		var b [net.IPv6len]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", fmt.Errorf("socks5: read ipv6 address: %w", err)
		}
		return net.IP(b[:]).String(), nil
	case atypDomain:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", fmt.Errorf("socks5: read name length: %w", err)
		}
		if length[0] == 0 {
			return "", errors.New("socks5: reply carries an empty name")
		}
		b := make([]byte, length[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", fmt.Errorf("socks5: read name: %w", err)
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("socks5: unsupported address type %#x", atyp)
	}
}

// replyError turns a reply code into an error naming the reason.
func replyError(code byte) error {
	reason := "unknown error"
	switch code {
	case 0x01:
		reason = "general server failure"
	case 0x02:
		reason = "connection not allowed by ruleset"
	case 0x03:
		reason = "network unreachable"
	case 0x04:
		reason = "host unreachable"
	case 0x05:
		reason = "connection refused"
	case 0x06:
		reason = "TTL expired"
	case 0x07:
		reason = "command not supported"
	case 0x08:
		reason = "address type not supported"
	}
	return fmt.Errorf("socks5: server refused the request: %s (code %d)", reason, code)
}

// UDPRelay is an established SOCKS5 UDP association. Every datagram carries the
// SOCKS5 UDP header, so one association serves any number of destinations: the
// inbound and TUN stages can reuse it as is, while DialPacket wraps it for
// callers that only need one destination.
//
// WriteTo may run concurrently with ReadFrom; concurrent reads are serialised
// on the internal buffer they share.
type UDPRelay struct {
	control net.Conn
	conn    *net.UDPConn
	server  Target

	wmu  sync.Mutex
	wbuf []byte

	rmu  sync.Mutex
	rbuf []byte
}

// WriteTo sends payload to destination through the server.
func (r *UDPRelay) WriteTo(payload []byte, destination Target) (int, error) {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	if need := MaxUDPHeaderLen + len(payload); cap(r.wbuf) < need {
		r.wbuf = make([]byte, 0, need)
	}
	buf := AppendUDPDatagram(r.wbuf[:0], destination, payload)
	r.wbuf = buf
	if _, err := r.conn.Write(buf); err != nil {
		return 0, err
	}
	return len(payload), nil
}

// AppendUDPDatagram appends the SOCKS5 UDP header and then the payload. The
// inbound listener writes the same framing towards its client, so a datagram
// that leaves one side is byte for byte what the other side expects.
func AppendUDPDatagram(b []byte, to Target, payload []byte) []byte {
	b = append(b, 0, 0, 0) // RSV, RSV, FRAG
	b = AppendAddress(b, to)
	return append(b, payload...)
}

// ReadFrom receives one payload and reports where it came from. A payload larger
// than p is truncated, as on any datagram socket. Fragmented datagrams are
// dropped because reassembly is not supported, and a burst of them fails the
// call rather than looping.
func (r *UDPRelay) ReadFrom(p []byte) (int, Target, error) {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	need := len(p) + MaxUDPHeaderLen
	if cap(r.rbuf) < need {
		r.rbuf = make([]byte, need)
	}
	buf := r.rbuf[:need]
	for skipped := 0; ; {
		n, err := r.conn.Read(buf)
		if err != nil {
			return 0, Target{}, err
		}
		payload, from, frag, err := DecodeUDPDatagram(buf[:n])
		if err == nil && frag == 0 {
			return copy(p, payload), from, nil
		}
		skipped++
		if skipped >= maxSkippedDatagrams {
			if err != nil {
				return 0, Target{}, err
			}
			return 0, Target{}, errors.New("socks5: fragmented udp datagrams are not supported")
		}
	}
}

// Close closes the datagram socket and the control connection that holds the
// association open.
func (r *UDPRelay) Close() error {
	err := r.conn.Close()
	if cerr := r.control.Close(); err == nil {
		err = cerr
	}
	return err
}

// LocalAddr reports the local datagram socket.
func (r *UDPRelay) LocalAddr() net.Addr { return r.conn.LocalAddr() }

// RemoteAddr reports the relay endpoint the server handed out.
func (r *UDPRelay) RemoteAddr() net.Addr { return r.server }

// SetDeadline implements net.PacketConn.
func (r *UDPRelay) SetDeadline(t time.Time) error { return r.conn.SetDeadline(t) }

// SetReadDeadline implements net.PacketConn.
func (r *UDPRelay) SetReadDeadline(t time.Time) error { return r.conn.SetReadDeadline(t) }

// SetWriteDeadline implements net.PacketConn.
func (r *UDPRelay) SetWriteDeadline(t time.Time) error { return r.conn.SetWriteDeadline(t) }

// DecodeUDPDatagram strips the SOCKS5 UDP header from a received datagram. The
// fragmentation byte is reported rather than interpreted: fragmentation is not
// supported, so the caller must drop such a datagram instead of mistaking a
// fragment for a whole payload. The inbound listener reads its client's
// datagrams with this, which is the mirror image of what UDPRelay does.
func DecodeUDPDatagram(b []byte) (payload []byte, from Target, frag byte, err error) {
	if len(b) < 4 {
		return nil, Target{}, 0, errors.New("socks5: udp datagram is shorter than its header")
	}
	if b[0] != 0 || b[1] != 0 {
		return nil, Target{}, 0, errors.New("socks5: udp datagram has reserved bytes set")
	}
	frag = b[2]
	atyp := b[3]
	off := 4
	var host string
	switch atyp {
	case atypIPv4:
		if len(b) < off+net.IPv4len+2 {
			return nil, Target{}, 0, errors.New("socks5: truncated ipv4 udp header")
		}
		host = net.IP(b[off : off+net.IPv4len]).String()
		off += net.IPv4len
	case atypIPv6:
		if len(b) < off+net.IPv6len+2 {
			return nil, Target{}, 0, errors.New("socks5: truncated ipv6 udp header")
		}
		host = net.IP(b[off : off+net.IPv6len]).String()
		off += net.IPv6len
	case atypDomain:
		if len(b) < off+1 {
			return nil, Target{}, 0, errors.New("socks5: truncated udp name length")
		}
		length := int(b[off])
		off++
		if length == 0 || len(b) < off+length+2 {
			return nil, Target{}, 0, errors.New("socks5: truncated udp name")
		}
		host = string(b[off : off+length])
		off += length
	default:
		return nil, Target{}, 0, fmt.Errorf("socks5: unsupported udp address type %#x", atyp)
	}
	port := binary.BigEndian.Uint16(b[off : off+2])
	return b[off+2:], Target{Host: host, Port: port}, frag, nil
}

// relayPacketConn is the single-destination view of a UDP relay. The
// association belongs to this connection alone, so every datagram that arrives
// is for the destination it was opened with.
type relayPacketConn struct {
	relay *UDPRelay
	dest  Target
}

// Read implements net.Conn.
func (c *relayPacketConn) Read(p []byte) (int, error) {
	n, _, err := c.relay.ReadFrom(p)
	return n, err
}

// Write implements net.Conn.
func (c *relayPacketConn) Write(p []byte) (int, error) { return c.relay.WriteTo(p, c.dest) }

// Close implements net.Conn.
func (c *relayPacketConn) Close() error { return c.relay.Close() }

// LocalAddr implements net.Conn.
func (c *relayPacketConn) LocalAddr() net.Addr { return c.relay.LocalAddr() }

// RemoteAddr implements net.Conn.
func (c *relayPacketConn) RemoteAddr() net.Addr { return c.dest }

// SetDeadline implements net.Conn.
func (c *relayPacketConn) SetDeadline(t time.Time) error { return c.relay.SetDeadline(t) }

// SetReadDeadline implements net.Conn.
func (c *relayPacketConn) SetReadDeadline(t time.Time) error { return c.relay.SetReadDeadline(t) }

// SetWriteDeadline implements net.Conn.
func (c *relayPacketConn) SetWriteDeadline(t time.Time) error {
	return c.relay.SetWriteDeadline(t)
}
