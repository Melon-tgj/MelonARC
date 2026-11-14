package outbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The VLESS request is a version byte, the account identifier, an addons block,
// the command, the target and then the first payload bytes. The response is a
// version byte and an addons block: everything after it belongs to the tunnel.
//
// Datagrams are not a separate association. A UDP request carries one target in
// its header and each datagram on the stream is a big-endian length followed by
// the payload.
const (
	vlessVersion = 0

	vlessCommandTCP = 1
	vlessCommandUDP = 2

	// VLESS numbers address types the way VMess does, not the way SOCKS5
	// does: a name is 2, not 3.
	vlessATYPIPv4   = 1
	vlessATYPDomain = 2
	vlessATYPIPv6   = 3

	vlessFlowVision = "xtls-rprx-vision"
	vlessMaxAddons  = 255
	// vlessLengthPrefix is the two-byte length in front of every datagram.
	vlessLengthPrefix = 2
	vlessMaxDatagram  = 0xFFFF
)

// VLESSOptions configures a VLESS outbound. The hop is plaintext unless TLS or
// REALITY secures it; the protocol itself is stateless and has no inner
// encryption.
type VLESSOptions struct {
	Server  string
	Port    int
	UUID    string
	Flow    string
	TLS     TLSOptions
	Reality *RealityOptions
	Timeout time.Duration
}

// VLESS is a VLESS outbound. Every dial opens its own connection: the protocol
// has no multiplexing in this build.
type VLESS struct {
	server  string
	host    string
	uuid    [16]byte
	flow    string
	addons  []byte
	tls     TLSOptions
	reality *RealityOptions
	timeout time.Duration
}

// NewVLESS builds a VLESS outbound.
func NewVLESS(opts VLESSOptions) (*VLESS, error) {
	if err := validateServer(opts.Server, opts.Port); err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	id, err := parseVMessUUID(opts.UUID)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	addons, err := vlessAddons(opts.Flow)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	tlsOpts := opts.TLS
	var reality *RealityOptions
	if opts.Reality != nil {
		if err := opts.Reality.validate(); err != nil {
			return nil, fmt.Errorf("vless: %w", err)
		}
		tlsOpts.Enabled = true
		// REALITY lives on the same TLS 1.3 handshake as the camouflage site,
		// so the client has to offer a browser-shaped ALPN list unless the
		// configuration names one.
		if len(tlsOpts.ALPN) == 0 {
			tlsOpts.ALPN = []string{"h2", "http/1.1"}
		}
		// The handshake and the tunnel share one ALPN list, so the copy the
		// handshake keeps is the one the caller configured.
		realityCopy := *opts.Reality
		realityCopy.ALPN = tlsOpts.ALPN
		reality = &realityCopy
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &VLESS{
		server:  net.JoinHostPort(opts.Server, strconv.Itoa(opts.Port)),
		host:    opts.Server,
		uuid:    id,
		flow:    normalizeFlow(opts.Flow),
		addons:  addons,
		tls:     tlsOpts,
		reality: reality,
		timeout: timeout,
	}, nil
}

// newVLESSFromSpec reads a [Proxy] line. The account identifier may be written
// positionally or as uuid=.
func newVLESSFromSpec(spec Spec) (Dialer, error) {
	allowed := optionSet(map[string]bool{
		optUUID: true, optFlow: true, optReality: true, optShortID: true,
	}, tlsOptionKeys)
	opts, positional, err := parseArgs(spec.Args, allowed)
	if err != nil {
		return nil, err
	}
	id := opts[optUUID]
	if id == "" && len(positional) > 0 {
		id, positional = positional[0], positional[1:]
	}
	if id == "" {
		return nil, fmt.Errorf("%w: vless needs a uuid", ErrInvalidOption)
	}
	if len(positional) > 0 {
		return nil, fmt.Errorf("%w: unexpected argument %q", ErrInvalidOption, positional[0])
	}

	var reality *RealityOptions
	_, hasTLS := opts[optTLS]
	if value, ok := opts[optReality]; ok {
		if hasTLS {
			return nil, fmt.Errorf("%w: tls= and reality= cannot be combined; reality decides how the hop is secured", ErrInvalidOption)
		}
		reality, err = parseRealityOptions(value, opts[optShortID], opts[optSNI])
		if err != nil {
			return nil, err
		}
	}
	tlsOpts, err := parseTLSOptions(opts, tlsOptional)
	if err != nil {
		return nil, err
	}
	if !hasTLS && reality == nil {
		return nil, fmt.Errorf("%w: vless carries no encryption of its own; write tls=true or reality=", ErrInvalidOption)
	}
	if _, ok := opts[optShortID]; ok && reality == nil {
		return nil, fmt.Errorf("%w: short-id only means something with reality=", ErrInvalidOption)
	}
	return NewVLESS(VLESSOptions{
		Server: spec.Server, Port: spec.Port, UUID: id,
		Flow: opts[optFlow], TLS: tlsOpts, Reality: reality,
	})
}

// normalizeFlow maps the accepted spellings of "no flow" to the empty string.
// Every other value is rejected by vlessAddons, so this only has to know the
// off switch.
func normalizeFlow(flow string) string {
	flow = strings.ToLower(strings.TrimSpace(flow))
	if flow == "none" {
		return ""
	}
	return flow
}

// vlessAddons encodes the addons block of a request. The block is a protobuf
// message with a single string field (the flow); the field tag is 0x0a, so the
// encoding is that byte, a length and the name.
//
// Only the empty flow is implemented. The vision flow is not a plain marker: a
// peer that reads it expects the client to pad the record stream in a format
// the public protocol description does not define, and a guess would produce a
// connection that looks established and then corrupts the first bytes of the
// stream. Refusing it here is what keeps such a configuration from silently
// turning into a broken tunnel.
func vlessAddons(flow string) ([]byte, error) {
	switch normalizeFlow(flow) {
	case "":
		return nil, nil
	case vlessFlowVision:
		return nil, fmt.Errorf("%w: flow %q needs record-level padding that this build does not implement; leave flow unset", ErrInvalidOption, flow)
	default:
		return nil, fmt.Errorf("%w: unknown flow %q", ErrInvalidOption, flow)
	}
}

// DialContext implements Dialer with the TCP command.
func (v *VLESS) DialContext(ctx context.Context, address string) (net.Conn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	if err := vlessAddressFits(target); err != nil {
		return nil, err
	}
	conn, err := v.dialHop(ctx)
	if err != nil {
		return nil, err
	}
	return completeHandshake(ctx, conn, func(c net.Conn) (net.Conn, error) {
		if err := v.writeRequest(c, vlessCommandTCP, target); err != nil {
			return nil, err
		}
		if err := v.readResponse(c); err != nil {
			return nil, err
		}
		return c, nil
	})
}

// DialPacket implements Dialer with the UDP command. Each datagram on the
// returned connection is framed with its own length.
func (v *VLESS) DialPacket(ctx context.Context, address string) (PacketConn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	if err := vlessAddressFits(target); err != nil {
		return nil, err
	}
	conn, err := v.dialHop(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := completeHandshake(ctx, conn, func(c net.Conn) (net.Conn, error) {
		if err := v.writeRequest(c, vlessCommandUDP, target); err != nil {
			return nil, err
		}
		if err := v.readResponse(c); err != nil {
			return nil, err
		}
		return &vlessPacketConn{conn: c, reader: bufio.NewReader(c), dest: target}, nil
	})
	if err != nil {
		return nil, err
	}
	return stream.(PacketConn), nil
}

// dialHop opens the transport and secures it with TLS or REALITY.
func (v *VLESS) dialHop(ctx context.Context) (net.Conn, error) {
	if v.reality != nil {
		conn, err := dialProxyHop(ctx, v.server, v.host, v.timeout, TLSOptions{})
		if err != nil {
			return nil, fmt.Errorf("vless: %w", err)
		}
		secured, err := v.reality.Dial(ctx, conn, v.host)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("vless: %w", err)
		}
		return secured, nil
	}
	conn, err := dialProxyHop(ctx, v.server, v.host, v.timeout, v.tls)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	return conn, nil
}

// writeRequest writes the header. The first payload is not appended: the
// protocol allows it, but sending the header on its own keeps the first write
// the size the addons block says it is, which is what a peer expects before it
// has any payload to forward.
func (v *VLESS) writeRequest(w io.Writer, command byte, target Target) error {
	buf := make([]byte, 0, 1+len(v.uuid)+1+len(v.addons)+1+2+MaxUDPHeaderLen)
	buf = append(buf, vlessVersion)
	buf = append(buf, v.uuid[:]...)
	buf = append(buf, byte(len(v.addons)))
	buf = append(buf, v.addons...)
	buf = append(buf, command)
	buf = appendVLESAddress(buf, target)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("vless: write request: %w", err)
	}
	return nil
}

// readResponse consumes the response header. The server reports nothing but a
// version and its own addons, so a mismatch means the peer is not speaking this
// protocol and the stream cannot be trusted.
func (v *VLESS) readResponse(r io.Reader) error {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return fmt.Errorf("vless: read response header: %w", err)
	}
	if head[0] != vlessVersion {
		return fmt.Errorf("vless: response has version %d, want %d", head[0], vlessVersion)
	}
	if head[1] == 0 {
		return nil
	}
	addons := make([]byte, head[1])
	if _, err := io.ReadFull(r, addons); err != nil {
		return fmt.Errorf("vless: read response addons: %w", err)
	}
	return nil
}

func vlessAddressFits(target Target) error {
	if !target.IsIP() && len(target.Host) > 255 {
		return fmt.Errorf("vless: %w: address name is too long", ErrInvalidAddress)
	}
	return nil
}

// appendVLESAddress writes the port, the address type and the address, in that
// order: VLESS copies the command block of VMess, which puts the port before
// the address.
func appendVLESAddress(dst []byte, target Target) []byte {
	dst = binary.BigEndian.AppendUint16(dst, target.Port)
	if ip := net.ParseIP(target.Host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(dst, vlessATYPIPv4)
			return append(dst, v4...)
		}
		dst = append(dst, vlessATYPIPv6)
		return append(dst, ip.To16()...)
	}
	dst = append(dst, vlessATYPDomain, byte(len(target.Host)))
	return append(dst, target.Host...)
}

// vlessOpenRequest reads one request header from a stream. The local test peer
// uses it, so the parsing side of the wire format is exercised by the same code
// the tests assert against instead of a second, drifting copy.
func vlessOpenRequest(r io.Reader, expectedUUID [16]byte) (Target, byte, []byte, error) {
	var head [1]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Target{}, 0, nil, fmt.Errorf("vless: read version: %w", err)
	}
	if head[0] != vlessVersion {
		return Target{}, 0, nil, fmt.Errorf("vless: request has version %d", head[0])
	}
	var id [16]byte
	if _, err := io.ReadFull(r, id[:]); err != nil {
		return Target{}, 0, nil, fmt.Errorf("vless: read uuid: %w", err)
	}
	if id != expectedUUID {
		return Target{}, 0, nil, errors.New("vless: request carries an unknown account")
	}
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Target{}, 0, nil, fmt.Errorf("vless: read addons length: %w", err)
	}
	var addons []byte
	if length := int(head[0]); length > 0 {
		addons = make([]byte, length)
		if _, err := io.ReadFull(r, addons); err != nil {
			return Target{}, 0, nil, fmt.Errorf("vless: read addons: %w", err)
		}
	}
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Target{}, 0, nil, fmt.Errorf("vless: read command: %w", err)
	}
	command := head[0]
	target, err := readVLESAddress(r)
	if err != nil {
		return Target{}, 0, nil, err
	}
	return target, command, addons, nil
}

// readVLESAddress reads the port, the address type and the address.
func readVLESAddress(r io.Reader) (Target, error) {
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Target{}, fmt.Errorf("vless: read port: %w", err)
	}
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Target{}, fmt.Errorf("vless: read address type: %w", err)
	}
	var host string
	switch atyp[0] {
	case vlessATYPIPv4:
		var b [net.IPv4len]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Target{}, fmt.Errorf("vless: read ipv4 address: %w", err)
		}
		host = net.IP(b[:]).String()
	case vlessATYPIPv6:
		var b [net.IPv6len]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Target{}, fmt.Errorf("vless: read ipv6 address: %w", err)
		}
		host = net.IP(b[:]).String()
	case vlessATYPDomain:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return Target{}, fmt.Errorf("vless: read name length: %w", err)
		}
		if length[0] == 0 {
			return Target{}, errors.New("vless: request carries an empty name")
		}
		b := make([]byte, length[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return Target{}, fmt.Errorf("vless: read name: %w", err)
		}
		host = string(b)
	default:
		return Target{}, fmt.Errorf("vless: unsupported address type %#x", atyp[0])
	}
	return Target{Host: host, Port: binary.BigEndian.Uint16(port[:])}, nil
}

// vlessWriteResponse writes the response header: the version and an empty
// addons block.
func vlessWriteResponse(w io.Writer) error {
	if _, err := w.Write([]byte{vlessVersion, 0}); err != nil {
		return fmt.Errorf("vless: write response: %w", err)
	}
	return nil
}

// vlessPacketConn carries one destination's datagrams over the stream.
type vlessPacketConn struct {
	conn   net.Conn
	reader *bufio.Reader
	dest   Target

	wmu sync.Mutex
	rmu sync.Mutex
}

func (c *vlessPacketConn) Write(p []byte) (int, error) {
	if len(p) > vlessMaxDatagram {
		return 0, fmt.Errorf("vless: datagram of %d bytes exceeds %d", len(p), vlessMaxDatagram)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	buf := make([]byte, 0, vlessLengthPrefix+len(p))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(p)))
	buf = append(buf, p...)
	if _, err := c.conn.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *vlessPacketConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var head [vlessLengthPrefix]byte
	if _, err := io.ReadFull(c.reader, head[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(head[:]))
	if length == 0 {
		return 0, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return 0, err
	}
	return copy(p, payload), nil
}

func (c *vlessPacketConn) Close() error                       { return c.conn.Close() }
func (c *vlessPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *vlessPacketConn) RemoteAddr() net.Addr               { return c.dest }
func (c *vlessPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *vlessPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *vlessPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

var _ PacketConn = (*vlessPacketConn)(nil)
