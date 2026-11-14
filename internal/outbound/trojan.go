package outbound

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// The Trojan request is the hexadecimal SHA-224 of the password, a CRLF, a
// SOCKS5-like command and address, another CRLF, then the first payload bytes.
// Datagrams reuse the same TLS connection and carry their own address header.
const (
	trojanCommandConnect      = 0x01
	trojanCommandUDPAssociate = 0x03
	trojanCRLF                = "\r\n"
	trojanMaxDatagram         = 0xFFFF
)

// TrojanOptions configures a Trojan outbound. The hop is always TLS: the
// protocol has no plaintext variant, so the type itself enables the TLS base.
type TrojanOptions struct {
	Server   string
	Port     int
	Password string
	TLS      TLSOptions
	Timeout  time.Duration
}

// Trojan is the TLS-only Trojan outbound. TCP uses CONNECT; UDP uses the
// UDP ASSOCIATE command and frames each datagram on the same TLS stream.
type Trojan struct {
	server   string
	host     string
	authHash string
	tls      TLSOptions
	timeout  time.Duration
}

// NewTrojan builds a Trojan outbound.
func NewTrojan(opts TrojanOptions) (*Trojan, error) {
	if err := validateServer(opts.Server, opts.Port); err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	if opts.Password == "" {
		return nil, fmt.Errorf("trojan: %w: password is required", ErrInvalidOption)
	}
	tlsOpts := opts.TLS
	tlsOpts.Enabled = true // the type, not a switch, decides that TLS is used
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	sum := sha256.Sum224([]byte(opts.Password))
	return &Trojan{
		server:   net.JoinHostPort(opts.Server, strconv.Itoa(opts.Port)),
		host:     opts.Server,
		authHash: hex.EncodeToString(sum[:]),
		tls:      tlsOpts,
		timeout:  timeout,
	}, nil
}

// newTrojanFromSpec reads a [Proxy] line. The password may be written
// positionally or as password=.
func newTrojanFromSpec(spec Spec) (Dialer, error) {
	allowed := optionSet(map[string]bool{optPassword: true}, tlsOptionKeys)
	opts, positional, err := parseArgs(spec.Args, allowed)
	if err != nil {
		return nil, err
	}
	secret, err := positionalCredential(opts, positional, optPassword)
	if err != nil {
		return nil, err
	}
	tlsOpts, err := parseTLSOptions(opts, tlsAlways)
	if err != nil {
		return nil, err
	}
	return NewTrojan(TrojanOptions{
		Server: spec.Server, Port: spec.Port, Password: secret, TLS: tlsOpts,
	})
}

// DialContext implements Dialer with a CONNECT request. There is no reply on
// the wire: once the request is written the connection is the tunnel.
func (t *Trojan) DialContext(ctx context.Context, address string) (net.Conn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	if err := trojanAddressFits(target); err != nil {
		return nil, err
	}
	conn, err := dialProxyHop(ctx, t.server, t.host, t.timeout, t.tls)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	return completeHandshake(ctx, conn, func(c net.Conn) (net.Conn, error) {
		if err := t.writeRequest(c, trojanCommandConnect, target, nil); err != nil {
			return nil, err
		}
		return c, nil
	})
}

// DialPacket implements Dialer with UDP ASSOCIATE. The returned connection
// frames one datagram per write and strips the same framing on read.
func (t *Trojan) DialPacket(ctx context.Context, address string) (PacketConn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	if err := trojanAddressFits(target); err != nil {
		return nil, err
	}
	conn, err := dialProxyHop(ctx, t.server, t.host, t.timeout, t.tls)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	stream, err := completeHandshake(ctx, conn, func(c net.Conn) (net.Conn, error) {
		if err := t.writeRequest(c, trojanCommandUDPAssociate, target, nil); err != nil {
			return nil, err
		}
		return &trojanPacketConn{
			conn: c, reader: bufio.NewReader(c), dest: target,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return stream.(PacketConn), nil
}

func trojanAddressFits(target Target) error {
	if !target.IsIP() && len(target.Host) > 255 {
		return fmt.Errorf("trojan: %w: address name is too long", ErrInvalidAddress)
	}
	return nil
}

// writeRequest writes the authentication hash, the command and address and
// the CRLF that ends the request. Payload is the first tunnel bytes, which may
// be empty; the protocol allows appending them to the same first packet.
func (t *Trojan) writeRequest(w io.Writer, command byte, target Target, payload []byte) error {
	buf := make([]byte, 0, 56+2+MaxUDPHeaderLen+2+len(payload))
	buf = append(buf, t.authHash...)
	buf = append(buf, trojanCRLF...)
	buf = append(buf, command)
	buf = AppendAddress(buf, target)
	buf = append(buf, trojanCRLF...)
	buf = append(buf, payload...)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("trojan: write request: %w", err)
	}
	return nil
}

// trojanPacketConn carries one destination's datagrams over the TLS stream.
type trojanPacketConn struct {
	conn   net.Conn
	reader *bufio.Reader
	dest   Target

	wmu sync.Mutex
	rmu sync.Mutex
}

func (c *trojanPacketConn) Write(p []byte) (int, error) {
	if len(p) > trojanMaxDatagram {
		return 0, fmt.Errorf("trojan: datagram of %d bytes exceeds %d", len(p), trojanMaxDatagram)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	buf := AppendAddress(nil, c.dest)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(p)))
	buf = append(buf, trojanCRLF...)
	buf = append(buf, p...)
	if _, err := c.conn.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *trojanPacketConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var atyp [1]byte
	if _, err := io.ReadFull(c.reader, atyp[:]); err != nil {
		return 0, err
	}
	host, err := readAddress(c.reader, atyp[0])
	if err != nil {
		return 0, err
	}
	var tail [4]byte // port, length
	if _, err := io.ReadFull(c.reader, tail[:]); err != nil {
		return 0, err
	}
	var crlf [2]byte
	if _, err := io.ReadFull(c.reader, crlf[:]); err != nil {
		return 0, err
	}
	if crlf != [2]byte{'\r', '\n'} {
		return 0, errors.New("trojan: udp packet has no CRLF after its header")
	}
	length := int(binary.BigEndian.Uint16(tail[2:]))
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return 0, err
	}
	_ = host // the source address is validated but not returned by PacketConn
	return copy(p, payload), nil
}

func (c *trojanPacketConn) Close() error                       { return c.conn.Close() }
func (c *trojanPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *trojanPacketConn) RemoteAddr() net.Addr               { return c.dest }
func (c *trojanPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *trojanPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *trojanPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

var _ PacketConn = (*trojanPacketConn)(nil)
