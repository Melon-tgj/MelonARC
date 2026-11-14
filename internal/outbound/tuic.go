package outbound

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// TUIC frames everything as a version byte, a command byte and then the
// command's own fields. TCP is one bidirectional stream per connection; UDP is
// a datagram per packet, tagged with the association and the fragment it
// belongs to.
const (
	tuicVersion = 0x05

	tuicCommandAuthenticate = 0x00
	tuicCommandConnect      = 0x01
	tuicCommandPacket       = 0x02
	tuicCommandDissociate   = 0x03
	tuicCommandHeartbeat    = 0x04

	// TUIC numbers address types its own way: no address, a name, IPv4, IPv6.
	tuicAddressNone   = 0xff
	tuicAddressDomain = 0x00
	tuicAddressIPv4   = 0x01
	tuicAddressIPv6   = 0x02

	tuicTokenLen = 32
	// tuicMaxDatagram keeps one datagram frame inside the payload a QUIC path
	// is guaranteed to carry.
	tuicMaxDatagram  = 1100
	tuicMaxFragments = 255
)

// TUICOptions configures a TUIC outbound.
type TUICOptions struct {
	Server   string
	Port     int
	UUID     string
	Password string
	TLS      TLSOptions
	Timeout  time.Duration
}

// TUIC is a QUIC outbound that authenticates with a token derived from the TLS
// session, tunnels TCP over streams and UDP over datagrams.
type TUIC struct {
	server  string
	host    string
	uuid    [16]byte
	uuidTxt string
	secret  string
	timeout time.Duration
	session *quicSession

	// nextAssoc hands out association ids. They are 16 bits and a connection
	// carries one per UDP flow, so a random id collides often enough to
	// matter; a counter cannot, because ids are released as flows close.
	nextAssoc atomic.Uint32
}

// NewTUIC builds a TUIC outbound.
func NewTUIC(opts TUICOptions) (*TUIC, error) {
	if err := validateServer(opts.Server, opts.Port); err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	id, err := parseVMessUUID(opts.UUID)
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	if opts.Password == "" {
		return nil, fmt.Errorf("tuic: %w: password is required", ErrInvalidOption)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	tlsOpts := opts.TLS
	tlsOpts.Enabled = true // the protocol has no plaintext variant
	if len(tlsOpts.ALPN) == 0 {
		tlsOpts.ALPN = []string{"h3"}
	}
	t := &TUIC{
		server:  net.JoinHostPort(opts.Server, strconv.Itoa(opts.Port)),
		host:    opts.Server,
		uuid:    id,
		uuidTxt: formatUUID(id),
		secret:  opts.Password,
		timeout: timeout,
	}
	tlsConfig, quicConfig, err := quicDialConfig(tlsOpts, t.host, true)
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	dial := func(ctx context.Context) (*quic.Conn, error) {
		conn, err := dialQUIC(ctx, t.server, tlsConfig, quicConfig, nil)
		if err != nil {
			return nil, fmt.Errorf("tuic: %w", err)
		}
		if err := t.authenticate(ctx, conn); err != nil {
			_ = conn.CloseWithError(0, "no auth")
			return nil, err
		}
		return conn, nil
	}
	t.session = newQUICSession(dial, newDatagramMux(tuicDatagramKey), DefaultQUICIdleTimeout)
	return t, nil
}

// newTUICFromSpec reads a [Proxy] line.
func newTUICFromSpec(spec Spec) (Dialer, error) {
	allowed := optionSet(map[string]bool{
		optUUID: true, optPassword: true,
	}, tlsOptionKeys)
	opts, positional, err := parseArgs(spec.Args, allowed)
	if err != nil {
		return nil, err
	}
	id := opts[optUUID]
	if id == "" && len(positional) > 0 {
		id, positional = positional[0], positional[1:]
	}
	secret := opts[optPassword]
	if secret == "" && len(positional) > 0 {
		secret, positional = positional[0], positional[1:]
	}
	if id == "" {
		return nil, fmt.Errorf("%w: tuic needs a uuid", ErrInvalidOption)
	}
	if secret == "" {
		return nil, fmt.Errorf("%w: tuic needs a password", ErrInvalidOption)
	}
	if len(positional) > 0 {
		return nil, fmt.Errorf("%w: unexpected argument %q", ErrInvalidOption, positional[0])
	}
	// The kind table, not this function, decides which TLS keys a type
	// accepts; both QUIC types are TLS by definition.
	tlsOpts, err := parseTLSOptions(opts, tlsModeFor("tuic"))
	if err != nil {
		return nil, err
	}
	return NewTUIC(TUICOptions{
		Server: spec.Server, Port: spec.Port,
		UUID: id, Password: secret, TLS: tlsOpts,
	})
}

// Close closes the shared QUIC connection.
func (t *TUIC) Close() error { return t.session.Close() }

// Disown retires the shared connection without cutting what it carries, so a
// reload that drops this outbound does not leave a socket behind.
func (t *TUIC) Disown() { t.session.Disown() }

// authenticate sends the Authenticate command. Its token is not a password on
// the wire: each side derives it from the TLS session, so a recorded handshake
// cannot be replayed against another one.
func (t *TUIC) authenticate(ctx context.Context, conn *quic.Conn) error {
	state := conn.ConnectionState().TLS
	token, err := state.ExportKeyingMaterial(t.uuidTxt, []byte(t.secret), tuicTokenLen)
	if err != nil {
		return fmt.Errorf("tuic: derive the authentication token: %w", err)
	}
	stream, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("tuic: open the authentication stream: %w", err)
	}
	command := []byte{tuicVersion, tuicCommandAuthenticate}
	command = append(command, t.uuid[:]...)
	command = append(command, token...)
	if _, err := stream.Write(command); err != nil {
		return fmt.Errorf("tuic: write the authentication command: %w", err)
	}
	// The command is complete; the stream stays open because closing it is
	// what a peer may interpret as a failure of the handshake.
	return nil
}

// DialContext implements Dialer with the Connect command.
func (t *TUIC) DialContext(ctx context.Context, address string) (net.Conn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	conn, release, err := t.session.acquire(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		release()
		return nil, fmt.Errorf("tuic: open a stream: %w", err)
	}
	if err := setStreamDeadline(stream, ctx, t.timeout); err != nil {
		_ = stream.Close()
		release()
		return nil, err
	}
	command := []byte{tuicVersion, tuicCommandConnect}
	command = appendTUICAddress(command, target)
	if _, err := stream.Write(command); err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		release()
		return nil, fmt.Errorf("tuic: write the connect command: %w", err)
	}
	// There is no answer: once the command is written the stream is the tunnel.
	_ = stream.SetDeadline(time.Time{})
	return &quicStreamConn{stream: stream, conn: conn, remote: target, release: release}, nil
}

// DialPacket implements Dialer with the Packet command.
func (t *TUIC) DialPacket(ctx context.Context, address string) (PacketConn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	conn, release, err := t.session.acquire(ctx)
	if err != nil {
		return nil, err
	}
	if !conn.ConnectionState().SupportsDatagrams.Remote {
		release()
		return nil, errors.New("tuic: the server does not support datagrams")
	}
	assoc := uint16(t.nextAssoc.Add(1))
	if assoc == 0 {
		assoc = 1
	}
	incoming, unsubscribe := t.session.mux.subscribe(uint32(assoc))
	packet := &tuicPacketConn{
		conn: conn, release: release, unsubscribe: unsubscribe,
		incoming: incoming, dest: target, assoc: assoc,
		fragment: newDatagramReassembler(),
		closed:   make(chan struct{}),
	}
	return packet, nil
}

// tuicDatagramKey reads the association id of a datagram.
func tuicDatagramKey(payload []byte) (uint32, bool) {
	if len(payload) < 4 {
		return 0, false
	}
	return uint32(binary.BigEndian.Uint16(payload[2:4])), true
}

// formatUUID renders an account identifier the way a configuration writes it:
// lowercase and hyphenated. The token both sides derive is keyed by this
// string, so a configuration that spells the same identifier differently must
// still produce the same label.
func formatUUID(id [16]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, b := range id {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}

// appendTUICAddress writes a TUIC address: its type, the address and the port.
func appendTUICAddress(dst []byte, target Target) []byte {
	if ip := net.ParseIP(target.Host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(dst, tuicAddressIPv4)
			dst = append(dst, v4...)
			return binary.BigEndian.AppendUint16(dst, target.Port)
		}
		dst = append(dst, tuicAddressIPv6)
		dst = append(dst, ip.To16()...)
		return binary.BigEndian.AppendUint16(dst, target.Port)
	}
	dst = append(dst, tuicAddressDomain, byte(len(target.Host)))
	dst = append(dst, target.Host...)
	return binary.BigEndian.AppendUint16(dst, target.Port)
}

// readTUICAddress reads one address, which the local test peer uses.
func readTUICAddress(r io.Reader) (Target, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Target{}, err
	}
	var host string
	switch atyp[0] {
	case tuicAddressIPv4:
		var b [net.IPv4len]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Target{}, err
		}
		host = net.IP(b[:]).String()
	case tuicAddressIPv6:
		var b [net.IPv6len]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Target{}, err
		}
		host = net.IP(b[:]).String()
	case tuicAddressDomain:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return Target{}, err
		}
		if length[0] == 0 {
			return Target{}, errors.New("tuic: empty address name")
		}
		b := make([]byte, length[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return Target{}, err
		}
		host = string(b)
	case tuicAddressNone:
		return Target{}, errors.New("tuic: a connect command cannot carry an empty address")
	default:
		return Target{}, fmt.Errorf("tuic: unsupported address type %#x", atyp[0])
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Target{}, err
	}
	return Target{Host: host, Port: binary.BigEndian.Uint16(port[:])}, nil
}

// tuicPacketConn is one UDP association over the shared connection.
type tuicPacketConn struct {
	conn        *quic.Conn
	release     func()
	unsubscribe func()
	incoming    <-chan []byte
	dest        Target
	assoc       uint16
	fragment    *datagramReassembler

	mu     sync.Mutex
	nextID uint16

	closeOnce sync.Once
	closed    chan struct{}

	deadline datagramDeadline
}

func (c *tuicPacketConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.deadline.expired() {
		return 0, os.ErrDeadlineExceeded
	}
	header := []byte{tuicVersion, tuicCommandPacket}
	header = binary.BigEndian.AppendUint16(header, c.assoc)
	packetID := c.nextPacketID()
	address := appendTUICAddress(nil, c.dest)
	// A packet frame is version, command, association, packet id, fragment
	// total, fragment index, size, address and payload.
	fixed := len(header) + 2 + 1 + 1 + 2
	room := tuicMaxDatagram - fixed - len(address)
	if room <= 0 {
		return 0, errors.New("tuic: the destination address leaves no room for a payload")
	}
	count := (len(p) + room - 1) / room
	if count > tuicMaxFragments {
		return 0, fmt.Errorf("tuic: datagram of %d bytes needs %d fragments, more than %d",
			len(p), count, tuicMaxFragments)
	}
	for index := 0; index < count; index++ {
		start := index * room
		end := min(start+room, len(p))
		frame := make([]byte, 0, fixed+len(address)+(end-start))
		frame = append(frame, header...)
		frame = binary.BigEndian.AppendUint16(frame, packetID)
		frame = append(frame, byte(count), byte(index))
		frame = binary.BigEndian.AppendUint16(frame, uint16(end-start))
		if index == 0 {
			frame = append(frame, address...)
		} else {
			// Only the first fragment names the destination.
			frame = append(frame, tuicAddressNone)
		}
		frame = append(frame, p[start:end]...)
		if err := c.conn.SendDatagram(frame); err != nil {
			return 0, fmt.Errorf("tuic: send a datagram: %w", err)
		}
	}
	return len(p), nil
}

func (c *tuicPacketConn) nextPacketID() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextID
	c.nextID++
	return id
}

func (c *tuicPacketConn) Read(p []byte) (int, error) {
	for {
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		case payload, ok := <-c.incoming:
			if !ok {
				return 0, io.EOF
			}
			complete, err := c.assemble(payload)
			if err != nil {
				continue // a malformed datagram is dropped
			}
			if complete == nil {
				continue // a fragment, waiting for its siblings
			}
			return copy(p, complete), nil
		case <-c.deadline.channel():
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// assemble turns one datagram into a payload, or into nil while a fragmented
// packet is incomplete.
func (c *tuicPacketConn) assemble(datagram []byte) ([]byte, error) {
	// The frame is version, command, association, packet id, fragment total,
	// fragment index and size, so anything shorter than ten bytes cannot be
	// one.
	if len(datagram) < 10 {
		return nil, errors.New("tuic: truncated datagram")
	}
	if datagram[0] != tuicVersion || datagram[1] != tuicCommandPacket {
		return nil, errors.New("tuic: the datagram is not a packet command")
	}
	if binary.BigEndian.Uint16(datagram[2:4]) != c.assoc {
		return nil, errors.New("tuic: datagram for another association")
	}
	packetID := binary.BigEndian.Uint16(datagram[4:6])
	count := int(datagram[6])
	index := int(datagram[7])
	size := int(binary.BigEndian.Uint16(datagram[8:10]))
	rest := datagram[10:]
	// Every fragment carries an address field, even the ones that use the
	// "none" type, so the payload always starts after one.
	if len(rest) == 0 {
		return nil, errors.New("tuic: truncated datagram address")
	}
	addressLen, err := tuicEncodedAddressLen(rest)
	if err != nil {
		return nil, err
	}
	if len(rest) < addressLen+size {
		return nil, errors.New("tuic: truncated datagram payload")
	}
	return c.fragment.add(packetID, index, count, rest[addressLen:addressLen+size])
}

// tuicEncodedAddressLen returns the size of the address at the front of b.
func tuicEncodedAddressLen(b []byte) (int, error) {
	switch b[0] {
	case tuicAddressNone:
		return 1, nil
	case tuicAddressIPv4:
		return 1 + net.IPv4len + 2, nil
	case tuicAddressIPv6:
		return 1 + net.IPv6len + 2, nil
	case tuicAddressDomain:
		if len(b) < 2 {
			return 0, errors.New("tuic: truncated address name")
		}
		return 1 + 1 + int(b[1]) + 2, nil
	default:
		return 0, fmt.Errorf("tuic: unsupported address type %#x", b[0])
	}
}

// Close ends the association: the peer is told to release the socket, and the
// connection loses one reference.
func (c *tuicPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.unsubscribe()
		// The dissociate command goes out while the connection is still
		// referenced: releasing first would let an idle session close it
		// underneath the command.
		c.dissociate()
		c.release()
	})
	return nil
}

// dissociate tells the server to drop the association. It is best effort: the
// association also expires on the server when it stays idle.
func (c *tuicPacketConn) dissociate() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := c.conn.OpenUniStreamSync(ctx)
	if err != nil {
		return
	}
	command := []byte{tuicVersion, tuicCommandDissociate}
	command = binary.BigEndian.AppendUint16(command, c.assoc)
	_, _ = stream.Write(command)
	_ = stream.Close()
}

func (c *tuicPacketConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *tuicPacketConn) RemoteAddr() net.Addr { return c.dest }

func (c *tuicPacketConn) SetDeadline(t time.Time) error      { return c.deadline.set(t) }
func (c *tuicPacketConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *tuicPacketConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

var _ PacketConn = (*tuicPacketConn)(nil)
