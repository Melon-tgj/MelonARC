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
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/blake2b"
)

// The Hysteria2 wire format: an HTTP/3 request authenticates the connection,
// one QUIC stream per TCP connection, and QUIC datagrams for UDP.
//
// Everything below the authentication is length prefixed with QUIC varints, and
// datagrams carry a session id so that a single QUIC connection can serve
// several UDP associations at once.
const (
	hysteria2FrameTCPRequest = 0x401
	hysteria2StatusOK        = 0x00
	hysteria2AuthPath        = "/auth"
	hysteria2AuthHost        = "hysteria"
	hysteria2AuthOK          = 233

	// hysteria2MaxDatagram bounds one datagram frame. QUIC guarantees only a
	// 1200-byte payload path, so a message that has to fit in one packet is
	// kept well below that; larger payloads are fragmented.
	hysteria2MaxDatagram  = 1100
	hysteria2MaxFragments = 255

	hysteria2ObfsSalamander = "salamander"
)

// Hysteria2Options configures a Hysteria2 outbound.
type Hysteria2Options struct {
	Server   string
	Port     int
	Password string
	// Up and Down are the rates the client declares, in bytes per second. Zero
	// means "do not declare one", which leaves the choice of congestion
	// control to the peer.
	Up   uint64
	Down uint64
	// Obfs names the optional obfuscation of the UDP layer; the only supported
	// value is "salamander", and it needs ObfsPassword.
	Obfs         string
	ObfsPassword string
	TLS          TLSOptions
	Timeout      time.Duration
}

// Hysteria2 is a QUIC outbound that tunnels TCP over streams and UDP over
// datagrams.
type Hysteria2 struct {
	server  string
	host    string
	auth    string
	rx      uint64
	timeout time.Duration
	obfs    *salamander
	session *quicSession
}

// NewHysteria2 builds a Hysteria2 outbound.
func NewHysteria2(opts Hysteria2Options) (*Hysteria2, error) {
	if err := validateServer(opts.Server, opts.Port); err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	if opts.Password == "" {
		return nil, fmt.Errorf("hysteria2: %w: password is required", ErrInvalidOption)
	}
	obfs, err := newSalamander(opts.Obfs, opts.ObfsPassword)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
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
	h := &Hysteria2{
		server:  net.JoinHostPort(opts.Server, strconv.Itoa(opts.Port)),
		host:    opts.Server,
		auth:    opts.Password,
		rx:      opts.Down,
		timeout: timeout,
		obfs:    obfs,
	}
	session, err := h.newSession(tlsOpts)
	if err != nil {
		return nil, err
	}
	h.session = session
	return h, nil
}

// newSession builds the lazily dialled connection of this outbound.
func (h *Hysteria2) newSession(tlsOpts TLSOptions) (*quicSession, error) {
	tlsConfig, quicConfig, err := quicDialConfig(tlsOpts, h.host, true)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	var wrap func(net.PacketConn) (net.PacketConn, error)
	if h.obfs != nil {
		wrap = h.obfs.wrap
	}
	dial := func(ctx context.Context) (*quic.Conn, error) {
		conn, err := dialQUIC(ctx, h.server, tlsConfig, quicConfig, wrap)
		if err != nil {
			return nil, fmt.Errorf("hysteria2: %w", err)
		}
		client, err := newH3Client(ctx, conn)
		if err != nil {
			_ = conn.CloseWithError(0, "no http3")
			return nil, fmt.Errorf("hysteria2: %w", err)
		}
		headers := [][2]string{
			{"hysteria-auth", h.auth},
			{"hysteria-cc-rx", strconv.FormatUint(h.rx, 10)},
		}
		if padding, err := randomBytes(8 + len(h.auth)); err == nil {
			headers = append(headers, [2]string{"hysteria-padding", string(padding)})
		}
		status, err := client.do(ctx, hysteria2AuthHost, hysteria2AuthPath, headers)
		if err != nil {
			_ = conn.CloseWithError(0, "no auth")
			return nil, fmt.Errorf("hysteria2: %w", err)
		}
		if status != hysteria2AuthOK {
			_ = conn.CloseWithError(0, "auth rejected")
			return nil, fmt.Errorf("hysteria2: the server refused the credentials with status %d", status)
		}
		return conn, nil
	}
	return newQUICSession(dial, newDatagramMux(hysteria2DatagramKey), DefaultQUICIdleTimeout), nil
}

// newHysteria2FromSpec reads a [Proxy] line.
func newHysteria2FromSpec(spec Spec) (Dialer, error) {
	allowed := optionSet(map[string]bool{
		optPassword: true, optUp: true, optDown: true, optObfs: true, optObfsPassword: true,
	}, tlsOptionKeys)
	opts, positional, err := parseArgs(spec.Args, allowed)
	if err != nil {
		return nil, err
	}
	secret, err := positionalCredential(opts, positional, optPassword)
	if err != nil {
		return nil, err
	}
	if len(positional) > 1 {
		return nil, fmt.Errorf("%w: unexpected argument %q", ErrInvalidOption, positional[1])
	}
	up, err := parseRate(opts[optUp])
	if err != nil {
		return nil, fmt.Errorf("%w: up: %v", ErrInvalidOption, err)
	}
	down, err := parseRate(opts[optDown])
	if err != nil {
		return nil, fmt.Errorf("%w: down: %v", ErrInvalidOption, err)
	}
	// The kind table, not this function, decides which TLS keys a type
	// accepts; both QUIC types are TLS by definition.
	tlsOpts, err := parseTLSOptions(opts, tlsModeFor("hysteria2"))
	if err != nil {
		return nil, err
	}
	return NewHysteria2(Hysteria2Options{
		Server: spec.Server, Port: spec.Port, Password: secret,
		Up: up, Down: down,
		Obfs: opts[optObfs], ObfsPassword: opts[optObfsPassword],
		TLS: tlsOpts,
	})
}

// parseRate reads an optional byte rate. An empty value means "unset"; a
// suffix of "mbps" (the unit the desktop clients use in their configuration)
// is converted to bytes per second so the same number means the same thing.
func parseRate(value string) (uint64, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return 0, nil
	}
	multiplier := uint64(1)
	switch {
	case strings.HasSuffix(value, "mbps"):
		value = strings.TrimSpace(strings.TrimSuffix(value, "mbps"))
		multiplier = 1000 * 1000 / 8
	case strings.HasSuffix(value, "kbps"):
		value = strings.TrimSpace(strings.TrimSuffix(value, "kbps"))
		multiplier = 1000 / 8
	case strings.HasSuffix(value, "bps"):
		value = strings.TrimSpace(strings.TrimSuffix(value, "bps"))
	}
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", value)
	}
	if number > 1<<40/multiplier {
		return 0, errors.New("the rate is too large")
	}
	return number * multiplier, nil
}

// Close closes the shared QUIC connection.
func (h *Hysteria2) Close() error { return h.session.Close() }

// Disown retires the shared connection without cutting what it carries, so a
// reload that drops this outbound does not leave a socket behind.
func (h *Hysteria2) Disown() { h.session.Disown() }

// DialContext implements Dialer with one QUIC stream carrying a TCP request.
func (h *Hysteria2) DialContext(ctx context.Context, address string) (net.Conn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	conn, release, err := h.session.acquire(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		release()
		return nil, fmt.Errorf("hysteria2: open a stream: %w", err)
	}
	if err := setStreamDeadline(stream, ctx, h.timeout); err != nil {
		_ = stream.Close()
		release()
		return nil, err
	}
	request := quicvarint.Append(nil, hysteria2FrameTCPRequest)
	request = quicvarint.Append(request, uint64(len(target.String())))
	request = append(request, target.String()...)
	request = quicvarint.Append(request, 0) // no padding
	if _, err := stream.Write(request); err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		release()
		return nil, fmt.Errorf("hysteria2: write the request: %w", err)
	}
	if err := hysteria2ReadResponse(stream); err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		release()
		return nil, err
	}
	_ = stream.SetDeadline(time.Time{})
	return &quicStreamConn{stream: stream, conn: conn, remote: target, release: release}, nil
}

// DialPacket implements Dialer with datagrams tagged by a session id.
func (h *Hysteria2) DialPacket(ctx context.Context, address string) (PacketConn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	conn, release, err := h.session.acquire(ctx)
	if err != nil {
		return nil, err
	}
	if !conn.ConnectionState().SupportsDatagrams.Remote {
		release()
		return nil, errors.New("hysteria2: the server does not support datagrams")
	}
	id, err := randomSessionID()
	if err != nil {
		release()
		return nil, err
	}
	incoming, unsubscribe := h.session.mux.subscribe(id)
	packet := &hysteria2PacketConn{
		conn: conn, release: release, unsubscribe: unsubscribe,
		incoming: incoming, dest: target, session: id,
		fragment: newDatagramReassembler(),
		closed:   make(chan struct{}),
	}
	return packet, nil
}

// hysteria2DatagramKey reads the session id a datagram belongs to.
func hysteria2DatagramKey(payload []byte) (uint32, bool) {
	if len(payload) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(payload), true
}

// hysteria2ReadResponse reads the answer to a TCP request.
func hysteria2ReadResponse(r io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return fmt.Errorf("hysteria2: read the response status: %w", err)
	}
	reader := exactReader{r: r}
	length, err := quicvarint.Read(reader)
	if err != nil {
		return fmt.Errorf("hysteria2: read the response message length: %w", err)
	}
	message := make([]byte, length)
	if _, err := io.ReadFull(r, message); err != nil {
		return fmt.Errorf("hysteria2: read the response message: %w", err)
	}
	padding, err := quicvarint.Read(reader)
	if err != nil {
		return fmt.Errorf("hysteria2: read the response padding length: %w", err)
	}
	if padding > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padding)); err != nil {
			return fmt.Errorf("hysteria2: read the response padding: %w", err)
		}
	}
	if status[0] != hysteria2StatusOK {
		if len(message) > 0 {
			return fmt.Errorf("hysteria2: the server refused the request: %s", message)
		}
		return fmt.Errorf("hysteria2: the server refused the request with status %#x", status[0])
	}
	return nil
}

// exactReader turns a reader into a byte reader without buffering ahead, which
// matters because the tunnel data follows the varints on the same stream.
type exactReader struct{ r io.Reader }

func (e exactReader) ReadByte() (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(e.r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// hysteria2PacketConn is one UDP association over the shared connection.
type hysteria2PacketConn struct {
	conn        *quic.Conn
	release     func()
	unsubscribe func()
	incoming    <-chan []byte
	dest        Target
	session     uint32

	mu       sync.Mutex
	nextID   uint16
	fragment *datagramReassembler

	closeOnce sync.Once
	closed    chan struct{}

	deadline datagramDeadline
}

func (c *hysteria2PacketConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.deadline.expired() {
		return 0, os.ErrDeadlineExceeded
	}
	address := c.dest.String()
	headerLen := 4 + 2 + 1 + 1 + quicvarint.Len(uint64(len(address))) + len(address)
	if headerLen+len(p) <= hysteria2MaxDatagram {
		if err := c.send(0, 0, 1, address, p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	// A payload that does not fit in one datagram is split; every piece
	// carries the same packet id and its own fragment index.
	room := hysteria2MaxDatagram - headerLen
	count := (len(p) + room - 1) / room
	if count > hysteria2MaxFragments {
		return 0, fmt.Errorf("hysteria2: datagram of %d bytes needs %d fragments, more than %d",
			len(p), count, hysteria2MaxFragments)
	}
	c.mu.Lock()
	packetID := c.nextID
	c.nextID++
	c.mu.Unlock()
	for index := 0; index < count; index++ {
		start := index * room
		end := min(start+room, len(p))
		if err := c.send(packetID, byte(index), byte(count), address, p[start:end]); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// send writes one datagram frame.
func (c *hysteria2PacketConn) send(packetID uint16, fragment, count byte, address string, payload []byte) error {
	frame := make([]byte, 0, 8+quicvarint.Len(uint64(len(address)))+len(address)+len(payload))
	frame = binary.BigEndian.AppendUint32(frame, c.session)
	frame = binary.BigEndian.AppendUint16(frame, packetID)
	frame = append(frame, fragment, count)
	frame = quicvarint.Append(frame, uint64(len(address)))
	frame = append(frame, address...)
	frame = append(frame, payload...)
	if err := c.conn.SendDatagram(frame); err != nil {
		return fmt.Errorf("hysteria2: send a datagram: %w", err)
	}
	return nil
}

func (c *hysteria2PacketConn) Read(p []byte) (int, error) {
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
				// A malformed datagram is dropped: the transport is
				// unreliable and there is no way to ask for it again.
				continue
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

// assemble turns a datagram into a payload, or into nil while a fragmented one
// is still incomplete.
func (c *hysteria2PacketConn) assemble(datagram []byte) ([]byte, error) {
	if len(datagram) < 9 {
		return nil, errors.New("hysteria2: truncated datagram")
	}
	if binary.BigEndian.Uint32(datagram) != c.session {
		return nil, errors.New("hysteria2: datagram for another session")
	}
	packetID := binary.BigEndian.Uint16(datagram[4:])
	fragment := int(datagram[6])
	count := int(datagram[7])
	if count == 0 || fragment >= count {
		return nil, errors.New("hysteria2: inconsistent fragment numbers")
	}
	rest := datagram[8:]
	addressLen, consumed, err := quicvarint.Parse(rest)
	if err != nil || uint64(len(rest)-consumed) < addressLen {
		return nil, errors.New("hysteria2: truncated datagram address")
	}
	payload := rest[consumed+int(addressLen):]
	return c.fragment.add(packetID, fragment, count, payload)
}

func (c *hysteria2PacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.unsubscribe()
		c.release()
	})
	return nil
}

func (c *hysteria2PacketConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *hysteria2PacketConn) RemoteAddr() net.Addr { return c.dest }

func (c *hysteria2PacketConn) SetDeadline(t time.Time) error      { return c.deadline.set(t) }
func (c *hysteria2PacketConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *hysteria2PacketConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

var _ PacketConn = (*hysteria2PacketConn)(nil)

// quicStreamConn is a net.Conn over one QUIC stream of a shared connection.
type quicStreamConn struct {
	stream  *quic.Stream
	conn    *quic.Conn
	remote  Target
	release func()

	closeOnce sync.Once
}

func (c *quicStreamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *quicStreamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }

// CloseWrite ends the send side and leaves the receive side open, which is what
// the relay's half close needs.
func (c *quicStreamConn) CloseWrite() error { return c.stream.Close() }

func (c *quicStreamConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.stream.Close()
		c.stream.CancelRead(0)
		c.release()
	})
	return nil
}

func (c *quicStreamConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *quicStreamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *quicStreamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *quicStreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *quicStreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

var _ net.Conn = (*quicStreamConn)(nil)

// setStreamDeadline applies the caller's deadline to a stream that is about to
// run a request.
func setStreamDeadline(stream *quic.Stream, ctx context.Context, fallback time.Duration) error {
	deadline := time.Time{}
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else if fallback > 0 {
		deadline = time.Now().Add(fallback)
	}
	return stream.SetDeadline(deadline)
}

// randomSessionID returns a non-zero session id.
func randomSessionID() (uint32, error) {
	for attempt := 0; attempt < 4; attempt++ {
		b, err := randomBytes(4)
		if err != nil {
			return 0, err
		}
		if id := binary.BigEndian.Uint32(b); id != 0 {
			return id, nil
		}
	}
	return 1, nil
}

// salamander is the optional obfuscation of the UDP layer: every packet gets an
// eight-byte salt in front and its bytes are xored with a key derived from the
// password and that salt.
type salamander struct{ key []byte }

// newSalamander validates the obfuscation options.
func newSalamander(name, password string) (*salamander, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "":
		if password != "" {
			return nil, fmt.Errorf("%w: obfs-password without obfs", ErrInvalidOption)
		}
		return nil, nil
	case hysteria2ObfsSalamander:
		if password == "" {
			return nil, fmt.Errorf("%w: obfs-password is required by obfs=%s", ErrInvalidOption, name)
		}
		return &salamander{key: []byte(password)}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported obfs %q", ErrInvalidOption, name)
	}
}

// wrap returns a packet connection that applies the obfuscation.
func (s *salamander) wrap(inner net.PacketConn) (net.PacketConn, error) {
	return &salamanderConn{PacketConn: inner, key: s.key}, nil
}

// salamanderConn obfuscates every datagram in both directions.
type salamanderConn struct {
	net.PacketConn
	key []byte
}

func (c *salamanderConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+8)
	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	if n < 8 {
		return 0, addr, errors.New("hysteria2: obfuscated packet is too short")
	}
	payload := buf[8:n]
	salamanderXOR(c.key, buf[:8], payload)
	return copy(p, payload), addr, nil
}

func (c *salamanderConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	salt, err := randomBytes(8)
	if err != nil {
		return 0, err
	}
	out := make([]byte, 8+len(p))
	copy(out, salt)
	copy(out[8:], p)
	salamanderXOR(c.key, salt, out[8:])
	if _, err := c.PacketConn.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// salamanderXOR applies the keystream of one packet in place. The keystream is
// the BLAKE2b-256 digest of the password followed by the packet's salt, which is
// what the protocol defines; it is a plain hash, not a keyed one.
func salamanderXOR(key, salt, payload []byte) {
	input := make([]byte, 0, len(key)+len(salt))
	input = append(input, key...)
	input = append(input, salt...)
	stream := blake2b.Sum256(input)
	for i := range payload {
		payload[i] ^= stream[i%len(stream)]
	}
}
