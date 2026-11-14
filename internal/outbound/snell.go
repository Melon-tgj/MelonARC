package outbound

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Snell v4 and v5 share one AEAD frame format. Each direction sends a random
// 16-byte salt before its first frame; every frame is a sealed 7-byte header
// followed by optional padding and a sealed payload, with a little-endian
// nonce counter that advances twice per frame.
const (
	snellHeaderVersion    = 1
	snellCommandConnect   = 1
	snellCommandConnectV2 = 5
	snellCommandUDP       = 6
	snellUDPForward       = 1
	snellResponseTunnel   = 0
	snellResponseError    = 2

	snellFrameVersion      = 4
	snellSaltSize          = 16
	snellHeaderPlainSize   = 7
	snellHeaderCipherSize  = snellHeaderPlainSize + 16
	snellMaxPayload        = 0x3FFF
	snellFrameSize         = 1460
	snellInitialPaddingMin = 0x100
	snellInitialPaddingMax = 0x1FF
	snellIdleReset         = 30 * time.Second
)

// SnellOptions configures a Snell v4 or v5 outbound. Version 5 enables the
// reuse-capable connect command and the dynamic record sizing behaviour;
// both versions use the same frame and request formats.
type SnellOptions struct {
	Server  string
	Port    int
	PSK     string
	Version int
	Cipher  string
	Timeout time.Duration
}

// Snell is a Snell v4/v5 outbound. Streams and datagrams are both carried by
// AEAD frames on one TCP connection.
type Snell struct {
	server  string
	host    string
	psk     []byte
	version int
	keyLen  int
	newAEAD func([]byte) (cipher.AEAD, error)
	timeout time.Duration
}

// NewSnell builds a Snell v4 or v5 outbound.
func NewSnell(opts SnellOptions) (*Snell, error) {
	if err := validateServer(opts.Server, opts.Port); err != nil {
		return nil, fmt.Errorf("snell: %w", err)
	}
	if opts.PSK == "" {
		return nil, fmt.Errorf("snell: %w: psk is required", ErrInvalidOption)
	}
	if opts.Version != 4 && opts.Version != 5 {
		return nil, fmt.Errorf("snell: %w: version must be 4 or 5, got %d", ErrInvalidOption, opts.Version)
	}
	keyLen, newAEAD, err := snellCipherFor(opts.Cipher)
	if err != nil {
		return nil, fmt.Errorf("snell: %w", err)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Snell{
		server:  net.JoinHostPort(opts.Server, strconv.Itoa(opts.Port)),
		host:    opts.Server,
		psk:     []byte(opts.PSK),
		version: opts.Version,
		keyLen:  keyLen,
		newAEAD: newAEAD,
		timeout: timeout,
	}, nil
}

// newSnellFromSpec reads a [Proxy] line. The pre-shared key may be written
// positionally or as psk=; version defaults to 4 when omitted.
func newSnellFromSpec(spec Spec) (Dialer, error) {
	allowed := optionSet(map[string]bool{
		optPSK: true, optVersion: true, optCipher: true,
	})
	opts, positional, err := parseArgs(spec.Args, allowed)
	if err != nil {
		return nil, err
	}
	secret, err := positionalCredential(opts, positional, optPSK)
	if err != nil {
		return nil, err
	}
	version := 4
	if value := opts[optVersion]; value != "" {
		version, err = strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("%w: version must be a number", ErrInvalidOption)
		}
	}
	return NewSnell(SnellOptions{
		Server: spec.Server, Port: spec.Port, PSK: secret,
		Version: version, Cipher: opts[optCipher],
	})
}

func snellCipherFor(name string) (int, func([]byte) (cipher.AEAD, error), error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "aes-128-gcm":
		return 16, newAESGCM, nil
	case "chacha20-ietf-poly1305":
		return 32, chacha20poly1305.New, nil
	default:
		return 0, nil, fmt.Errorf("%w: unsupported cipher %q", ErrInvalidOption, name)
	}
}

// snellKDF derives the per-direction AEAD key from the pre-shared key and the
// salt. The argon2id parameters are fixed by the protocol.
func snellKDF(psk, salt []byte, keyLen int) []byte {
	full := argon2.IDKey(psk, salt, 3, 8, 1, 32)
	return full[:keyLen]
}

// DialContext implements Dialer with the TCP connect command.
func (s *Snell) DialContext(ctx context.Context, address string) (net.Conn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	if !target.IsIP() && len(target.Host) > 255 {
		return nil, fmt.Errorf("snell: %w: address name is too long", ErrInvalidAddress)
	}
	conn, err := dialProxyHop(ctx, s.server, s.host, s.timeout, TLSOptions{})
	if err != nil {
		return nil, fmt.Errorf("snell: %w", err)
	}
	return completeHandshake(ctx, conn, func(c net.Conn) (net.Conn, error) {
		sc := newSnellConn(c, s)
		if err := sc.writeStreamHeader(target); err != nil {
			return nil, err
		}
		if err := sc.readResponse(); err != nil {
			return nil, err
		}
		return sc, nil
	})
}

// DialPacket implements Dialer with the UDP command. Datagrams are framed
// one per AEAD frame so the association preserves packet boundaries.
func (s *Snell) DialPacket(ctx context.Context, address string) (PacketConn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	if !target.IsIP() && len(target.Host) > 255 {
		return nil, fmt.Errorf("snell: %w: address name is too long", ErrInvalidAddress)
	}
	conn, err := dialProxyHop(ctx, s.server, s.host, s.timeout, TLSOptions{})
	if err != nil {
		return nil, fmt.Errorf("snell: %w", err)
	}
	stream, err := completeHandshake(ctx, conn, func(c net.Conn) (net.Conn, error) {
		sc := newSnellConn(c, s)
		if _, err := sc.Write([]byte{snellHeaderVersion, snellCommandUDP, 0}); err != nil {
			return nil, err
		}
		if err := sc.readResponse(); err != nil {
			return nil, err
		}
		return &snellPacketConn{sc: sc, dest: target}, nil
	})
	if err != nil {
		return nil, err
	}
	return stream.(PacketConn), nil
}

// snellDirection holds one direction's AEAD state. The salt is written or read
// once, lazily, when that direction first carries a frame.
type snellDirection struct {
	aead  cipher.AEAD
	nonce [12]byte
	ready bool
}

// snellConn is the framed connection. Stream Writes split large payloads into
// frames; WritePacketFrame keeps one datagram in exactly one frame.
type snellConn struct {
	conn    net.Conn
	psk     []byte
	keyLen  int
	newAEAD func([]byte) (cipher.AEAD, error)
	version int

	rd, wr snellDirection
	rmu    sync.Mutex
	wmu    sync.Mutex

	readBuf      []byte
	payloadLimit uint16
	lastWrite    time.Time
	firstFrame   bool
	initialPad   int
}

func newSnellConn(conn net.Conn, s *Snell) *snellConn {
	c := &snellConn{
		conn: conn, psk: s.psk, keyLen: s.keyLen,
		newAEAD: s.newAEAD, version: s.version, firstFrame: true,
	}
	if s.version == 5 {
		c.initialPad = c.randomInitialPadding()
	}
	return c
}

func (c *snellConn) initWrite() error {
	if c.wr.ready {
		return nil
	}
	salt, err := randomBytes(snellSaltSize)
	if err != nil {
		return err
	}
	aead, err := c.newAEAD(snellKDF(c.psk, salt, c.keyLen))
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(salt); err != nil {
		return fmt.Errorf("snell: write salt: %w", err)
	}
	c.wr = snellDirection{aead: aead, ready: true}
	return nil
}

func (c *snellConn) initRead() error {
	if c.rd.ready {
		return nil
	}
	salt := make([]byte, snellSaltSize)
	if _, err := io.ReadFull(c.conn, salt); err != nil {
		return fmt.Errorf("snell: read salt: %w", err)
	}
	aead, err := c.newAEAD(snellKDF(c.psk, salt, c.keyLen))
	if err != nil {
		return err
	}
	c.rd = snellDirection{aead: aead, ready: true}
	return nil
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// snellSwapPadding interleaves the even-indexed padding bytes with the first
// bytes of the payload ciphertext. Applying it twice restores both streams.
func snellSwapPadding(padding, ciphertext []byte) {
	limit := len(padding)
	if len(ciphertext) < limit {
		limit = len(ciphertext)
	}
	for i := 0; i < limit; i += 2 {
		padding[i], ciphertext[i] = ciphertext[i], padding[i]
	}
}

func (c *snellConn) writeFrame(payload []byte, paddingLength int) error {
	if len(payload) > snellMaxPayload || paddingLength > snellMaxPayload {
		return errors.New("snell: frame is too large")
	}
	if err := c.initWrite(); err != nil {
		return err
	}
	header := make([]byte, snellHeaderPlainSize)
	header[0] = snellFrameVersion
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingLength))
	binary.BigEndian.PutUint16(header[5:7], uint16(len(payload)))
	headerCipher := c.wr.aead.Seal(nil, c.wr.nonce[:], header, nil)
	incrementNonce(c.wr.nonce[:])
	var payloadCipher []byte
	if len(payload) > 0 {
		payloadCipher = c.wr.aead.Seal(nil, c.wr.nonce[:], payload, nil)
		incrementNonce(c.wr.nonce[:])
	}
	var padding []byte
	if paddingLength > 0 {
		var err error
		padding, err = randomBytes(paddingLength)
		if err != nil {
			return err
		}
		snellSwapPadding(padding, payloadCipher)
	}
	frame := make([]byte, 0, len(headerCipher)+len(padding)+len(payloadCipher))
	frame = append(frame, headerCipher...)
	frame = append(frame, padding...)
	frame = append(frame, payloadCipher...)
	return writeAll(c.conn, frame)
}

func (c *snellConn) readFrame() ([]byte, error) {
	if err := c.initRead(); err != nil {
		return nil, err
	}
	headerCipher := make([]byte, snellHeaderCipherSize)
	if _, err := io.ReadFull(c.conn, headerCipher); err != nil {
		return nil, fmt.Errorf("snell: read frame header: %w", err)
	}
	header, err := c.rd.aead.Open(headerCipher[:0], c.rd.nonce[:], headerCipher, nil)
	incrementNonce(c.rd.nonce[:])
	if err != nil {
		return nil, fmt.Errorf("snell: decrypt frame header: %w", err)
	}
	if len(header) != snellHeaderPlainSize || header[0] != snellFrameVersion {
		return nil, errors.New("snell: invalid frame header")
	}
	paddingLength := int(binary.BigEndian.Uint16(header[3:5]))
	payloadLength := int(binary.BigEndian.Uint16(header[5:7]))
	if payloadLength == 0 {
		if paddingLength != 0 {
			return nil, errors.New("snell: zero chunk carries padding")
		}
		return nil, io.EOF
	}
	if payloadLength > snellMaxPayload || paddingLength > snellMaxPayload {
		return nil, errors.New("snell: frame is too large")
	}
	frame := make([]byte, paddingLength+payloadLength+c.rd.aead.Overhead())
	if _, err := io.ReadFull(c.conn, frame); err != nil {
		return nil, fmt.Errorf("snell: read frame payload: %w", err)
	}
	if paddingLength > 0 {
		snellSwapPadding(frame[:paddingLength], frame[paddingLength:])
	}
	payload, err := c.rd.aead.Open(frame[paddingLength:paddingLength], c.rd.nonce[:], frame[paddingLength:], nil)
	incrementNonce(c.rd.nonce[:])
	if err != nil {
		return nil, fmt.Errorf("snell: decrypt frame payload: %w", err)
	}
	return payload, nil
}

// nextPayloadLimit implements v5 dynamic record sizing: the first frame is
// small so the salt and initial padding fit in one segment, then the limit
// ramps up and resets after an idle window. v4 uses the full frame size.
func (c *snellConn) nextPayloadLimit() int {
	if c.version == 4 {
		return snellMaxPayload
	}
	now := time.Now()
	if !c.lastWrite.IsZero() && now.Sub(c.lastWrite) > snellIdleReset {
		c.payloadLimit = 0
	}
	c.lastWrite = now
	if c.payloadLimit == 0 {
		c.payloadLimit = uint16(snellFrameSize - 55 - c.initialPad)
	} else {
		next := int(c.payloadLimit) + snellFrameSize - 39
		if next > snellMaxPayload {
			next = snellMaxPayload
		}
		c.payloadLimit = uint16(next)
	}
	if int(c.payloadLimit) > snellMaxPayload {
		return snellMaxPayload
	}
	return int(c.payloadLimit)
}

func (c *snellConn) randomInitialPadding() int {
	random, err := randomBytes(2)
	if err != nil {
		return snellInitialPaddingMin
	}
	span := snellInitialPaddingMax - snellInitialPaddingMin + 1
	return snellInitialPaddingMin + int(binary.BigEndian.Uint16(random))%span
}

func (c *snellConn) paddingFor(payloadLength int) int {
	if c.version == 4 || !c.firstFrame || payloadLength == 0 {
		return 0
	}
	return c.initialPad
}

func (c *snellConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if len(p) == 0 {
		return 0, c.writeFrame(nil, 0)
	}
	written := 0
	for written < len(p) {
		limit := c.nextPayloadLimit()
		end := written + limit
		if end > len(p) {
			end = len(p)
		}
		padding := c.paddingFor(end - written)
		if err := c.writeFrame(p[written:end], padding); err != nil {
			return written, err
		}
		c.firstFrame = false
		written = end
	}
	return written, nil
}

func (c *snellConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.readBuf) == 0 {
		payload, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		c.readBuf = payload
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// writePacketFrame writes one datagram as one frame.
func (c *snellConn) writePacketFrame(p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	padding := c.paddingFor(len(p))
	if err := c.writeFrame(p, padding); err != nil {
		return err
	}
	c.firstFrame = false
	return nil
}

// takePacketFrame returns one frame's payload, draining stream leftovers first
// (the READY byte may share a frame with the first datagram).
func (c *snellConn) takePacketFrame() ([]byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.readBuf) > 0 {
		out := c.readBuf
		c.readBuf = nil
		return out, nil
	}
	return c.readFrame()
}

// writeStreamHeader writes the TCP request header. v5 uses the reuse-capable
// connect command, v4 the original one.
func (c *snellConn) writeStreamHeader(target Target) error {
	command := byte(snellCommandConnect)
	if c.version == 5 {
		command = snellCommandConnectV2
	}
	buf := make([]byte, 0, 5+len(target.Host)+2)
	buf = append(buf, snellHeaderVersion, command, 0, byte(len(target.Host)))
	buf = append(buf, target.Host...)
	buf = binary.BigEndian.AppendUint16(buf, target.Port)
	_, err := c.Write(buf)
	return err
}

// readStreamHeader parses the TCP request header. The local test peer uses it.
func readSnellStreamHeader(r io.Reader) (Target, byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Target{}, 0, err
	}
	if head[0] != snellHeaderVersion {
		return Target{}, 0, fmt.Errorf("snell: unsupported header version %d", head[0])
	}
	if head[2] != 0 {
		return Target{}, 0, errors.New("snell: client id is not supported")
	}
	host := make([]byte, int(head[3]))
	if _, err := io.ReadFull(r, host); err != nil {
		return Target{}, 0, err
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Target{}, 0, err
	}
	return Target{Host: string(host), Port: binary.BigEndian.Uint16(port[:])}, head[1], nil
}

func (c *snellConn) readResponse() error {
	var status [1]byte
	if _, err := io.ReadFull(c, status[:]); err != nil {
		return fmt.Errorf("snell: read response: %w", err)
	}
	switch status[0] {
	case snellResponseTunnel, 1: // tunnel or pong
		return nil
	case snellResponseError:
		var detail [2]byte
		if _, err := io.ReadFull(c, detail[:]); err != nil {
			return fmt.Errorf("snell: read error detail: %w", err)
		}
		message := make([]byte, int(detail[1]))
		if _, err := io.ReadFull(c, message); err != nil {
			return fmt.Errorf("snell: read error message: %w", err)
		}
		return fmt.Errorf("snell: server rejected the request (code %d): %s", detail[0], message)
	default:
		return fmt.Errorf("snell: unknown response code %#x", status[0])
	}
}

func (c *snellConn) Close() error                       { return c.conn.Close() }
func (c *snellConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *snellConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *snellConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *snellConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *snellConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

var _ net.Conn = (*snellConn)(nil)

// snellPacketConn carries one destination's datagrams over a single framed
// stream. Each frame names the destination on the way out and the source on
// the way back, so no UDP socket is needed.
type snellPacketConn struct {
	sc   *snellConn
	dest Target
}

func (c *snellPacketConn) Write(p []byte) (int, error) {
	frame := snellUDPRequest(c.dest, p)
	if len(frame) > snellMaxPayload {
		return 0, errors.New("snell: datagram is too large for one frame")
	}
	if err := c.sc.writePacketFrame(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *snellPacketConn) Read(p []byte) (int, error) {
	frame, err := c.sc.takePacketFrame()
	if err != nil {
		return 0, err
	}
	payload, err := snellUDPResponsePayload(frame)
	if err != nil {
		return 0, err
	}
	return copy(p, payload), nil
}

func (c *snellPacketConn) Close() error                       { return c.sc.Close() }
func (c *snellPacketConn) LocalAddr() net.Addr                { return c.sc.LocalAddr() }
func (c *snellPacketConn) RemoteAddr() net.Addr               { return c.dest }
func (c *snellPacketConn) SetDeadline(t time.Time) error      { return c.sc.SetDeadline(t) }
func (c *snellPacketConn) SetReadDeadline(t time.Time) error  { return c.sc.SetReadDeadline(t) }
func (c *snellPacketConn) SetWriteDeadline(t time.Time) error { return c.sc.SetWriteDeadline(t) }

var _ PacketConn = (*snellPacketConn)(nil)

// snellUDPRequest builds one client-to-server datagram frame. A domain target
// is introduced by its length; an IP target by a zero length and a version
// marker.
func snellUDPRequest(dest Target, payload []byte) []byte {
	buf := make([]byte, 0, 1+MaxUDPHeaderLen+len(payload))
	buf = append(buf, snellUDPForward)
	if ip := net.ParseIP(dest.Host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 0, 0x04)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 0, 0x06)
			buf = append(buf, ip.To16()...)
		}
	} else {
		buf = append(buf, byte(len(dest.Host)))
		buf = append(buf, dest.Host...)
	}
	buf = binary.BigEndian.AppendUint16(buf, dest.Port)
	return append(buf, payload...)
}

// parseSnellUDPRequest is the inverse used by the local test peer.
func parseSnellUDPRequest(frame []byte) (Target, []byte, error) {
	if len(frame) < 1 || frame[0] != snellUDPForward {
		return Target{}, nil, errors.New("snell: invalid udp request")
	}
	if len(frame) < 2 {
		return Target{}, nil, errors.New("snell: udp request is truncated")
	}
	off := 1
	var host string
	if length := int(frame[off]); length != 0 {
		off++
		if len(frame) < off+length+2 {
			return Target{}, nil, errors.New("snell: udp domain request is truncated")
		}
		host = string(frame[off : off+length])
		off += length
	} else {
		off++
		if len(frame) < off+1 {
			return Target{}, nil, errors.New("snell: udp ip request is truncated")
		}
		switch frame[off] {
		case 0x04:
			off++
			if len(frame) < off+net.IPv4len+2 {
				return Target{}, nil, errors.New("snell: udp ipv4 request is truncated")
			}
			host = net.IP(frame[off : off+net.IPv4len]).String()
			off += net.IPv4len
		case 0x06:
			off++
			if len(frame) < off+net.IPv6len+2 {
				return Target{}, nil, errors.New("snell: udp ipv6 request is truncated")
			}
			host = net.IP(frame[off : off+net.IPv6len]).String()
			off += net.IPv6len
		default:
			return Target{}, nil, fmt.Errorf("snell: unsupported udp address marker %#x", frame[off])
		}
	}
	if len(frame) < off+2 {
		return Target{}, nil, errors.New("snell: udp request has no port")
	}
	port := binary.BigEndian.Uint16(frame[off : off+2])
	return Target{Host: host, Port: port}, frame[off+2:], nil
}

// snellUDPResponse builds one server-to-client datagram frame. Responses
// always name an IP source, never a domain.
func snellUDPResponse(from Target, payload []byte) ([]byte, error) {
	buf := make([]byte, 0, 1+net.IPv6len+2+len(payload))
	ip := net.ParseIP(from.Host)
	if ip == nil {
		return nil, errors.New("snell: udp response needs an ip source")
	}
	if v4 := ip.To4(); v4 != nil {
		buf = append(buf, 0x04)
		buf = append(buf, v4...)
	} else {
		buf = append(buf, 0x06)
		buf = append(buf, ip.To16()...)
	}
	buf = binary.BigEndian.AppendUint16(buf, from.Port)
	return append(buf, payload...), nil
}

func snellUDPResponsePayload(frame []byte) ([]byte, error) {
	if len(frame) < 1 {
		return nil, errors.New("snell: udp response is empty")
	}
	off := 1
	switch frame[0] {
	case 0x04:
		off += net.IPv4len
	case 0x06:
		off += net.IPv6len
	default:
		return nil, fmt.Errorf("snell: unsupported udp response marker %#x", frame[0])
	}
	if len(frame) < off+2 {
		return nil, errors.New("snell: udp response is truncated")
	}
	return frame[off+2:], nil
}
