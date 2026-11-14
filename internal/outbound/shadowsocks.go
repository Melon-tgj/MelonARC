package outbound

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// ShadowsocksOptions configures a Shadowsocks outbound. Method is one of the
// three legacy AEAD ciphers or one of the three 2022 BLAKE3 ciphers. Secret is
// a password for the former and a base64 pre-shared key for the latter.
type ShadowsocksOptions struct {
	Server   string
	Port     int
	Method   string
	Password string
	// Timeout bounds the dial and the handshake. Zero means DefaultTimeout.
	Timeout time.Duration
}

// Shadowsocks is an AEAD Shadowsocks outbound. TCP streams and UDP datagrams
// both use the cipher's per-session subkey derivation and independent nonces.
type Shadowsocks struct {
	server  string
	host    string
	info    cipherInfo
	master  []byte
	timeout time.Duration
}

// NewShadowsocks builds a Shadowsocks outbound.
func NewShadowsocks(opts ShadowsocksOptions) (*Shadowsocks, error) {
	if err := validateServer(opts.Server, opts.Port); err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	info, err := cipherInfoFor(opts.Method)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	master, err := info.masterKey(opts.Password)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Shadowsocks{
		server:  net.JoinHostPort(opts.Server, strconv.Itoa(opts.Port)),
		host:    opts.Server,
		info:    info,
		master:  master,
		timeout: timeout,
	}, nil
}

// newShadowsocksFromSpec reads a [Proxy] line. The cipher and the secret may be
// written positionally ("ss, host, port, aes-128-gcm, secret", the shape used by
// the sample configuration) or with method= and password= keys.
func newShadowsocksFromSpec(spec Spec) (Dialer, error) {
	allowed := optionSet(map[string]bool{optMethod: true, optPassword: true})
	opts, positional, err := parseArgs(spec.Args, allowed)
	if err != nil {
		return nil, err
	}
	method := opts[optMethod]
	if method == "" && len(positional) > 0 {
		method, positional = positional[0], positional[1:]
	}
	if method == "" {
		return nil, fmt.Errorf("%w: ss needs a cipher method", ErrInvalidOption)
	}
	secret, err := positionalCredential(opts, positional, optPassword)
	if err != nil {
		return nil, err
	}
	return NewShadowsocks(ShadowsocksOptions{
		Server: spec.Server, Port: spec.Port, Method: method, Password: secret,
	})
}

func (s *Shadowsocks) dial(ctx context.Context, network string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: s.timeout}
	conn, err := dialer.DialContext(ctx, network, s.server)
	if err != nil {
		return nil, fmt.Errorf("ss: connect to %s: %w", s.server, err)
	}
	setConnDeadline(conn, ctx, s.timeout)
	return conn, nil
}

// DialContext opens a TCP stream. Legacy AEAD starts with a salt and the
// encrypted target address; 2022 additionally sends a typed request header and
// validates the server's typed response header (including the echoed request
// salt) before handing the stream to the caller.
func (s *Shadowsocks) DialContext(ctx context.Context, address string) (net.Conn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	conn, err := s.dial(ctx, "tcp")
	if err != nil {
		return nil, err
	}
	release := guardConn(ctx, conn)
	stream, err := s.openStream(conn, target)
	if err != nil {
		release()
		_ = conn.Close()
		return nil, err
	}
	if !release() {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	_ = conn.SetDeadline(time.Time{})
	return stream, nil
}

// openStream does the handshake on a connection the caller already owns.
func (s *Shadowsocks) openStream(conn net.Conn, target Target) (net.Conn, error) {
	salt, err := randomBytes(s.info.saltLen)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	aead, err := s.info.sessionKey(s.master, salt)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	writer := newChunkStream(conn, aead, s.info.maxPayload)
	address := AppendAddress(nil, target)
	if !s.info.version22 {
		// One write for the salt and the whole request header: a server reads
		// the request with a single Read and rejects what looks truncated.
		head := make([]byte, 0, len(salt)+len(address)+2*aead.Overhead()+2)
		head = append(head, salt...)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(address)))
		head = writer.appendChunk(head, length[:])
		head = writer.appendChunk(head, address)
		if _, err := conn.Write(head); err != nil {
			return nil, fmt.Errorf("ss: write request header: %w", err)
		}
		return &splitStream{
			conn:   conn,
			reader: &responseReader{conn: conn, info: s.info, master: s.master},
			writer: writer,
		}, nil
	}

	// 2022 request stream: salt, a fixed-length header chunk (type, timestamp,
	// length of the next chunk), then the variable-length header chunk with the
	// target address and non-zero padding. Every chunk advances the nonce.
	padding, err := randomBytes(8)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	varHeader := make([]byte, 0, len(address)+2+len(padding))
	varHeader = append(varHeader, address...)
	varHeader = binary.BigEndian.AppendUint16(varHeader, uint16(len(padding)))
	varHeader = append(varHeader, padding...)
	fixed := make([]byte, 0, 11)
	fixed = append(fixed, 0) // HeaderTypeClientStream
	fixed = binary.BigEndian.AppendUint64(fixed, uint64(time.Now().Unix()))
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(varHeader)))
	// One write for salt and both header chunks, for the reason given above in
	// the legacy branch: the peer reads the header once.
	head := make([]byte, 0, len(salt)+(len(fixed)+len(varHeader))+2*aead.Overhead())
	head = append(head, salt...)
	head = writer.appendChunk(head, fixed)
	head = writer.appendChunk(head, varHeader)
	if _, err := conn.Write(head); err != nil {
		return nil, fmt.Errorf("ss: write request header: %w", err)
	}
	// The answer is keyed by the server's own salt and starts with a header
	// that names the request salt, so a server answering a different
	// connection is rejected. Both are read lazily: a server sends them
	// together with its first payload, and a client that waited here would
	// deadlock against any target that speaks first only after being spoken to.
	return &splitStream{
		conn: conn,
		reader: &responseReader{
			conn: conn, info: s.info, master: s.master, requestSalt: salt,
		},
		writer: writer,
	}, nil
}

// DialPacket opens a datagram association with one destination. The socket is
// connected to the server, so every datagram read belongs to that association.
func (s *Shadowsocks) DialPacket(ctx context.Context, address string) (PacketConn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	conn, err := s.dial(ctx, "udp")
	if err != nil {
		return nil, err
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("ss: udp dial returned a non datagram connection")
	}
	_ = conn.SetDeadline(time.Time{})
	session, err := randomBytes(8)
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("ss: %w", err)
	}
	return &ssPacketConn{
		conn: udp, dest: target, info: s.info, master: s.master,
		sessionID: session,
	}, nil
}

// responseReader reads the server's direction of a Shadowsocks connection. It
// opens lazily on the first read because the server sends what keys it with its
// first payload: the salt of its own direction, and for 2022 a header naming the
// request salt. A client that blocked on either inside DialContext would
// deadlock against a target that only answers what it is asked, which is most of
// them.
//
// The 2022 response header is a chunk of type, timestamp, request salt and the
// length of what follows; what follows is the first payload, not a framed chunk.
// Only later payloads carry the two-byte length frame. A reference server made
// this visible: reading the first payload as a frame fails the tag of a two-byte
// chunk cut out of it, because the header's length field had already said how
// much payload was coming.
type responseReader struct {
	conn        net.Conn
	info        cipherInfo
	master      []byte
	requestSalt []byte

	stream  *chunkStream
	pending []byte
	opened  bool
}

func (r *responseReader) Read(p []byte) (int, error) {
	if !r.opened {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	return r.stream.Read(p)
}

// open derives the response subkey and consumes the protocol's response header.
func (r *responseReader) open() error {
	salt := make([]byte, r.info.saltLen)
	if _, err := io.ReadFull(r.conn, salt); err != nil {
		return fmt.Errorf("ss: read response salt: %w", err)
	}
	aead, err := r.info.sessionKey(r.master, salt)
	if err != nil {
		return fmt.Errorf("ss: %w", err)
	}
	r.stream = newChunkStream(r.conn, aead, r.info.maxPayload)
	r.opened = true
	if !r.info.version22 {
		return nil
	}
	header, err := r.stream.readChunk(11 + r.info.saltLen)
	if err != nil {
		return err
	}
	if header[0] != 1 {
		return fmt.Errorf("ss: response header has type %d, want 1", header[0])
	}
	stamp := int64(binary.BigEndian.Uint64(header[1:9]))
	if delta := time.Now().Unix() - stamp; delta > 30 || delta < -30 {
		return fmt.Errorf("ss: response timestamp is %d seconds away", delta)
	}
	if !bytes.Equal(header[9:9+r.info.saltLen], r.requestSalt) {
		return errors.New("ss: response header names a different request salt")
	}
	initial := int(binary.BigEndian.Uint16(header[9+r.info.saltLen:]))
	if initial == 0 {
		return nil
	}
	// The header declares the payload's plaintext length; the chunk that
	// carries it is that plus the tag.
	payload := make([]byte, initial+r.stream.aead.Overhead())
	if _, err := io.ReadFull(r.conn, payload); err != nil {
		return fmt.Errorf("ss: read initial payload: %w", err)
	}
	plain, err := r.stream.openChunk(payload)
	if err != nil {
		return err
	}
	r.pending = plain
	return nil
}

// splitStream joins the request and response streams of a connection. The two
// directions use different subkeys (hence different nonces starting at zero) but
// share one socket and one lifetime.
type splitStream struct {
	conn   net.Conn
	reader *responseReader
	writer *chunkStream
}

func (c *splitStream) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *splitStream) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *splitStream) Close() error                { return c.conn.Close() }
func (c *splitStream) LocalAddr() net.Addr         { return c.conn.LocalAddr() }
func (c *splitStream) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }
func (c *splitStream) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
func (c *splitStream) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
func (c *splitStream) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

var _ net.Conn = (*splitStream)(nil)

// ssPacketConn carries one destination's datagrams. Each datagram is
// independently encrypted: legacy AEAD uses a fresh salt with a zero nonce,
// 2022 AES-GCM uses an AES-encrypted separate header (session id and packet
// id) plus a body keyed by the session id, and 2022 ChaCha uses a 24-byte
// random nonce with the pre-shared key directly.
type ssPacketConn struct {
	conn      *net.UDPConn
	dest      Target
	info      cipherInfo
	master    []byte
	sessionID []byte

	wmu      sync.Mutex
	rmu      sync.Mutex
	packetID uint64
}

const maxDatagram = 65507

func (c *ssPacketConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	packet, err := c.seal(p)
	if err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(packet); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *ssPacketConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	buf := make([]byte, maxDatagram)
	n, err := c.conn.Read(buf)
	if err != nil {
		return 0, err
	}
	payload, err := c.open(buf[:n])
	if err != nil {
		return 0, err
	}
	return copy(p, payload), nil
}

func (c *ssPacketConn) seal(payload []byte) ([]byte, error) {
	address := AppendAddress(nil, c.dest)
	if !c.info.version22 {
		salt, err := randomBytes(c.info.saltLen)
		if err != nil {
			return nil, err
		}
		aead, err := c.info.sessionKey(c.master, salt)
		if err != nil {
			return nil, err
		}
		body := append(append([]byte(nil), address...), payload...)
		return append(salt, aead.Seal(nil, make([]byte, 12), body, nil)...), nil
	}

	stamp := uint64(time.Now().Unix())
	if !c.info.chacha22 {
		return c.seal2022AES(address, payload, stamp)
	}
	return c.seal2022ChaCha(address, payload, stamp)
}

func (c *ssPacketConn) seal2022AES(address, payload []byte, stamp uint64) ([]byte, error) {
	block, err := aes.NewCipher(c.master)
	if err != nil {
		return nil, fmt.Errorf("ss: udp separate header: %w", err)
	}
	separate := make([]byte, 16)
	copy(separate, c.sessionID)
	binary.BigEndian.PutUint64(separate[8:], c.packetID)
	c.packetID++
	encryptedSeparate := make([]byte, 16)
	block.Encrypt(encryptedSeparate, separate)
	material := append(append([]byte(nil), c.master...), separate[:8]...)
	derived := blake3DeriveKey(ss2022Context, material)
	aead, err := c.info.newAEAD(derived[:c.info.keyLen])
	if err != nil {
		return nil, err
	}
	body := ss2022PacketBody(0, stamp, nil, address, payload)
	packet := append([]byte(nil), encryptedSeparate...)
	return append(packet, aead.Seal(nil, separate[4:16], body, nil)...), nil
}

func (c *ssPacketConn) seal2022ChaCha(address, payload []byte, stamp uint64) ([]byte, error) {
	nonce, err := randomBytes(24)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(c.master)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 0, 8+8+1+8+2)
	header = append(header, c.sessionID...)
	header = binary.BigEndian.AppendUint64(header, c.packetID)
	c.packetID++
	header = append(header, 0)
	header = binary.BigEndian.AppendUint64(header, stamp)
	header = binary.BigEndian.AppendUint16(header, 0)
	header = append(header, address...)
	header = append(header, payload...)
	packet := append([]byte(nil), nonce...)
	return append(packet, aead.Seal(nil, nonce, header, nil)...), nil
}

// ss2022PacketBody builds the AEAD body of an AES-GCM 2022 datagram. A server
// message has type 1 and carries the client session id, which lets the client
// confirm the answer belongs to its session.
func ss2022PacketBody(typ byte, stamp uint64, clientSession []byte, address, payload []byte) []byte {
	body := make([]byte, 0, 1+8+8+2+len(address)+len(payload))
	body = append(body, typ)
	body = binary.BigEndian.AppendUint64(body, stamp)
	if typ == 1 {
		body = append(body, clientSession...)
	}
	body = binary.BigEndian.AppendUint16(body, 0) // padding length
	body = append(body, address...)
	return append(body, payload...)
}

func (c *ssPacketConn) open(packet []byte) ([]byte, error) {
	if !c.info.version22 {
		if len(packet) < c.info.saltLen+16 {
			return nil, errors.New("ss: udp packet is too short")
		}
		aead, err := c.info.sessionKey(c.master, packet[:c.info.saltLen])
		if err != nil {
			return nil, err
		}
		body, err := aead.Open(nil, make([]byte, 12), packet[c.info.saltLen:], nil)
		if err != nil {
			return nil, fmt.Errorf("ss: decrypt udp packet: %w", err)
		}
		_, n, err := decodeAddress(body)
		if err != nil {
			return nil, err
		}
		return body[n:], nil
	}
	if len(packet) < 32 {
		return nil, errors.New("ss: 2022 udp packet is too short")
	}
	if !c.info.chacha22 {
		return c.open2022AES(packet)
	}
	nonce := packet[:24]
	aead, err := chacha20poly1305.NewX(c.master)
	if err != nil {
		return nil, err
	}
	body, err := aead.Open(nil, nonce, packet[24:], nil)
	if err != nil {
		return nil, fmt.Errorf("ss: decrypt 2022 udp packet: %w", err)
	}
	return c.strip2022Body(body, true)
}

func (c *ssPacketConn) open2022AES(packet []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.master)
	if err != nil {
		return nil, err
	}
	separate := make([]byte, 16)
	block.Decrypt(separate, packet[:16])
	material := append(append([]byte(nil), c.master...), separate[:8]...)
	derived := blake3DeriveKey(ss2022Context, material)
	aead, err := c.info.newAEAD(derived[:c.info.keyLen])
	if err != nil {
		return nil, err
	}
	body, err := aead.Open(nil, separate[4:16], packet[16:], nil)
	if err != nil {
		return nil, fmt.Errorf("ss: decrypt 2022 udp packet: %w", err)
	}
	return c.strip2022Body(body, false)
}

// strip2022Body validates a 2022 response header and returns its payload.
// chachaLayout has the session id and packet id in front of the common header.
func (c *ssPacketConn) strip2022Body(body []byte, chachaLayout bool) ([]byte, error) {
	off := 0
	if chachaLayout {
		if len(body) < 16 {
			return nil, errors.New("ss: 2022 udp body is truncated")
		}
		off = 16 // server session id and packet id
	}
	if len(body) < off+21 {
		return nil, errors.New("ss: 2022 udp header is truncated")
	}
	if body[off] != 1 {
		return nil, fmt.Errorf("ss: 2022 udp response has type %d, want 1", body[off])
	}
	stamp := int64(binary.BigEndian.Uint64(body[off+1 : off+9]))
	if delta := time.Now().Unix() - stamp; delta > 30 || delta < -30 {
		return nil, fmt.Errorf("ss: 2022 udp timestamp is %d seconds away", delta)
	}
	off += 9
	if !bytes.Equal(body[off:off+8], c.sessionID) {
		return nil, errors.New("ss: 2022 udp response names a different client session")
	}
	off += 8
	padding := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2 + padding
	if off > len(body) {
		return nil, errors.New("ss: 2022 udp padding is truncated")
	}
	_, n, err := decodeAddress(body[off:])
	if err != nil {
		return nil, err
	}
	return body[off+n:], nil
}

func (c *ssPacketConn) Close() error                       { return c.conn.Close() }
func (c *ssPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *ssPacketConn) RemoteAddr() net.Addr               { return c.dest }
func (c *ssPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *ssPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *ssPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

var _ PacketConn = (*ssPacketConn)(nil)
