package outbound

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// The AEAD VMess wire constants. The KDF salts are fixed by the public
// protocol definition: they are domain separators, not secrets.
const (
	vmessKDFRoot        = "VMess AEAD KDF"
	kdfAuthIDEncryption = "AES Auth ID Encryption"
	kdfHeaderLenKey     = "VMess Header AEAD Key_Length"
	kdfHeaderLenIV      = "VMess Header AEAD Nonce_Length"
	kdfHeaderKey        = "VMess Header AEAD Key"
	kdfHeaderIV         = "VMess Header AEAD Nonce"
	kdfRespLenKey       = "AEAD Resp Header Len Key"
	kdfRespLenIV        = "AEAD Resp Header Len IV"
	kdfRespKey          = "AEAD Resp Header Key"
	kdfRespIV           = "AEAD Resp Header IV"

	vmessCmdKeySuffix = "c48619fe-8f02-49e0-b9e9-edf763e17e21"

	vmessVersion           = 1
	vmessOptionChunkStream = 0x01
	vmessCommandTCP        = 1
	vmessCommandUDP        = 2
	vmessSecurityAESGCM    = 3
	vmessSecurityChaCha    = 4

	// VMess writes the port before the address and uses its own address type
	// numbers, which are not the SOCKS5 ones.
	vmessATYPIPv4   = 1
	vmessATYPDomain = 2
	vmessATYPIPv6   = 3

	vmessMaxChunk = 0x3FFF
)

// VMessOptions configures an AEAD VMess outbound. UUID is the 16-byte account
// identifier in its usual dashed text form. Security selects the body cipher;
// TLS is optional and comes from the shared TLS base.
type VMessOptions struct {
	Server   string
	Port     int
	UUID     string
	Security string
	TLS      TLSOptions
	Timeout  time.Duration
}

// VMess is an AEAD VMess outbound. Streams and datagrams share one header
// format; the command byte decides how the peer interprets the body chunks.
type VMess struct {
	server   string
	host     string
	cmdKey   []byte
	security byte
	tls      TLSOptions
	timeout  time.Duration
}

// NewVMess builds an AEAD VMess outbound.
func NewVMess(opts VMessOptions) (*VMess, error) {
	if err := validateServer(opts.Server, opts.Port); err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	id, err := parseVMessUUID(opts.UUID)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	security, err := vmessSecurityFor(opts.Security)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	h := md5.New()
	_, _ = h.Write(id[:])
	_, _ = h.Write([]byte(vmessCmdKeySuffix))
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &VMess{
		server:   net.JoinHostPort(opts.Server, strconv.Itoa(opts.Port)),
		host:     opts.Server,
		cmdKey:   h.Sum(nil),
		security: security,
		tls:      opts.TLS,
		timeout:  timeout,
	}, nil
}

// newVMessFromSpec reads a [Proxy] line. The account identifier may be written
// positionally or as uuid=; alterid is accepted for configuration portability
// but has no meaning in the AEAD header format.
func newVMessFromSpec(spec Spec) (Dialer, error) {
	allowed := optionSet(map[string]bool{
		optUUID: true, optAlterID: true, optSecurity: true,
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
		return nil, fmt.Errorf("%w: vmess needs a uuid", ErrInvalidOption)
	}
	if len(positional) > 0 {
		return nil, fmt.Errorf("%w: unexpected argument %q", ErrInvalidOption, positional[0])
	}
	if value, ok := opts[optAlterID]; ok {
		if _, err := strconv.Atoi(value); err != nil {
			return nil, fmt.Errorf("%w: alterid must be a number", ErrInvalidOption)
		}
	}
	tlsOpts, err := parseTLSOptions(opts, tlsOptional)
	if err != nil {
		return nil, err
	}
	return NewVMess(VMessOptions{
		Server: spec.Server, Port: spec.Port, UUID: id,
		Security: opts[optSecurity], TLS: tlsOpts,
	})
}

func parseVMessUUID(s string) ([16]byte, error) {
	var out [16]byte
	compact := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(compact) != 32 {
		return out, fmt.Errorf("%w: uuid must be 16 bytes of hex", ErrInvalidOption)
	}
	raw, err := hex.DecodeString(compact)
	if err != nil {
		return out, fmt.Errorf("%w: uuid is not hex: %v", ErrInvalidOption, err)
	}
	copy(out[:], raw)
	return out, nil
}

func vmessSecurityFor(name string) (byte, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "auto", "aes-128-gcm":
		return vmessSecurityAESGCM, nil
	case "chacha20-poly1305":
		return vmessSecurityChaCha, nil
	default:
		return 0, fmt.Errorf("%w: unsupported security %q", ErrInvalidOption, name)
	}
}

// DialContext implements Dialer with the TCP command.
func (v *VMess) DialContext(ctx context.Context, address string) (net.Conn, error) {
	return v.open(ctx, address, vmessCommandTCP, false)
}

// DialPacket implements Dialer with the UDP command. VMess carries datagrams
// as discrete body chunks over the same TCP hop, each chunk naming its own
// destination, so one association can serve one target without a UDP socket.
func (v *VMess) DialPacket(ctx context.Context, address string) (PacketConn, error) {
	conn, err := v.open(ctx, address, vmessCommandUDP, true)
	if err != nil {
		return nil, err
	}
	chunks := conn.(*vmessChunkConn)
	return &vmessPacketConn{chunks: chunks, dest: chunks.remote.(Target)}, nil
}

func (v *VMess) open(ctx context.Context, address string, command byte, datagrams bool) (net.Conn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	if !target.IsIP() && len(target.Host) > 255 {
		return nil, fmt.Errorf("vmess: %w: address name is too long", ErrInvalidAddress)
	}
	conn, err := dialProxyHop(ctx, v.server, v.host, v.timeout, v.tls)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	return completeHandshake(ctx, conn, func(c net.Conn) (net.Conn, error) {
		return v.openSession(c, target, command, datagrams)
	})
}

// vmessSession holds the keys of one connection. The response direction has
// its own key and IV, derived from the request ones with SHA-256.
type vmessSession struct {
	requestKey, requestIV   [16]byte
	responseKey, responseIV [16]byte
	responseHeader          byte
	security                byte
}

func newVMessSession(security byte) (*vmessSession, error) {
	s := &vmessSession{security: security}
	key, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	iv, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	marker, err := randomBytes(1)
	if err != nil {
		return nil, err
	}
	copy(s.requestKey[:], key)
	copy(s.requestIV[:], iv)
	s.responseHeader = marker[0]
	sumKey := sha256.Sum256(s.requestKey[:])
	sumIV := sha256.Sum256(s.requestIV[:])
	copy(s.responseKey[:], sumKey[:16])
	copy(s.responseIV[:], sumIV[:16])
	return s, nil
}

func (s *vmessSession) bodyAEAD(key []byte) (cipher.AEAD, error) {
	switch s.security {
	case vmessSecurityAESGCM:
		return newAESGCM(key)
	case vmessSecurityChaCha:
		first := md5.Sum(key)
		second := md5.Sum(first[:])
		full := append(append([]byte(nil), first[:]...), second[:]...)
		return chacha20poly1305.New(full)
	default:
		return nil, errors.New("vmess: unknown body security")
	}
}

// openSession writes the AEAD request header, reads and validates the AEAD
// response header, and returns the chunk-framed body connection.
func (v *VMess) openSession(conn net.Conn, target Target, command byte, datagrams bool) (net.Conn, error) {
	session, err := newVMessSession(v.security)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	header, err := vmessRequestHeader(session, target, command)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	sealed, err := vmessSealHeader(v.cmdKey, header)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	if _, err := conn.Write(sealed); err != nil {
		return nil, fmt.Errorf("vmess: write request header: %w", err)
	}
	if err := vmessReadResponseHeader(conn, session); err != nil {
		return nil, err
	}
	writeAEAD, err := session.bodyAEAD(session.requestKey[:])
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	readAEAD, err := session.bodyAEAD(session.responseKey[:])
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	return &vmessChunkConn{
		conn: conn, remote: target,
		writeAEAD: writeAEAD, readAEAD: readAEAD,
		writeIV: session.requestIV, readIV: session.responseIV,
		datagrams: datagrams,
	}, nil
}

// vmessRequestHeader builds the plaintext header that the AEAD envelope
// protects. It ends with an FNV1a hash over everything before it.
func vmessRequestHeader(s *vmessSession, target Target, command byte) ([]byte, error) {
	const paddingLen = 8
	pad, err := randomBytes(paddingLen)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 38+paddingLen+MaxUDPHeaderLen+4)
	buf = append(buf, vmessVersion)
	buf = append(buf, s.requestIV[:]...)
	buf = append(buf, s.requestKey[:]...)
	buf = append(buf, s.responseHeader, vmessOptionChunkStream)
	buf = append(buf, byte(paddingLen<<4)|s.security, 0, command)
	buf = appendVMessAddress(buf, target)
	buf = append(buf, pad...)
	h := fnv.New32a()
	_, _ = h.Write(buf)
	return h.Sum(buf), nil
}

// appendVMessAddress writes the port first, then the address, using the
// protocol's own address type numbers.
func appendVMessAddress(dst []byte, target Target) []byte {
	dst = binary.BigEndian.AppendUint16(dst, target.Port)
	if ip := net.ParseIP(target.Host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(dst, vmessATYPIPv4)
			return append(dst, v4...)
		}
		dst = append(dst, vmessATYPIPv6)
		return append(dst, ip.To16()...)
	}
	host := target.Host
	dst = append(dst, vmessATYPDomain, byte(len(host)))
	return append(dst, host...)
}

// decodeVMessAddress reads one port-then-address field and reports its size.
func decodeVMessAddress(b []byte) (Target, int, error) {
	if len(b) < 3 {
		return Target{}, 0, errors.New("vmess: truncated address")
	}
	port := binary.BigEndian.Uint16(b[:2])
	off := 2
	var host string
	switch b[off] {
	case vmessATYPIPv4:
		off++
		if len(b) < off+net.IPv4len {
			return Target{}, 0, errors.New("vmess: truncated ipv4 address")
		}
		host = net.IP(b[off : off+net.IPv4len]).String()
		off += net.IPv4len
	case vmessATYPIPv6:
		off++
		if len(b) < off+net.IPv6len {
			return Target{}, 0, errors.New("vmess: truncated ipv6 address")
		}
		host = net.IP(b[off : off+net.IPv6len]).String()
		off += net.IPv6len
	case vmessATYPDomain:
		off++
		if len(b) < off+1 {
			return Target{}, 0, errors.New("vmess: truncated name length")
		}
		length := int(b[off])
		off++
		if length == 0 || len(b) < off+length {
			return Target{}, 0, errors.New("vmess: truncated name")
		}
		host = string(b[off : off+length])
		off += length
	default:
		return Target{}, 0, fmt.Errorf("vmess: unsupported address type %#x", b[off])
	}
	return Target{Host: host, Port: port}, off, nil
}

// vmessKDFConstructor returns the nested HMAC constructor of a KDF path.
// The protocol's KDF is a chain of HMAC-SHA256 instances: each path element
// becomes the key of an HMAC whose hash is the previous element's HMAC.
func vmessKDFConstructor(path []string) func() hash.Hash {
	if len(path) == 0 {
		return func() hash.Hash { return hmac.New(sha256.New, []byte(vmessKDFRoot)) }
	}
	parent := vmessKDFConstructor(path[:len(path)-1])
	last := []byte(path[len(path)-1])
	return func() hash.Hash { return hmac.New(parent, last) }
}

func vmessKDF(key []byte, path ...string) []byte {
	var h hash.Hash
	if len(path) == 0 {
		h = hmac.New(sha256.New, []byte(vmessKDFRoot))
	} else {
		h = hmac.New(vmessKDFConstructor(path[:len(path)-1]), []byte(path[len(path)-1]))
	}
	_, _ = h.Write(key)
	return h.Sum(nil)
}

func vmessKDF16(key []byte, path ...string) []byte { return vmessKDF(key, path...)[:16] }

// vmessAuthID builds the 16-byte encrypted authenticator: a timestamp, four
// random bytes and a CRC32 over the first twelve bytes, sealed with one AES
// block under a KDF-derived key.
func vmessAuthID(cmdKey []byte) ([16]byte, error) {
	var plain, out [16]byte
	binary.BigEndian.PutUint64(plain[:8], uint64(time.Now().Unix()))
	fresh, err := randomBytes(4)
	if err != nil {
		return out, fmt.Errorf("generate auth id: %w", err)
	}
	copy(plain[8:12], fresh)
	binary.BigEndian.PutUint32(plain[12:], crc32.ChecksumIEEE(plain[:12]))
	block, err := aes.NewCipher(vmessKDF16(cmdKey, kdfAuthIDEncryption))
	if err != nil {
		return out, err
	}
	block.Encrypt(out[:], plain[:])
	return out, nil
}

// vmessDecodeAuthID decrypts an authenticator and validates its CRC32 and
// timestamp. The local test peer uses it; keeping both halves together stops
// the two from drifting apart.
func vmessDecodeAuthID(cmdKey, authID []byte) (int64, error) {
	if len(authID) != 16 {
		return 0, errors.New("vmess: auth id is not 16 bytes")
	}
	block, err := aes.NewCipher(vmessKDF16(cmdKey, kdfAuthIDEncryption))
	if err != nil {
		return 0, err
	}
	plain := make([]byte, 16)
	block.Decrypt(plain, authID)
	if got := binary.BigEndian.Uint32(plain[12:]); got != crc32.ChecksumIEEE(plain[:12]) {
		return 0, errors.New("vmess: auth id checksum does not match")
	}
	stamp := int64(binary.BigEndian.Uint64(plain[:8]))
	if delta := time.Now().Unix() - stamp; delta > 120 || delta < -120 {
		return 0, fmt.Errorf("vmess: auth id timestamp is %d seconds away", delta)
	}
	return stamp, nil
}

// vmessSealHeader wraps a plaintext request header in the AEAD envelope:
// auth id, encrypted length, connection nonce and encrypted header.
func vmessSealHeader(cmdKey, header []byte) ([]byte, error) {
	if len(header) > 0xFFFF {
		return nil, errors.New("vmess: header is too long")
	}
	authID, err := vmessAuthID(cmdKey)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(8)
	if err != nil {
		return nil, err
	}
	authArg, nonceArg := string(authID[:]), string(nonce)
	lengthAEAD, err := newAESGCM(vmessKDF16(cmdKey, kdfHeaderLenKey, authArg, nonceArg))
	if err != nil {
		return nil, err
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(header)))
	encLength := lengthAEAD.Seal(nil, vmessKDF(cmdKey, kdfHeaderLenIV, authArg, nonceArg)[:12], length[:], authID[:])
	headerAEAD, err := newAESGCM(vmessKDF16(cmdKey, kdfHeaderKey, authArg, nonceArg))
	if err != nil {
		return nil, err
	}
	encHeader := headerAEAD.Seal(nil, vmessKDF(cmdKey, kdfHeaderIV, authArg, nonceArg)[:12], header, authID[:])
	out := make([]byte, 0, 16+len(encLength)+8+len(encHeader))
	out = append(out, authID[:]...)
	out = append(out, encLength...)
	out = append(out, nonce...)
	return append(out, encHeader...), nil
}

// vmessOpenHeader is the inverse of vmessSealHeader. It is used by the local
// test peer and by the header validation tests.
func vmessOpenHeader(cmdKey []byte, r io.Reader) ([]byte, error) {
	authID := make([]byte, 16)
	if _, err := io.ReadFull(r, authID); err != nil {
		return nil, fmt.Errorf("vmess: read auth id: %w", err)
	}
	if _, err := vmessDecodeAuthID(cmdKey, authID); err != nil {
		return nil, err
	}
	encLength := make([]byte, 2+16)
	if _, err := io.ReadFull(r, encLength); err != nil {
		return nil, fmt.Errorf("vmess: read header length: %w", err)
	}
	nonce := make([]byte, 8)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, fmt.Errorf("vmess: read connection nonce: %w", err)
	}
	authArg, nonceArg := string(authID), string(nonce)
	lengthAEAD, err := newAESGCM(vmessKDF16(cmdKey, kdfHeaderLenKey, authArg, nonceArg))
	if err != nil {
		return nil, err
	}
	plainLength, err := lengthAEAD.Open(nil, vmessKDF(cmdKey, kdfHeaderLenIV, authArg, nonceArg)[:12], encLength, authID)
	if err != nil {
		return nil, fmt.Errorf("vmess: decrypt header length: %w", err)
	}
	length := int(binary.BigEndian.Uint16(plainLength))
	encHeader := make([]byte, length+16)
	if _, err := io.ReadFull(r, encHeader); err != nil {
		return nil, fmt.Errorf("vmess: read header: %w", err)
	}
	headerAEAD, err := newAESGCM(vmessKDF16(cmdKey, kdfHeaderKey, authArg, nonceArg))
	if err != nil {
		return nil, err
	}
	header, err := headerAEAD.Open(nil, vmessKDF(cmdKey, kdfHeaderIV, authArg, nonceArg)[:12], encHeader, authID)
	if err != nil {
		return nil, fmt.Errorf("vmess: decrypt header: %w", err)
	}
	return header, nil
}

// vmessParseRequestHeader validates the FNV1a hash and returns the fields the
// peer needs. It is used by the local test peer.
func vmessParseRequestHeader(header []byte) (session *vmessSession, target Target, command byte, err error) {
	if len(header) < 38+4 {
		return nil, Target{}, 0, errors.New("vmess: request header is too short")
	}
	body := header[:len(header)-4]
	h := fnv.New32a()
	_, _ = h.Write(body)
	if !bytes.Equal(h.Sum(nil), header[len(header)-4:]) {
		return nil, Target{}, 0, errors.New("vmess: request header hash does not match")
	}
	if body[0] != vmessVersion {
		return nil, Target{}, 0, fmt.Errorf("vmess: unsupported header version %d", body[0])
	}
	session = &vmessSession{
		responseHeader: body[33],
		security:       body[35] & 0x0F,
	}
	copy(session.requestIV[:], body[1:17])
	copy(session.requestKey[:], body[17:33])
	sumKey := sha256.Sum256(session.requestKey[:])
	sumIV := sha256.Sum256(session.requestIV[:])
	copy(session.responseKey[:], sumKey[:16])
	copy(session.responseIV[:], sumIV[:16])
	// The address follows the 38 fixed bytes immediately; the padding is
	// appended after it, just before the FNV1a hash.
	command = body[37]
	addrStart := 38
	if padding := int(body[35] >> 4); len(body) < addrStart+padding {
		return nil, Target{}, 0, errors.New("vmess: request header padding is truncated")
	}
	target, _, err = decodeVMessAddress(body[addrStart:])
	if err != nil {
		return nil, Target{}, 0, err
	}
	return session, target, command, nil
}

// vmessWriteResponseHeader writes the four-byte response header inside its own
// AEAD envelope. The local test peer calls it; the client reads the same shape.
func vmessWriteResponseHeader(w io.Writer, s *vmessSession) error {
	plain := []byte{s.responseHeader, 0, 0, 0}
	lenAEAD, err := newAESGCM(vmessKDF16(s.responseKey[:], kdfRespLenKey))
	if err != nil {
		return err
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(plain)))
	encLength := lenAEAD.Seal(nil, vmessKDF(s.responseIV[:], kdfRespLenIV)[:12], length[:], nil)
	payloadAEAD, err := newAESGCM(vmessKDF16(s.responseKey[:], kdfRespKey))
	if err != nil {
		return err
	}
	encPayload := payloadAEAD.Seal(nil, vmessKDF(s.responseIV[:], kdfRespIV)[:12], plain, nil)
	_, err = w.Write(append(encLength, encPayload...))
	return err
}

func vmessReadResponseHeader(r io.Reader, s *vmessSession) error {
	encLength := make([]byte, 2+16)
	if _, err := io.ReadFull(r, encLength); err != nil {
		return fmt.Errorf("vmess: read response header length: %w", err)
	}
	lenAEAD, err := newAESGCM(vmessKDF16(s.responseKey[:], kdfRespLenKey))
	if err != nil {
		return err
	}
	plainLength, err := lenAEAD.Open(nil, vmessKDF(s.responseIV[:], kdfRespLenIV)[:12], encLength, nil)
	if err != nil {
		return fmt.Errorf("vmess: decrypt response header length: %w", err)
	}
	encPayload := make([]byte, int(binary.BigEndian.Uint16(plainLength))+16)
	if _, err := io.ReadFull(r, encPayload); err != nil {
		return fmt.Errorf("vmess: read response header: %w", err)
	}
	payloadAEAD, err := newAESGCM(vmessKDF16(s.responseKey[:], kdfRespKey))
	if err != nil {
		return err
	}
	plain, err := payloadAEAD.Open(nil, vmessKDF(s.responseIV[:], kdfRespIV)[:12], encPayload, nil)
	if err != nil {
		return fmt.Errorf("vmess: decrypt response header: %w", err)
	}
	if len(plain) < 1 || plain[0] != s.responseHeader {
		return errors.New("vmess: response header does not echo the request marker")
	}
	return nil
}

// vmessChunkConn frames body data as [2-byte plaintext length][AEAD chunk].
// The nonce is the 12-byte IV prefix with a big-endian counter in its first
// two bytes; the request and response directions have independent keys and
// counters. With datagrams set, one Read returns exactly one chunk so the UDP
// path preserves packet boundaries.
type vmessChunkConn struct {
	conn      net.Conn
	remote    net.Addr
	writeAEAD cipher.AEAD
	readAEAD  cipher.AEAD
	writeIV   [16]byte
	readIV    [16]byte
	wCount    uint16
	rCount    uint16
	datagrams bool

	wmu     sync.Mutex
	rmu     sync.Mutex
	readBuf []byte
}

func vmessChunkNonce(iv [16]byte, count uint16) []byte {
	nonce := make([]byte, 12)
	copy(nonce, iv[:12])
	binary.BigEndian.PutUint16(nonce, count)
	return nonce
}

func (c *vmessChunkConn) writeChunk(payload []byte) error {
	if len(payload) > vmessMaxChunk {
		return fmt.Errorf("vmess: chunk of %d bytes exceeds %d", len(payload), vmessMaxChunk)
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(payload)))
	sealed := c.writeAEAD.Seal(nil, vmessChunkNonce(c.writeIV, c.wCount), payload, nil)
	c.wCount++
	frame := append(length[:], sealed...)
	_, err := c.conn.Write(frame)
	if err != nil {
		return fmt.Errorf("vmess: write chunk: %w", err)
	}
	return nil
}

func (c *vmessChunkConn) readChunk() ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(c.conn, length[:]); err != nil {
		return nil, fmt.Errorf("vmess: read chunk length: %w", err)
	}
	size := int(binary.BigEndian.Uint16(length[:]))
	if size > vmessMaxChunk {
		return nil, fmt.Errorf("vmess: chunk length %d exceeds %d", size, vmessMaxChunk)
	}
	sealed := make([]byte, size+c.readAEAD.Overhead())
	if _, err := io.ReadFull(c.conn, sealed); err != nil {
		return nil, fmt.Errorf("vmess: read chunk: %w", err)
	}
	plain, err := c.readAEAD.Open(nil, vmessChunkNonce(c.readIV, c.rCount), sealed, nil)
	c.rCount++
	if err != nil {
		return nil, fmt.Errorf("vmess: decrypt chunk: %w", err)
	}
	return plain, nil
}

func (c *vmessChunkConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.datagrams {
		if err := c.writeChunk(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	written := 0
	for written < len(p) {
		end := written + vmessMaxChunk
		if end > len(p) {
			end = len(p)
		}
		if err := c.writeChunk(p[written:end]); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (c *vmessChunkConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.datagrams {
		payload, err := c.readChunk()
		if err != nil {
			return 0, err
		}
		return copy(p, payload), nil
	}
	for len(c.readBuf) == 0 {
		payload, err := c.readChunk()
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			return 0, io.EOF
		}
		c.readBuf = payload
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *vmessChunkConn) Close() error                       { return c.conn.Close() }
func (c *vmessChunkConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *vmessChunkConn) RemoteAddr() net.Addr               { return c.remote }
func (c *vmessChunkConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *vmessChunkConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *vmessChunkConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

var _ net.Conn = (*vmessChunkConn)(nil)

// vmessPacketConn names the destination in every datagram chunk. VMess UDP
// chunks carry a port-then-address prefix, so a read strips it before handing
// the payload back as one datagram.
type vmessPacketConn struct {
	chunks *vmessChunkConn
	dest   Target
}

func (c *vmessPacketConn) Write(p []byte) (int, error) {
	frame := appendVMessAddress(nil, c.dest)
	frame = append(frame, p...)
	if _, err := c.chunks.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *vmessPacketConn) Read(p []byte) (int, error) {
	buf := make([]byte, vmessMaxChunk)
	n, err := c.chunks.Read(buf)
	if err != nil {
		return 0, err
	}
	_, off, err := decodeVMessAddress(buf[:n])
	if err != nil {
		return 0, err
	}
	return copy(p, buf[off:n]), nil
}

func (c *vmessPacketConn) Close() error                       { return c.chunks.Close() }
func (c *vmessPacketConn) LocalAddr() net.Addr                { return c.chunks.LocalAddr() }
func (c *vmessPacketConn) RemoteAddr() net.Addr               { return c.dest }
func (c *vmessPacketConn) SetDeadline(t time.Time) error      { return c.chunks.SetDeadline(t) }
func (c *vmessPacketConn) SetReadDeadline(t time.Time) error  { return c.chunks.SetReadDeadline(t) }
func (c *vmessPacketConn) SetWriteDeadline(t time.Time) error { return c.chunks.SetWriteDeadline(t) }

var _ PacketConn = (*vmessPacketConn)(nil)
