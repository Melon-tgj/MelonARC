package outbound

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// The AEAD cipher table. The three legacy methods derive a master key from a
// password with EVP_BytesToKey and a per-session subkey with HKDF-SHA1; the
// 2022 methods take a fixed-length base64 pre-shared key and derive the
// subkey with BLAKE3's derive-key mode.
const (
	legacyMaxPayload = 0x3FFF
	modernMaxPayload = 0xFFFF
	ssSubkeyInfo     = "ss-subkey"
	ss2022Context    = "shadowsocks 2022 session subkey"
)

type cipherInfo struct {
	name       string
	keyLen     int
	saltLen    int
	version22  bool
	chacha22   bool
	maxPayload int
	newAEAD    func(key []byte) (cipher.AEAD, error)
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func cipherInfoFor(name string) (cipherInfo, error) {
	switch name {
	case "aes-128-gcm":
		return cipherInfo{name: name, keyLen: 16, saltLen: 16, maxPayload: legacyMaxPayload, newAEAD: newAESGCM}, nil
	case "aes-256-gcm":
		return cipherInfo{name: name, keyLen: 32, saltLen: 32, maxPayload: legacyMaxPayload, newAEAD: newAESGCM}, nil
	case "chacha20-ietf-poly1305":
		return cipherInfo{name: name, keyLen: 32, saltLen: 32, maxPayload: legacyMaxPayload, newAEAD: chacha20poly1305.New}, nil
	case "2022-blake3-aes-128-gcm":
		return cipherInfo{name: name, keyLen: 16, saltLen: 16, version22: true, maxPayload: modernMaxPayload, newAEAD: newAESGCM}, nil
	case "2022-blake3-aes-256-gcm":
		return cipherInfo{name: name, keyLen: 32, saltLen: 32, version22: true, maxPayload: modernMaxPayload, newAEAD: newAESGCM}, nil
	case "2022-blake3-chacha20-poly1305":
		return cipherInfo{name: name, keyLen: 32, saltLen: 32, version22: true, chacha22: true,
			maxPayload: modernMaxPayload, newAEAD: chacha20poly1305.New}, nil
	default:
		return cipherInfo{}, fmt.Errorf("%w: unsupported cipher %q", ErrInvalidOption, name)
	}
}

// evpBytesToKey is the MD5 based password derivation the legacy AEAD family
// uses. Shadowsocks passes no salt for the master key.
func evpBytesToKey(password []byte, keyLen int) []byte {
	var previous, out []byte
	for len(out) < keyLen {
		h := md5.New()
		_, _ = h.Write(previous)
		_, _ = h.Write(password)
		previous = h.Sum(nil)
		out = append(out, previous...)
	}
	return out[:keyLen]
}

// masterKey turns the configured secret into the fixed-length key a cipher
// needs. Legacy methods hash a password; 2022 methods require a base64 PSK of
// exactly the cipher's key length, as their specification mandates.
func (c cipherInfo) masterKey(secret string) ([]byte, error) {
	if !c.version22 {
		if secret == "" {
			return nil, fmt.Errorf("%w: password is required for %s", ErrInvalidOption, c.name)
		}
		return evpBytesToKey([]byte(secret), c.keyLen), nil
	}
	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(secret)
		if err != nil {
			return nil, fmt.Errorf("%w: %s needs a base64 pre-shared key: %v", ErrInvalidOption, c.name, err)
		}
	}
	if len(key) != c.keyLen {
		return nil, fmt.Errorf("%w: %s needs a %d byte pre-shared key, got %d", ErrInvalidOption, c.name, c.keyLen, len(key))
	}
	return key, nil
}

// sessionKey derives the per-session AEAD key from the master key and salt.
func (c cipherInfo) sessionKey(master, salt []byte) (cipher.AEAD, error) {
	var key []byte
	if c.version22 {
		material := make([]byte, 0, len(master)+len(salt))
		material = append(material, master...)
		material = append(material, salt...)
		derived := blake3DeriveKey(ss2022Context, material)
		key = derived[:c.keyLen]
	} else {
		var err error
		key, err = hkdf.Key(sha1.New, master, salt, ssSubkeyInfo, c.keyLen)
		if err != nil {
			return nil, fmt.Errorf("derive session key: %w", err)
		}
	}
	return c.newAEAD(key)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}
	return b, nil
}

func incrementNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

// chunkStream is an AEAD protected stream whose unit is a chunk: each write
// seals one plaintext chunk with the current nonce and advances the nonce.
// Both the legacy AEAD chunk format and the 2022 TCP format are built from it;
// a "frame" is a pair of chunks (a 2-byte length and its payload), while a
// 2022 header is a single chunk with a known plaintext length.
type chunkStream struct {
	conn       net.Conn
	aead       cipher.AEAD
	wNonce     [12]byte
	rNonce     [12]byte
	maxPayload int

	wmu sync.Mutex
	rmu sync.Mutex

	readBuf []byte
}

func newChunkStream(conn net.Conn, aead cipher.AEAD, maxPayload int) *chunkStream {
	return &chunkStream{conn: conn, aead: aead, maxPayload: maxPayload}
}

// writeChunk seals one plaintext chunk and advances the write nonce.
func (s *chunkStream) writeChunk(plaintext []byte) error {
	sealed := s.aead.Seal(nil, s.wNonce[:], plaintext, nil)
	incrementNonce(s.wNonce[:])
	_, err := s.conn.Write(sealed)
	if err != nil {
		return fmt.Errorf("write chunk: %w", err)
	}
	return nil
}

// readChunk reads a chunk with plainLen plaintext bytes and advances the read
// nonce. plainLen may be zero, in which case only the tag is on the wire.
func (s *chunkStream) readChunk(plainLen int) ([]byte, error) {
	buf := make([]byte, plainLen+s.aead.Overhead())
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return nil, fmt.Errorf("read chunk: %w", err)
	}
	plain, err := s.aead.Open(buf[:0], s.rNonce[:], buf, nil)
	incrementNonce(s.rNonce[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt chunk: %w", err)
	}
	return plain, nil
}

// writeFrame writes one length chunk and one payload chunk in a single write.
func (s *chunkStream) writeFrame(payload []byte) error {
	if len(payload) > s.maxPayload {
		return fmt.Errorf("chunk payload %d exceeds %d", len(payload), s.maxPayload)
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(payload)))
	lengthChunk := s.aead.Seal(nil, s.wNonce[:], length[:], nil)
	incrementNonce(s.wNonce[:])
	payloadChunk := s.aead.Seal(nil, s.wNonce[:], payload, nil)
	incrementNonce(s.wNonce[:])
	frame := append(lengthChunk, payloadChunk...)
	_, err := s.conn.Write(frame)
	if err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// readFrame returns one length/payload frame's payload.
func (s *chunkStream) readFrame() ([]byte, error) {
	lengthChunk, err := s.readChunk(2)
	if err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(lengthChunk))
	if length > s.maxPayload {
		return nil, fmt.Errorf("chunk length %d exceeds %d", length, s.maxPayload)
	}
	return s.readChunk(length)
}

func (s *chunkStream) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	written := 0
	for written < len(p) {
		end := written + s.maxPayload
		if end > len(p) {
			end = len(p)
		}
		if err := s.writeFrame(p[written:end]); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (s *chunkStream) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	for len(s.readBuf) == 0 {
		payload, err := s.readFrame()
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			return 0, io.EOF
		}
		s.readBuf = payload
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

func (s *chunkStream) Close() error                       { return s.conn.Close() }
func (s *chunkStream) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *chunkStream) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *chunkStream) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *chunkStream) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *chunkStream) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

var _ net.Conn = (*chunkStream)(nil)

// decodeAddress reads the SOCKS-style address (ATYP, address, port) shared by
// the encrypted protocols and reports how many bytes it consumed.
func decodeAddress(b []byte) (Target, int, error) {
	if len(b) < 1 {
		return Target{}, 0, errors.New("address is empty")
	}
	atyp := b[0]
	off := 1
	var host string
	switch atyp {
	case atypIPv4:
		if len(b) < off+net.IPv4len+2 {
			return Target{}, 0, errors.New("truncated ipv4 address")
		}
		host = net.IP(b[off : off+net.IPv4len]).String()
		off += net.IPv4len
	case atypIPv6:
		if len(b) < off+net.IPv6len+2 {
			return Target{}, 0, errors.New("truncated ipv6 address")
		}
		host = net.IP(b[off : off+net.IPv6len]).String()
		off += net.IPv6len
	case atypDomain:
		if len(b) < off+1 {
			return Target{}, 0, errors.New("truncated name length")
		}
		length := int(b[off])
		off++
		if length == 0 || len(b) < off+length+2 {
			return Target{}, 0, errors.New("truncated name")
		}
		host = string(b[off : off+length])
		off += length
	default:
		return Target{}, 0, fmt.Errorf("unsupported address type %#x", atyp)
	}
	return Target{Host: host, Port: binary.BigEndian.Uint16(b[off : off+2])}, off + 2, nil
}
