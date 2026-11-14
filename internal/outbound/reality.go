package outbound

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// REALITY replaces the certificate check of a TLS 1.3 handshake with a check
// the client can perform without trusting any authority: the client proves to
// the server that it knows the server's static public key, and the server
// proves the same thing back by sealing the session with a signature derived
// from the handshake secret.
//
// The two halves of that exchange live in fields every TLS 1.3 peer already
// sends, so the handshake is a normal one from the outside:
//
//   - the client writes a timestamp and a short id into the legacy session id,
//     encrypts the first half of it with a key derived from the X25519 shared
//     secret, and uses the whole ClientHello as additional data;
//   - the server answers with a certificate whose signature field is an HMAC
//     over its own public key, keyed by the same shared secret.
//
// The constants below are the protocol's public domain separators and field
// sizes, not secrets.
const (
	// realityAuthInfo is the HKDF info string of the authentication key.
	realityAuthInfo = "REALITY"
	// realityAuthKeyLen is the length of the authentication key.
	realityAuthKeyLen = 32
	// realityPlainLen is the part of the session id that carries data: three
	// bytes of protocol version, one reserved byte, four of timestamp and up
	// to eight of short id.
	realityPlainLen = 16
	// realitySaltLen is how much of the client random salts the auth key, and
	// how much of it is left as the AEAD nonce.
	realitySaltLen = 20
	// realityShortIDMax is the longest short id the protocol carries.
	realityShortIDMax = 8
	// realityVersion is the client version stamped into the session id.
	realityVersionMajor = 1
	realityVersionMinor = 8
	realityVersionPatch = 22
)

// RealityOptions is the client half of a REALITY handshake.
type RealityOptions struct {
	// PublicKey is the server's static X25519 public key.
	PublicKey []byte
	// ShortID distinguishes clients on the same server; it may be empty.
	ShortID []byte
	// ServerName is the certificate name of the site the handshake imitates.
	// It is the SNI, and the server must be configured to accept it.
	ServerName string
	// ALPN is the protocol list offered in the handshake. It is filled in by
	// the caller that knows which protocol is going to run on top, because a
	// handshake that imitates a browser has to offer what that browser offers.
	ALPN []string
}

// validate checks the options that a [Proxy] line can get wrong.
func (o *RealityOptions) validate() error {
	if len(o.PublicKey) != 32 {
		return fmt.Errorf("%w: reality= needs a 32-byte base64 public key", ErrInvalidOption)
	}
	if len(o.ShortID) > realityShortIDMax {
		return fmt.Errorf("%w: short-id is longer than %d bytes", ErrInvalidOption, realityShortIDMax)
	}
	if o.ServerName == "" {
		return fmt.Errorf("%w: reality= needs sni= (the name the handshake imitates)", ErrInvalidOption)
	}
	return nil
}

// parseRealityOptions reads the reality option group of a [Proxy] line.
func parseRealityOptions(publicKey, shortID, serverName string) (*RealityOptions, error) {
	if strings.TrimSpace(publicKey) == "" {
		return nil, fmt.Errorf("%w: reality= is empty", ErrInvalidOption)
	}
	key, err := decodeRealityKey(publicKey)
	if err != nil {
		return nil, err
	}
	var short []byte
	if shortID != "" {
		short, err = hex.DecodeString(shortID)
		if err != nil {
			return nil, fmt.Errorf("%w: short-id must be hex: %v", ErrInvalidOption, err)
		}
		if len(short) > realityShortIDMax {
			return nil, fmt.Errorf("%w: short-id is longer than %d bytes", ErrInvalidOption, realityShortIDMax)
		}
	}
	o := &RealityOptions{PublicKey: key, ShortID: short, ServerName: strings.TrimSpace(serverName)}
	if err := o.validate(); err != nil {
		return nil, err
	}
	return o, nil
}

// decodeRealityKey accepts the base64 forms a key is usually written in:
// unpadded or padded, standard or URL alphabet.
func decodeRealityKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		if key, err := encoding.DecodeString(value); err == nil {
			if len(key) != 32 {
				return nil, fmt.Errorf("%w: reality= key is %d bytes, want 32", ErrInvalidOption, len(key))
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("%w: reality= key is not base64", ErrInvalidOption)
}

// Dial runs the REALITY handshake on conn and returns the established
// connection.
func (o *RealityOptions) Dial(ctx context.Context, conn net.Conn, host string) (net.Conn, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	// The certificate check needs the key the session id was sealed with, so
	// the hook that computes it hands the value through this closure.
	var authKey []byte
	return tls13Client(ctx, conn, tls13ClientConfig{
		ServerName: o.ServerName,
		ALPN:       o.ALPN,
		PeerKey:    o.PublicKey,
		SessionID: func(hello []byte, offset int, random, shared []byte) [tls13SessionIDLen]byte {
			authKey = realityAuthKey(shared, random)
			var plain [realityPlainLen]byte
			plain[0] = realityVersionMajor
			plain[1] = realityVersionMinor
			plain[2] = realityVersionPatch
			plain[3] = 0
			binary.BigEndian.PutUint32(plain[4:8], uint32(time.Now().Unix()))
			copy(plain[8:], o.ShortID)
			var out [tls13SessionIDLen]byte
			copy(out[:], realitySealSessionID(authKey, random, hello, offset, plain[:]))
			return out
		},
		VerifyPeer: func(certs [][]byte) error {
			return realityVerifyCertificate(authKey, certs)
		},
	})
}

// realityAuthKey derives the authentication key from the handshake secret. The
// first bytes of the client random are the salt, so two handshakes never share
// a key even against the same server key.
func realityAuthKey(shared, random []byte) []byte {
	if len(random) < realitySaltLen {
		return nil
	}
	return hkdfExpand(hkdfExtract(random[:realitySaltLen], shared), []byte(realityAuthInfo), realityAuthKeyLen)
}

// realitySealSessionID encrypts the plaintext session id. The nonce is the
// rest of the client random and the additional data is the ClientHello with a
// zeroed session id, which is what the peer can rebuild from what it received:
// it never has to know the plaintext to check it.
func realitySealSessionID(authKey, random, hello []byte, offset int, plain []byte) []byte {
	if len(authKey) != realityAuthKeyLen || len(random) < realitySaltLen+12 {
		return nil
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	additional := append([]byte(nil), hello...)
	if len(additional) < offset+tls13SessionIDLen {
		return nil
	}
	clear(additional[offset : offset+tls13SessionIDLen])
	return aead.Seal(nil, random[realitySaltLen:realitySaltLen+12], plain, additional)
}

// realityOpenSessionID is the peer half of realitySealSessionID: it checks
// that a ClientHello's session id was sealed with the key that the server's
// static private key and the client's key share produce. The local test peer
// uses it, so the sealing side is verified by the same code that describes the
// format rather than by a second, drifting copy.
func realityOpenSessionID(hello []byte, offset int, authKey, random []byte) ([]byte, error) {
	if len(authKey) != realityAuthKeyLen || len(random) < realitySaltLen+12 {
		return nil, errors.New("reality: not enough key material")
	}
	if len(hello) < offset+tls13SessionIDLen {
		return nil, errors.New("reality: the client hello is too short for a session id")
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	additional := append([]byte(nil), hello...)
	ciphertext := append([]byte(nil), hello[offset:offset+tls13SessionIDLen]...)
	clear(additional[offset : offset+tls13SessionIDLen])
	plain, err := aead.Open(nil, random[realitySaltLen:realitySaltLen+12], ciphertext, additional)
	if err != nil {
		return nil, errors.New("reality: the session id was not sealed with this key")
	}
	if len(plain) != realityPlainLen {
		return nil, fmt.Errorf("reality: the session id opens to %d bytes, want %d", len(plain), realityPlainLen)
	}
	return plain, nil
}

// realityVerifyCertificate is the client's half of the server's proof: the
// leaf certificate carries an Ed25519 public key whose signature field is an
// HMAC over that key. A chain that does not verify this way is a real
// certificate, which means the handshake reached the imitated site instead of
// the server, and the connection is refused rather than used.
func realityVerifyCertificate(authKey []byte, certs [][]byte) error {
	if len(authKey) != realityAuthKeyLen {
		return errors.New("reality: the handshake produced no authentication key")
	}
	if len(certs) == 0 {
		return errors.New("reality: the server sent no certificate")
	}
	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return fmt.Errorf("reality: parse certificate: %w", err)
	}
	publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("reality: the server certificate carries a %T key, want ed25519", cert.PublicKey)
	}
	mac := hmac.New(sha512.New, authKey)
	_, _ = mac.Write(publicKey)
	if !hmac.Equal(mac.Sum(nil), cert.Signature) {
		return errors.New("reality: the server certificate is not sealed with the authentication key")
	}
	return nil
}

// realityServerCertificate builds the certificate a peer presents after a
// successful REALITY authentication: a certificate signed by signer whose
// signature field is then replaced by the HMAC the client checks. The
// signature value is the last element of a DER certificate, so the rewrite is a
// copy over its tail. The local test peer uses it.
func realityServerCertificate(template *x509.Certificate, signer crypto.Signer, authKey []byte) ([]byte, error) {
	if len(authKey) != realityAuthKeyLen {
		return nil, errors.New("reality: no authentication key")
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("reality: the template is not an ed25519 certificate")
	}
	mac := hmac.New(sha512.New, authKey)
	_, _ = mac.Write(publicKey)
	signature := mac.Sum(nil)
	if len(signature) != len(cert.Signature) {
		return nil, errors.New("reality: the certificate signature length does not match the HMAC")
	}
	copy(der[len(der)-len(signature):], signature)
	return der, nil
}
