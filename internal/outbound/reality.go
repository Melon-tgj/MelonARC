package outbound

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
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
	// realitySessionIDLen is the size of the TLS 1.3 legacy session id, which
	// is where the client half of the handshake rides.
	realitySessionIDLen = 32
	// realitySessionIDOffset is where that session id starts inside a
	// marshaled ClientHello: the 4-byte handshake header, two bytes of legacy
	// version, the 32-byte random and the length byte in front of the id.
	realitySessionIDOffset = 4 + 2 + 32 + 1
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
//
// The TLS 1.3 handshake itself is done by the pinned uTLS client, which owns
// the state machine: the server authentication sequence, the key schedule, the
// record layer and the client Finished are its work, not this package's. What
// stays here is only what REALITY adds to a TLS 1.3 handshake:
//
//   - the client half of the proof, sealed into the legacy session id of a
//     ClientHello the browser-shaped template built;
//   - the authentication key derived from the X25519 share of that handshake;
//   - the check of the server's half, run from the certificate callback.
//
// A connection is returned only after the handshake completed, which includes
// this client's Finished, and only if the credential check passed. Every other
// outcome closes the connection: the caller never sees a half-open or
// unauthenticated stream.
func (o *RealityOptions) Dial(ctx context.Context, conn net.Conn, host string) (net.Conn, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	peerKey, err := ecdh.X25519().NewPublicKey(o.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("reality: the server key: %w", err)
	}

	// The certificate callback needs the key the session id was sealed with,
	// so it reads the value this closure computes.
	var (
		authKey  []byte
		verified bool
	)
	cfg := &utls.Config{
		ServerName: o.ServerName,
		// REALITY replaces the public key infrastructure with a shared-key
		// proof, so the chain check is off on purpose: nothing but the
		// callback below is allowed to accept this peer.
		InsecureSkipVerify: true,
		// No PSK resumption and no early data. Resuming would skip the
		// certificate that carries the server's half of the proof, and the
		// session id has to stay available to carry the client's half.
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// With the chain check off the library always reports no verified
			// chains, so this guard only fires if that ever changes. A chain
			// that verifies is a publicly trusted certificate, which means the
			// handshake reached the imitated site: that is a refusal, never a
			// success with an empty callback result.
			if len(verifiedChains) > 0 {
				return errors.New("reality: the peer presented a publicly trusted chain, not a REALITY server")
			}
			if err := realityVerifyCertificate(authKey, rawCerts); err != nil {
				return err
			}
			verified = true
			return nil
		},
	}

	uconn := utls.UClient(conn, cfg, utls.HelloChrome_Auto)
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("reality: build the client hello: %w", err)
	}
	hello := uconn.HandshakeState.Hello
	if hello == nil {
		return nil, errors.New("reality: the client hello was not built")
	}
	if len(hello.Random) < realitySaltLen+12 {
		return nil, errors.New("reality: the client hello carries no usable random")
	}
	keys := uconn.HandshakeState.State13.KeyShareKeys
	if keys == nil {
		return nil, errors.New("reality: the client hello carries no TLS 1.3 key share")
	}
	// The server derives the same key from the X25519 key share it was offered,
	// and it takes the standalone one. The browser templates offer a hybrid
	// group as well, and uTLS keeps the X25519 key of that share in its own
	// field, so sealing with the wrong half produces a ClientHello the server
	// can only treat as an unauthenticated probe: it answers with the imitated
	// site, and the mistake shows up as that site's certificate rather than as
	// an authentication error. The hybrid half is only the right choice for a
	// hello that offers nothing else.
	ecdhe := keys.Ecdhe
	if ecdhe == nil {
		ecdhe = keys.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, errors.New("reality: the client hello carries no X25519 key share")
	}
	shared, err := ecdhe.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("reality: the shared secret: %w", err)
	}
	authKey = realityAuthKey(shared, hello.Random)
	if len(authKey) != realityAuthKeyLen {
		return nil, errors.New("reality: no authentication key")
	}

	// The ALPN list and the signature algorithms are part of the hello the
	// template carries. Two adjustments are required by REALITY itself, and
	// both are applied to the extension objects so the marshaled bytes and the
	// lists the client checks the server against stay in step.
	if err := realityShapeHello(uconn, cfg, o.ALPN); err != nil {
		return nil, err
	}
	hello = uconn.HandshakeState.Hello
	if hello == nil || len(hello.Raw) == 0 {
		return nil, errors.New("reality: the client hello was not marshaled")
	}

	// The session id is sealed into the bytes that are actually sent. uTLS has
	// already marshaled the hello, including the template's own extensions and
	// padding, and the handshake writes that buffer verbatim: re-marshaling it
	// from the public message fields would drop the extension objects and
	// produce a different ClientHello, so the additional data has to be this
	// buffer with the id zeroed.
	if len(hello.Raw) < realitySessionIDOffset+realitySessionIDLen || hello.Raw[realitySessionIDOffset-1] != realitySessionIDLen {
		return nil, errors.New("reality: the template does not carry a 32-byte session id")
	}
	clear(hello.Raw[realitySessionIDOffset : realitySessionIDOffset+realitySessionIDLen])
	sealed := realitySealSessionID(authKey, hello.Random, hello.Raw, realitySessionIDOffset, realitySessionIDPlain(o.ShortID))
	if len(sealed) != realitySessionIDLen {
		return nil, errors.New("reality: could not seal the session id")
	}
	hello.SessionId = sealed
	copy(hello.Raw[realitySessionIDOffset:], sealed)

	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("reality: %w", err)
	}
	state := uconn.ConnectionState()
	if !state.HandshakeComplete {
		return nil, errors.New("reality: the handshake did not complete")
	}
	if state.Version != utls.VersionTLS13 {
		return nil, fmt.Errorf("reality: the handshake settled on version %#04x, want TLS 1.3", state.Version)
	}
	if state.DidResume {
		return nil, errors.New("reality: the handshake resumed a session instead of authenticating")
	}
	// The callback returning nil is not the proof: only a REALITY credential
	// sets this flag, and a peer whose certificate never reached the callback
	// leaves the connection unusable.
	if !verified {
		return nil, errors.New("reality: the handshake finished without a REALITY credential")
	}
	return uconn, nil
}

// realityShapeHello applies the two adjustments REALITY needs on top of the
// browser template it borrows the rest of the hello from.
//
// The first is Ed25519 in the signature algorithms. The credential the server
// proves itself with is an Ed25519 certificate, so a peer that only offers the
// template's list cannot present it: the handshake would die on certificate
// selection, before the REALITY check ever ran. The templates pinned by this
// build do not carry that scheme, which is why it is added here rather than
// assumed.
//
// The second is the ALPN list the configuration names, which replaces the
// template's own list when it differs.
//
// Both edits are made on the extension objects, not on the marshaled bytes, so
// that a re-marshal writes them and the lists the client checks the server
// against stay in step with what was offered.
func realityShapeHello(uconn *utls.UConn, cfg *utls.Config, alpn []string) error {
	changed := false
	for _, ext := range uconn.Extensions {
		switch e := ext.(type) {
		case *utls.SignatureAlgorithmsExtension:
			if !slices.Contains(e.SupportedSignatureAlgorithms, utls.Ed25519) {
				e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, utls.Ed25519)
				changed = true
			}
		case *utls.ALPNExtension:
			if len(alpn) > 0 && !slices.Equal(e.AlpnProtocols, alpn) {
				e.AlpnProtocols = append([]string(nil), alpn...)
				changed = true
			}
		}
	}
	hello := uconn.HandshakeState.Hello
	if hello == nil {
		return errors.New("reality: the client hello was not built")
	}
	// These two lists are what the client checks the server against, and they
	// were filled from the extension objects during the build, so an edit made
	// above has to be mirrored here or the client would enforce the list it no
	// longer offers.
	if len(alpn) > 0 {
		hello.AlpnProtocols = append([]string(nil), alpn...)
		cfg.NextProtos = append([]string(nil), alpn...)
	}
	if !slices.Contains(hello.SupportedSignatureAlgorithms, utls.Ed25519) {
		hello.SupportedSignatureAlgorithms = append(hello.SupportedSignatureAlgorithms, utls.Ed25519)
	}
	if !changed {
		return nil
	}
	if err := uconn.MarshalClientHello(); err != nil {
		return fmt.Errorf("reality: marshal the client hello: %w", err)
	}
	return nil
}

// realitySessionIDPlain builds the 16 bytes the client seals into the session
// id: three bytes of version, one reserved byte, a timestamp and the short id.
func realitySessionIDPlain(shortID []byte) []byte {
	plain := make([]byte, realityPlainLen)
	plain[0] = realityVersionMajor
	plain[1] = realityVersionMinor
	plain[2] = realityVersionPatch
	plain[3] = 0
	binary.BigEndian.PutUint32(plain[4:8], uint32(time.Now().Unix()))
	copy(plain[8:], shortID)
	return plain
}

// realityAuthKey derives the authentication key from the handshake secret. The
// first bytes of the client random are the salt, so two handshakes never share
// a key even against the same server key.
func realityAuthKey(shared, random []byte) []byte {
	if len(random) < realitySaltLen {
		return nil
	}
	key, err := hkdf.Key(sha256.New, shared, random[:realitySaltLen], realityAuthInfo, realityAuthKeyLen)
	if err != nil {
		return nil
	}
	return key
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
	if len(additional) < offset+realitySessionIDLen {
		return nil
	}
	clear(additional[offset : offset+realitySessionIDLen])
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
	if len(hello) < offset+realitySessionIDLen {
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
	ciphertext := append([]byte(nil), hello[offset:offset+realitySessionIDLen]...)
	clear(additional[offset : offset+realitySessionIDLen])
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
