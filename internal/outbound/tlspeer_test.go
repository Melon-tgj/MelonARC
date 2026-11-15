package outbound

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// This file is a scripted TLS 1.3 server. It exists because the interesting
// failures of a REALITY client live in the negative space of the handshake:
// crypto/tls only ever sends a correct, well-ordered flight, so a missing or
// duplicated CertificateVerify, a reordered flight, a signature over the wrong
// transcript or a wrong Finished can only be produced by a peer that speaks the
// record layer itself. It is test-only code; nothing here ships.

// Wire constants, spelled out rather than borrowed from the implementation, so
// a mistake in the client cannot hide behind a shared name.
const (
	peerRecordChangeCipher = 20
	peerRecordAlert        = 21
	peerRecordHandshake    = 22
	peerRecordAppData      = 23

	peerMsgClientHello = 1
	peerMsgServerHello = 2
	peerMsgEncExts     = 8
	peerMsgCertificate = 11
	peerMsgCertVerify  = 15
	peerMsgFinished    = 20

	peerExtALPN         = 16
	peerExtSigAlgs      = 13
	peerExtSupportedVer = 43
	peerExtKeyShare     = 51

	peerGroupX25519         = 29
	peerGroupX25519MLKEM768 = 4588

	peerSuiteAES128 = 0x1301

	peerSigEd25519         = 0x0807
	peerSigECDSAP256SHA256 = 0x0403
	peerSigRSAPKCS1SHA256  = 0x0401
)

const peerCertVerifyContext = "TLS 1.3, server CertificateVerify\x00"

// peerHello is the subset of a ClientHello the scripted server needs.
type peerHello struct {
	random    []byte
	sessionID []byte
	suites    []uint16
	alpn      []string
	keyShares map[uint16][]byte
	sigAlgs   []uint16
	versions  []uint16
}

// peerRecord reads one TLS record.
func peerRecord(r io.Reader) (byte, []byte, error) {
	head := make([]byte, 5)
	if _, err := io.ReadFull(r, head); err != nil {
		return 0, nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(head[3:]))
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return head[0], body, nil
}

func peerWriteRecord(w io.Writer, typ byte, payload []byte) error {
	head := []byte{typ, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(head[3:], uint16(len(payload)))
	_, err := w.Write(append(head, payload...))
	return err
}

// peerReadHandshake reads handshake messages until one whole message arrives.
func peerReadHandshake(r io.Reader) ([]byte, error) {
	var buf []byte
	for {
		typ, payload, err := peerRecord(r)
		if err != nil {
			return nil, err
		}
		if typ != peerRecordHandshake {
			if typ == peerRecordAlert && len(payload) >= 2 {
				return nil, fmt.Errorf("peer: the client sent alert %d", payload[1])
			}
			continue
		}
		buf = append(buf, payload...)
		if len(buf) >= 4 {
			want := 4 + int(buf[1])<<16 + int(buf[2])<<8 + int(buf[3])
			if len(buf) >= want {
				return buf[:want], nil
			}
		}
	}
}

// parsePeerHello reads the fields the server needs out of a ClientHello.
func parsePeerHello(msg []byte) (*peerHello, error) {
	if len(msg) < 4 || msg[0] != peerMsgClientHello {
		return nil, errors.New("peer: not a client hello")
	}
	body := msg[4:]
	h := &peerHello{keyShares: map[uint16][]byte{}}
	take := func(n int) ([]byte, bool) {
		if len(body) < n {
			return nil, false
		}
		out := body[:n]
		body = body[n:]
		return out, true
	}
	if _, ok := take(2); !ok { // legacy version
		return nil, errors.New("peer: truncated version")
	}
	random, ok := take(32)
	if !ok {
		return nil, errors.New("peer: truncated random")
	}
	h.random = append([]byte(nil), random...)
	idLen, ok := take(1)
	if !ok {
		return nil, errors.New("peer: truncated session id")
	}
	sessionID, ok := take(int(idLen[0]))
	if !ok {
		return nil, errors.New("peer: truncated session id")
	}
	h.sessionID = append([]byte(nil), sessionID...)
	suiteLen, ok := take(2)
	if !ok {
		return nil, errors.New("peer: truncated cipher suites")
	}
	suites, ok := take(int(binary.BigEndian.Uint16(suiteLen)))
	if !ok {
		return nil, errors.New("peer: truncated cipher suites")
	}
	for i := 0; i+1 < len(suites); i += 2 {
		h.suites = append(h.suites, binary.BigEndian.Uint16(suites[i:]))
	}
	compLen, ok := take(1)
	if !ok {
		return nil, errors.New("peer: truncated compression methods")
	}
	if _, ok := take(int(compLen[0])); !ok {
		return nil, errors.New("peer: truncated compression methods")
	}
	extLen, ok := take(2)
	if !ok {
		return nil, errors.New("peer: truncated extensions")
	}
	exts, ok := take(int(binary.BigEndian.Uint16(extLen)))
	if !ok {
		return nil, errors.New("peer: truncated extensions")
	}
	for len(exts) >= 4 {
		typ := binary.BigEndian.Uint16(exts)
		length := int(binary.BigEndian.Uint16(exts[2:]))
		exts = exts[4:]
		if len(exts) < length {
			return nil, errors.New("peer: truncated extension")
		}
		value := exts[:length]
		exts = exts[length:]
		switch typ {
		case peerExtALPN:
			if len(value) < 2 {
				continue
			}
			list := value[2:]
			for len(list) >= 1 {
				n := int(list[0])
				if len(list) < 1+n {
					break
				}
				h.alpn = append(h.alpn, string(list[1:1+n]))
				list = list[1+n:]
			}
		case peerExtKeyShare:
			if len(value) < 2 {
				continue
			}
			list := value[2:]
			for len(list) >= 4 {
				group := binary.BigEndian.Uint16(list)
				size := int(binary.BigEndian.Uint16(list[2:]))
				list = list[4:]
				if len(list) < size {
					break
				}
				h.keyShares[group] = append([]byte(nil), list[:size]...)
				list = list[size:]
			}
		case peerExtSigAlgs:
			if len(value) < 2 {
				continue
			}
			list := value[2:]
			for i := 0; i+1 < len(list); i += 2 {
				h.sigAlgs = append(h.sigAlgs, binary.BigEndian.Uint16(list[i:]))
			}
		case peerExtSupportedVer:
			if len(value) < 1 {
				continue
			}
			list := value[1:]
			for i := 0; i+1 < len(list); i += 2 {
				h.versions = append(h.versions, binary.BigEndian.Uint16(list[i:]))
			}
		}
	}
	return h, nil
}

// peerSecrets is one direction of the record layer.
type peerSecrets struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func newPeerSecrets(secret []byte) (*peerSecrets, error) {
	key, err := hkdfExpandLabel(secret, "key", nil, 16)
	if err != nil {
		return nil, err
	}
	iv, err := hkdfExpandLabel(secret, "iv", nil, 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &peerSecrets{aead: aead, iv: iv}, nil
}

func (p *peerSecrets) nonce() []byte {
	nonce := append([]byte(nil), p.iv...)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], p.seq)
	for i := range seq {
		nonce[len(nonce)-8+i] ^= seq[i]
	}
	p.seq++
	return nonce
}

func (p *peerSecrets) write(w io.Writer, typ byte, payload []byte) error {
	inner := append(append([]byte(nil), payload...), typ)
	head := []byte{peerRecordAppData, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(head[3:], uint16(len(inner)+p.aead.Overhead()))
	sealed := p.aead.Seal(nil, p.nonce(), inner, head)
	_, err := w.Write(append(head, sealed...))
	return err
}

// read returns the inner content type and the plaintext of one record.
func (p *peerSecrets) read(r io.Reader) (byte, []byte, error) {
	for {
		typ, body, err := peerRecord(r)
		if err != nil {
			return 0, nil, err
		}
		if typ != peerRecordAppData {
			if typ == peerRecordAlert && len(body) >= 2 {
				return 0, nil, fmt.Errorf("peer: the client sent alert %d", body[1])
			}
			continue
		}
		head := []byte{peerRecordAppData, 0x03, 0x03, 0, 0}
		binary.BigEndian.PutUint16(head[3:], uint16(len(body)))
		plain, err := p.aead.Open(nil, p.nonce(), body, head)
		if err != nil {
			return 0, nil, errors.New("peer: a record failed to decrypt")
		}
		if len(plain) == 0 {
			return 0, nil, errors.New("peer: empty record")
		}
		return plain[len(plain)-1], plain[:len(plain)-1], nil
	}
}

// hkdfExpandLabel is the TLS 1.3 label expansion.
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	full := "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

func peerHandshakeMessage(typ byte, body []byte) []byte {
	out := []byte{typ, 0, 0, 0}
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	return append(out, body...)
}

func slicesContainsUint16(list []uint16, want uint16) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// peerFlight is one scripted server configuration.
type peerFlight struct {
	// order spells the server authentication segment: E(encrypted
	// extensions), C(ertificate), V(ertificate verify), F(inished).
	order string
	// reality seals the certificate with the REALITY authentication key,
	// derived from the static key and the client's key share.
	reality   bool
	staticKey *ecdh.PrivateKey
	// plainLeaf sends an ordinary self-signed Ed25519 certificate that is not
	// sealed, which is what a peer that answers the handshake without being a
	// REALITY server does.
	plainLeaf bool
	// plainCert is sent instead of a generated leaf when set.
	plainCert []byte
	// signKey signs the CertificateVerify; the leaf key by default, so a
	// different key means a genuine signature that belongs to somebody else.
	signKey crypto.Signer
	// scheme overrides the signature scheme written into the message. The
	// signature itself still matches the key, so a scheme the certificate
	// cannot produce is a message the client has to refuse before it even
	// looks at the bytes.
	scheme uint16
	// wrongTranscript signs a transcript the client never saw.
	signAnotherTranscript bool
	// wrongCredential seals the certificate with another authentication key.
	wrongCredential bool
	// badFinished corrupts the server Finished.
	badFinished bool
	// echo sends application data back once the handshake completed.
	echo bool
}

// peerCountingConn counts the bytes a client has sent, so a test can talk about
// positions in the client's byte stream instead of guessing with sleeps. When
// tap is set, the bytes are also copied there, which is what a failure message
// needs to say what actually arrived.
type peerCountingConn struct {
	net.Conn
	read int
	tap  *peerEvents
}

func (c *peerCountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read += n
	if c.tap != nil && n > 0 {
		c.tap.mu.Lock()
		c.tap.afterBytes = append(c.tap.afterBytes, p[:n]...)
		c.tap.mu.Unlock()
	}
	return n, err
}

// peerEvents is what a test can observe about a scripted connection.
type peerEvents struct {
	mu sync.Mutex
	// hello is the ClientHello the client actually sent.
	hello *peerHello
	// finished is set once the client Finished verified.
	finished bool
	// finishedAt is the client byte offset just past that Finished record.
	finishedAt int
	// appData collects application records in arrival order.
	appData [][]byte
	// appAt is the client byte offset just past the first application record.
	appAt int
	// afterFlight counts every client byte that arrived after the server's
	// authentication segment: the Finished of a good handshake, an alert of a
	// bad one, and nothing else.
	afterFlight int
	// afterBytes is the same traffic verbatim, for failure messages.
	afterBytes []byte
	failure    error
	// done closes when the served connection ends, which is the only point at
	// which the counters above are final.
	done     chan struct{}
	doneOnce sync.Once
}

// peerState is a consistent copy of everything a test may inspect.
type peerState struct {
	hello       *peerHello
	finished    bool
	finishedAt  int
	appData     [][]byte
	appAt       int
	afterFlight int
	afterBytes  []byte
	failure     error
}

func newPeerEvents() *peerEvents { return &peerEvents{done: make(chan struct{})} }

func (e *peerEvents) snapshot() peerState {
	e.mu.Lock()
	defer e.mu.Unlock()
	return peerState{
		hello:       e.hello,
		finished:    e.finished,
		finishedAt:  e.finishedAt,
		appData:     e.appData,
		appAt:       e.appAt,
		afterFlight: e.afterFlight,
		afterBytes:  append([]byte(nil), e.afterBytes...),
		failure:     e.failure,
	}
}

func (e *peerEvents) sawFinished() bool { return e.snapshot().finished }

func (e *peerEvents) err() error { return e.snapshot().failure }

// wait blocks until the served connection ended, so a test reads final counters
// rather than racing the server goroutine.
func (e *peerEvents) wait(t *testing.T) {
	t.Helper()
	select {
	case <-e.done:
	case <-time.After(testServerDeadline):
		t.Fatal("the scripted peer did not finish serving the connection")
	}
}

func (e *peerEvents) finish() {
	e.doneOnce.Do(func() { close(e.done) })
}

// startTLSPeer runs one scripted TLS 1.3 server on a loopback port.
func startTLSPeer(t *testing.T, cfg peerFlight) (string, *peerEvents) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	events := newPeerEvents()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				defer events.finish()
				_ = c.SetDeadline(time.Now().Add(testServerDeadline))
				if err := serveTLSPeer(c, cfg, events); err != nil {
					events.mu.Lock()
					if events.failure == nil {
						events.failure = err
					}
					events.mu.Unlock()
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), events
}

func serveTLSPeer(raw net.Conn, cfg peerFlight, events *peerEvents) error {
	conn := &peerCountingConn{Conn: raw}
	h, err := newScriptedHandshake(conn, cfg, events)
	if err != nil {
		return err
	}
	if err := h.serverFlight(cfg); err != nil {
		return err
	}
	// Everything the client writes from here on is post-flight traffic: the
	// Finished of a handshake that verified, an alert of one that did not.
	// Neither can carry application data, which is what makes this counter a
	// usable answer to "did a request leave before authentication finished?".
	after := conn.read
	conn.tap = events
	defer func() {
		events.mu.Lock()
		events.afterFlight = conn.read - after
		events.mu.Unlock()
	}()
	if err := h.readClientFinished(events); err != nil {
		return err
	}
	if !cfg.echo {
		// Keep reading so a stray application write is observed rather than
		// silently reset.
		_ = h.drain(events)
		return nil
	}
	return h.echo(events)
}

// peerHandshake holds the state of one scripted handshake.
type peerHandshake struct {
	conn       net.Conn
	counted    *peerCountingConn
	hello      *peerHello
	transcript hash.Hash
	write      *peerSecrets
	read       *peerSecrets
	appWrite   *peerSecrets
	appRead    *peerSecrets
	clientHS   []byte
	serverHS   []byte
	master     []byte
}

func newScriptedHandshake(conn *peerCountingConn, cfg peerFlight, events *peerEvents) (*peerHandshake, error) {
	msg, err := peerReadHandshake(conn)
	if err != nil {
		return nil, err
	}
	hello, err := parsePeerHello(msg)
	if err != nil {
		return nil, err
	}
	events.mu.Lock()
	events.hello = hello
	events.mu.Unlock()
	if !slicesContainsUint16(hello.suites, peerSuiteAES128) {
		return nil, errors.New("peer: the client did not offer TLS_AES_128_GCM_SHA256")
	}
	group, serverShare, shared, err := peerKeyExchange(hello)
	if err != nil {
		return nil, err
	}

	zeros := make([]byte, 32)
	early, err := hkdf.Extract(sha256.New, zeros, zeros)
	if err != nil {
		return nil, err
	}
	// Derive-Secret with an empty transcript still has a context: the hash of
	// the empty string, not nothing.
	emptyTranscript := sha256.Sum256(nil)
	derived, err := hkdfExpandLabel(early, "derived", emptyTranscript[:], 32)
	if err != nil {
		return nil, err
	}
	handshakeSecret, err := hkdf.Extract(sha256.New, shared, derived)
	if err != nil {
		return nil, err
	}
	transcript := sha256.New()
	transcript.Write(msg)

	serverHello := peerServerHello(hello, group, serverShare)
	transcript.Write(serverHello)
	if err := peerWriteRecord(conn, peerRecordHandshake, serverHello); err != nil {
		return nil, err
	}

	th := transcript.Sum(nil)
	clientHS, err := hkdfExpandLabel(handshakeSecret, "c hs traffic", th, 32)
	if err != nil {
		return nil, err
	}
	serverHS, err := hkdfExpandLabel(handshakeSecret, "s hs traffic", th, 32)
	if err != nil {
		return nil, err
	}
	writeSecrets, err := newPeerSecrets(serverHS)
	if err != nil {
		return nil, err
	}
	readSecrets, err := newPeerSecrets(clientHS)
	if err != nil {
		return nil, err
	}
	derivedKey, err := hkdfExpandLabel(handshakeSecret, "derived", emptyTranscript[:], 32)
	if err != nil {
		return nil, err
	}
	master, err := hkdf.Extract(sha256.New, zeros, derivedKey)
	if err != nil {
		return nil, err
	}
	return &peerHandshake{
		conn:       conn,
		counted:    conn,
		hello:      hello,
		transcript: transcript,
		write:      writeSecrets,
		read:       readSecrets,
		clientHS:   clientHS,
		serverHS:   serverHS,
		master:     master,
	}, nil
}

// peerKeyExchange answers the key share a REALITY server would use: the hybrid
// group when it is offered, the plain X25519 one otherwise.
func peerKeyExchange(hello *peerHello) (uint16, []byte, []byte, error) {
	if share, ok := hello.keyShares[peerGroupX25519MLKEM768]; ok {
		if len(share) != mlkem.EncapsulationKeySize768+32 {
			return 0, nil, nil, errors.New("peer: the hybrid share has the wrong length")
		}
		ek, err := mlkem.NewEncapsulationKey768(share[:mlkem.EncapsulationKeySize768])
		if err != nil {
			return 0, nil, nil, err
		}
		secret, ciphertext := ek.Encapsulate()
		x, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return 0, nil, nil, err
		}
		peerKey, err := ecdh.X25519().NewPublicKey(share[mlkem.EncapsulationKeySize768:])
		if err != nil {
			return 0, nil, nil, err
		}
		classic, err := x.ECDH(peerKey)
		if err != nil {
			return 0, nil, nil, err
		}
		serverShare := append(append([]byte(nil), ciphertext...), x.PublicKey().Bytes()...)
		return peerGroupX25519MLKEM768, serverShare, append(append([]byte(nil), secret...), classic...), nil
	}
	share, ok := hello.keyShares[peerGroupX25519]
	if !ok {
		return 0, nil, nil, errors.New("peer: the client offered no usable key share")
	}
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return 0, nil, nil, err
	}
	peerKey, err := ecdh.X25519().NewPublicKey(share)
	if err != nil {
		return 0, nil, nil, err
	}
	shared, err := x.ECDH(peerKey)
	if err != nil {
		return 0, nil, nil, err
	}
	return peerGroupX25519, x.PublicKey().Bytes(), shared, nil
}

func peerServerHello(hello *peerHello, group uint16, share []byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	random := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, random)
	body = append(body, random...)
	body = append(body, byte(len(hello.sessionID)))
	body = append(body, hello.sessionID...)
	body = binary.BigEndian.AppendUint16(body, peerSuiteAES128)
	body = append(body, 0)

	exts := binary.BigEndian.AppendUint16(nil, peerExtSupportedVer)
	exts = binary.BigEndian.AppendUint16(exts, 2)
	exts = binary.BigEndian.AppendUint16(exts, 0x0304)
	keyShare := binary.BigEndian.AppendUint16(nil, group)
	keyShare = binary.BigEndian.AppendUint16(keyShare, uint16(len(share)))
	keyShare = append(keyShare, share...)
	exts = binary.BigEndian.AppendUint16(exts, peerExtKeyShare)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(keyShare)))
	exts = append(exts, keyShare...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	return peerHandshakeMessage(peerMsgServerHello, body)
}

// peerCertificate builds the leaf a scripted peer presents. With an
// authentication key the signature field is replaced by the REALITY HMAC, which
// is the credential a REALITY client checks; without one it is an ordinary
// self-signed certificate, which is what a peer that is not a REALITY server
// would send.
func peerCertificate(authKey []byte) ([]byte, crypto.Signer, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "scripted reality peer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	if authKey == nil {
		der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
		return der, private, err
	}
	der, err := realityServerCertificate(template, private, authKey)
	return der, private, err
}

func peerCertificateMessage(der []byte) []byte {
	entry := []byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}
	entry = append(entry, der...)
	entry = append(entry, 0, 0)
	body := []byte{0, byte(len(entry) >> 16), byte(len(entry) >> 8), byte(len(entry))}
	body = append(body, entry...)
	return peerHandshakeMessage(peerMsgCertificate, body)
}

// peerSign produces the CertificateVerify signature. The signature always
// matches the key, so a caller that declares another scheme is sending a
// message only a broken or hostile peer would send: a genuine signature with a
// label the certificate cannot produce.
func peerSign(key crypto.Signer, th []byte) ([]byte, error) {
	input := make([]byte, 0, 64+len(peerCertVerifyContext)+32)
	input = append(input, bytes.Repeat([]byte{0x20}, 64)...)
	input = append(input, peerCertVerifyContext...)
	input = append(input, th...)
	if _, ok := key.(ed25519.PrivateKey); ok {
		return key.Sign(rand.Reader, input, crypto.Hash(0))
	}
	digest := sha256.Sum256(input)
	return key.Sign(rand.Reader, digest[:], crypto.SHA256)
}

// serverFlight writes the authentication segment in the configured order.
func (h *peerHandshake) serverFlight(cfg peerFlight) error {
	var authKey []byte
	if cfg.reality {
		if cfg.staticKey == nil {
			return errors.New("peer: reality needs a static key")
		}
		classical := peerClassicalShare(h.hello)
		if classical == nil {
			return errors.New("peer: no classical share to authenticate")
		}
		peerKey, err := ecdh.X25519().NewPublicKey(classical)
		if err != nil {
			return err
		}
		shared, err := cfg.staticKey.ECDH(peerKey)
		if err != nil {
			return err
		}
		authKey = realityAuthKey(shared, h.hello.random)
		if cfg.wrongCredential {
			authKey = realityAuthKey(shared, append([]byte{0xff}, h.hello.random[1:]...))
		}
	}

	var certMsg []byte
	var certKey crypto.Signer
	switch {
	case cfg.reality:
		der, key, err := peerCertificate(authKey)
		if err != nil {
			return err
		}
		certMsg, certKey = peerCertificateMessage(der), key
	case len(cfg.plainCert) > 0:
		certMsg = peerCertificateMessage(cfg.plainCert)
	case cfg.plainLeaf:
		der, key, err := peerCertificate(nil)
		if err != nil {
			return err
		}
		certMsg, certKey = peerCertificateMessage(der), key
	default:
		return errors.New("peer: no certificate to send")
	}
	if cfg.signKey != nil {
		certKey = cfg.signKey
	}
	if certKey == nil {
		return errors.New("peer: no key to sign the certificate verify with")
	}
	scheme := cfg.scheme
	if scheme == 0 {
		scheme = peerSigEd25519
	}
	finishedKey, err := hkdfExpandLabel(h.serverHS, "finished", nil, 32)
	if err != nil {
		return err
	}

	encExts := peerHandshakeMessage(peerMsgEncExts, []byte{0, 0})
	for _, step := range cfg.order {
		var msg []byte
		switch step {
		case 'E':
			msg = encExts
		case 'C':
			msg = certMsg
		case 'V':
			th := h.transcript.Sum(nil)
			if cfg.signAnotherTranscript {
				sum := sha256.Sum256(append([]byte("another handshake"), th...))
				th = sum[:]
			}
			signature, err := peerSign(certKey, th)
			if err != nil {
				return err
			}
			body := binary.BigEndian.AppendUint16(nil, scheme)
			body = binary.BigEndian.AppendUint16(body, uint16(len(signature)))
			body = append(body, signature...)
			msg = peerHandshakeMessage(peerMsgCertVerify, body)
		case 'F':
			mac := hmac.New(sha256.New, finishedKey)
			mac.Write(h.transcript.Sum(nil))
			verifyData := mac.Sum(nil)
			if cfg.badFinished {
				verifyData[0] ^= 0x5a
			}
			msg = peerHandshakeMessage(peerMsgFinished, verifyData)
		default:
			return fmt.Errorf("peer: unknown flight step %q", step)
		}
		h.transcript.Write(msg)
		if err := h.write.write(h.conn, peerRecordHandshake, msg); err != nil {
			return err
		}
	}
	return nil
}

// peerClassicalShare returns the X25519 share a REALITY server authenticates
// against: the standalone one when the client offered it, and the classical
// half of the hybrid share only for a hello that offers nothing else.
func peerClassicalShare(hello *peerHello) []byte {
	if share, ok := hello.keyShares[peerGroupX25519]; ok {
		return share
	}
	if share, ok := hello.keyShares[peerGroupX25519MLKEM768]; ok && len(share) >= 32 {
		return share[len(share)-32:]
	}
	return nil
}

// readClientFinished verifies the client Finished, then derives the
// application traffic keys.
func (h *peerHandshake) readClientFinished(events *peerEvents) error {
	inner, payload, err := h.read.read(h.conn)
	if err != nil {
		return err
	}
	if inner != peerRecordHandshake {
		return fmt.Errorf("peer: the client sent inner content type %d, want a finished", inner)
	}
	if len(payload) < 4 || payload[0] != peerMsgFinished {
		return errors.New("peer: the client did not send a finished message")
	}
	finishedKey, err := hkdfExpandLabel(h.clientHS, "finished", nil, 32)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, finishedKey)
	mac.Write(h.transcript.Sum(nil))
	if !hmac.Equal(mac.Sum(nil), payload[4:]) {
		return errors.New("peer: the client finished does not verify")
	}
	// The application traffic secrets are derived from the transcript up to the
	// server Finished, so they are computed before this Finished joins it.
	th := h.transcript.Sum(nil)
	h.transcript.Write(payload)

	clientAP, err := hkdfExpandLabel(h.master, "c ap traffic", th, 32)
	if err != nil {
		return err
	}
	serverAP, err := hkdfExpandLabel(h.master, "s ap traffic", th, 32)
	if err != nil {
		return err
	}
	if h.appRead, err = newPeerSecrets(clientAP); err != nil {
		return err
	}
	if h.appWrite, err = newPeerSecrets(serverAP); err != nil {
		return err
	}
	events.mu.Lock()
	events.finished = true
	events.finishedAt = h.counted.read
	events.mu.Unlock()
	return nil
}

// observe records application bytes together with the client offset they ended
// at, which is what the ordering assertion is made of.
func (h *peerHandshake) observe(events *peerEvents, payload []byte) {
	events.mu.Lock()
	defer events.mu.Unlock()
	if events.appAt == 0 {
		events.appAt = h.counted.read
	}
	events.appData = append(events.appData, append([]byte(nil), payload...))
}

// drain reads application records without answering.
func (h *peerHandshake) drain(events *peerEvents) error {
	if h.appRead == nil {
		return nil
	}
	for {
		inner, payload, err := h.appRead.read(h.conn)
		if err != nil {
			return nil // a closed connection is the expected end here
		}
		if inner == peerRecordAppData {
			h.observe(events, payload)
			continue
		}
		if inner == peerRecordAlert {
			return nil
		}
	}
}

// peerStream reads decrypted application records as one byte stream, so the
// VLESS parsers of the package can run on a scripted connection instead of a
// second, drifting copy of the wire format.
type peerStream struct {
	h   *peerHandshake
	ev  *peerEvents
	buf []byte
}

func (s *peerStream) Read(p []byte) (int, error) {
	for len(s.buf) == 0 {
		inner, payload, err := s.h.appRead.read(s.h.conn)
		if err != nil {
			return 0, err
		}
		if inner != peerRecordAppData {
			continue
		}
		s.h.observe(s.ev, payload)
		s.buf = payload
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

// peerSink writes one application record per call.
type peerSink struct{ h *peerHandshake }

func (s peerSink) Write(p []byte) (int, error) {
	if err := s.h.appWrite.write(s.h.conn, peerRecordAppData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// echo answers application data with the same bytes after speaking just enough
// VLESS to make the connection usable.
func (h *peerHandshake) echo(events *peerEvents) error {
	in := &peerStream{h: h, ev: events}
	out := peerSink{h: h}
	id, err := parseVMessUUID(testVLESSID)
	if err != nil {
		return err
	}
	if _, _, _, err := vlessOpenRequest(in, id); err != nil {
		return err
	}
	if err := vlessWriteResponse(out); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			if _, writeErr := out.Write(buf[:n]); writeErr != nil {
				return nil
			}
		}
		if err != nil {
			return nil
		}
	}
}
