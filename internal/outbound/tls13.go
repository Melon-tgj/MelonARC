package outbound

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// This file is a client-only TLS 1.3 implementation covering exactly what one
// handshake variant needs: one key share (the hybrid X25519MLKEM768 group, with
// plain X25519 as the fallback a server may choose), one AEAD cipher suite, no
// session resumption, no early data, no client certificates and no HelloRetry
// Request.
//
// It exists because crypto/tls does not let a caller choose the legacy session
// id, and the handshake variant built on top of this file (see reality.go)
// authenticates through exactly that field. Keeping the code here small and
// option-free is what makes it reviewable: every deviation from RFC 8446 is a
// line somebody can point at.
const (
	tls13Version       = 0x0304
	tls13LegacyVersion = 0x0303
	tls13CipherAES128  = 0x1301
	tls13MaxRecord     = 1 << 14
	tls13TagLen        = 16
	tls13KeyLen        = 16
	tls13IVLen         = 12
	tls13SessionIDLen  = 32

	tls13RecordChangeCipher = 20
	tls13RecordAlert        = 21
	tls13RecordHandshake    = 22
	tls13RecordApplication  = 23

	tls13ExtServerName        = 0
	tls13ExtSupportedGroups   = 10
	tls13ExtSignatureAlgs     = 13
	tls13ExtALPN              = 16
	tls13ExtKeyShare          = 51
	tls13ExtSupportedVersions = 43

	// tls13GroupX25519 is the classical group; tls13GroupX25519MLKEM768 is the
	// hybrid post-quantum group whose share is an ML-KEM-768 encapsulation key
	// followed by an X25519 public key.
	tls13GroupX25519         = 29
	tls13GroupX25519MLKEM768 = 4588

	tls13MsgClientHello = 1
	tls13MsgServerHello = 2
	tls13MsgEncExts     = 8
	tls13MsgCertificate = 11
	tls13MsgCertRequest = 13
	tls13MsgCertVerify  = 15
	tls13MsgFinished    = 20

	tls13SigEd25519         = 0x0807
	tls13SigECDSAP256SHA256 = 0x0403
	tls13SigRSAPSSRSAE256   = 0x0804
	tls13SigRSAPKCS1SHA256  = 0x0401

	tls13AlertCloseNotify = 0
)

// tls13SessionIDOffset is where the 32-byte legacy session id sits in the
// ClientHello: four bytes of handshake header, two of legacy version, 32 of
// random and one length byte.
const tls13SessionIDOffset = 4 + 2 + 32 + 1

// tls13HelloRetryRequestRandom is the special server random of RFC 8446 §4.1.3.
const tls13HelloRetryRequestRandom = "\xcf\x21\xad\x74\xe5\x9a\x61\x11" +
	"\xbe\x1d\x8c\x02\x1e\x65\xb8\x91" +
	"\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e" +
	"\x07\x9e\x09\xe2\xc8\xa8\x33\x9c"

// tls13ClientConfig is the handshake configuration.
type tls13ClientConfig struct {
	ServerName string
	ALPN       []string
	// PeerKey is the server's X25519 public key. It is required, and only
	// used, when SessionID is set: the session id is derived from the shared
	// secret, so the secret has to exist before the ClientHello is built.
	PeerKey []byte
	// SessionID is called once the ClientHello is assembled, with the offset
	// of its 32-byte legacy session id, the client random and the X25519
	// shared secret, and returns the 32 bytes to store there. The session id
	// is zero when it is called, so a caller that authenticates through it can
	// use the hello itself as additional data.
	SessionID func(hello []byte, offset int, random, shared []byte) [tls13SessionIDLen]byte
	// VerifyPeer receives the raw certificate chain. It runs after the server
	// finished message verifies, so the chain belongs to the peer that proved
	// possession of the handshake keys.
	VerifyPeer func(certs [][]byte) error
}

// tls13Conn is the established connection: application data in both
// directions, with the record layer underneath.
type tls13Conn struct {
	conn net.Conn
	in   *bufio.Reader

	readAEAD  cipher.AEAD
	writeAEAD cipher.AEAD
	readIV    []byte
	writeIV   []byte
	readSeq   uint64
	writeSeq  uint64

	// pending holds decrypted application bytes that did not fit the caller's
	// buffer; handshake holds decrypted handshake bytes that do not yet form a
	// whole message. A record boundary means nothing to a TLS 1.3 peer.
	pending   []byte
	handshake []byte

	rmu sync.Mutex
	wmu sync.Mutex

	closeOnce sync.Once
}

// tls13KeyExchange holds the private halves of the key share this client
// offers. The share is the hybrid X25519MLKEM768 group, and it is not optional:
// a REALITY server rejects a ClientHello whose key share does not carry an
// ML-KEM encapsulation key, because a handshake recorded today could be
// decrypted later by a quantum computer. The plain X25519 share is offered
// second, as a fallback a server may choose. Either way the classical half is
// what REALITY derives its authentication key from, so it is kept separately.
type tls13KeyExchange struct {
	mlkem  *mlkem.DecapsulationKey768
	x25519 *ecdh.PrivateKey
}

func newTLS13KeyExchange() (*tls13KeyExchange, error) {
	mlkemKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("tls13: generate an ml-kem key: %w", err)
	}
	curveKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tls13: generate a key share: %w", err)
	}
	return &tls13KeyExchange{mlkem: mlkemKey, x25519: curveKey}, nil
}

// share is the client key share in the order the group defines it: the ML-KEM
// encapsulation key first, then the X25519 public key.
func (k *tls13KeyExchange) share() []byte {
	share := make([]byte, 0, mlkem.EncapsulationKeySize768+32)
	share = append(share, k.mlkem.EncapsulationKey().Bytes()...)
	return append(share, k.x25519.PublicKey().Bytes()...)
}

// curveShared is the plain X25519 secret, which REALITY derives its
// authentication key from even when the handshake itself is hybrid.
func (k *tls13KeyExchange) curveShared(peer []byte) ([]byte, error) {
	peerKey, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, fmt.Errorf("tls13: server public key: %w", err)
	}
	shared, err := k.x25519.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("tls13: ecdh: %w", err)
	}
	return shared, nil
}

// shared returns the key schedule's ECDHE input for the group the server chose:
// the ML-KEM secret followed by the X25519 secret for the hybrid group, or the
// X25519 secret alone.
func (k *tls13KeyExchange) shared(group uint16, serverShare []byte) ([]byte, error) {
	if group == tls13GroupX25519 {
		return k.curveShared(serverShare)
	}
	const hybridLen = mlkem.CiphertextSize768 + 32
	if len(serverShare) != hybridLen {
		return nil, fmt.Errorf("tls13: server key share is %d bytes, want %d", len(serverShare), hybridLen)
	}
	secret, err := k.mlkem.Decapsulate(serverShare[:mlkem.CiphertextSize768])
	if err != nil {
		return nil, fmt.Errorf("tls13: decapsulate the server share: %w", err)
	}
	curve, err := k.curveShared(serverShare[mlkem.CiphertextSize768:])
	if err != nil {
		return nil, err
	}
	return append(secret[:len(secret):len(secret)], curve...), nil
}

// tls13Client runs the handshake on conn and returns the established
// connection. conn stays owned by the caller on error and becomes owned by the
// result on success.
func tls13Client(ctx context.Context, conn net.Conn, cfg tls13ClientConfig) (*tls13Conn, error) {
	if cfg.ServerName == "" {
		return nil, errors.New("tls13: no server name")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	key, err := newTLS13KeyExchange()
	if err != nil {
		return nil, err
	}
	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, fmt.Errorf("tls13: generate random: %w", err)
	}
	var sessionID [tls13SessionIDLen]byte
	var shared []byte
	if cfg.SessionID != nil {
		if len(cfg.PeerKey) != 32 {
			return nil, errors.New("tls13: a session id builder needs a 32-byte peer key")
		}
		if shared, err = key.curveShared(cfg.PeerKey); err != nil {
			return nil, err
		}
	} else if _, err := io.ReadFull(rand.Reader, sessionID[:]); err != nil {
		return nil, fmt.Errorf("tls13: generate session id: %w", err)
	}

	hello := tls13BuildClientHello(cfg, random, sessionID, key.share())
	if cfg.SessionID != nil {
		sealed := cfg.SessionID(hello, tls13SessionIDOffset, random, shared)
		copy(hello[tls13SessionIDOffset:tls13SessionIDOffset+tls13SessionIDLen], sealed[:])
	}
	// The session id the server has to echo is whatever ended up in the hello.
	copy(sessionID[:], hello[tls13SessionIDOffset:tls13SessionIDOffset+tls13SessionIDLen])
	client := &tls13Conn{conn: conn, in: bufio.NewReaderSize(conn, 4096)}
	if err := client.writeRecordLocked(tls13RecordHandshake, hello); err != nil {
		return nil, err
	}

	// The transcript accumulates handshake messages without their record
	// headers; every secret below is derived from a prefix of it.
	transcript := append([]byte(nil), hello...)
	serverHello, err := client.nextMessage(ctx)
	if err != nil {
		return nil, err
	}
	if serverHello[0] != tls13MsgServerHello {
		return nil, fmt.Errorf("tls13: first handshake message is type %d, want a server hello", serverHello[0])
	}
	group, serverShare, err := tls13ParseServerHello(serverHello, sessionID)
	if err != nil {
		return nil, err
	}
	shared, err = key.shared(group, serverShare)
	if err != nil {
		return nil, err
	}
	transcript = append(transcript, serverHello...)

	hs, err := tls13HandshakeSecrets(shared, transcript)
	if err != nil {
		return nil, err
	}
	client.readAEAD, client.readIV = hs.serverAEAD, hs.serverIV
	client.writeAEAD, client.writeIV = hs.clientAEAD, hs.clientIV

	var certs [][]byte
	sawFinished := false
	for !sawFinished {
		message, err := client.nextMessage(ctx)
		if err != nil {
			return nil, err
		}
		switch message[0] {
		case tls13MsgEncExts:
			transcript = append(transcript, message...)
		case tls13MsgCertRequest:
			return nil, errors.New("tls13: the server asked for a client certificate, which this client cannot present")
		case tls13MsgCertificate:
			if certs != nil {
				return nil, errors.New("tls13: the server sent two certificate messages")
			}
			if certs, err = tls13ParseCertificate(message); err != nil {
				return nil, err
			}
			transcript = append(transcript, message...)
		case tls13MsgCertVerify:
			// The signature is not checked here. The handshake is
			// authenticated by the finished message that follows, and the
			// caller's certificate check decides whether the chain is
			// acceptable; this client is for a caller that does not rely on a
			// certificate chain at all.
			transcript = append(transcript, message...)
		case tls13MsgFinished:
			if certs == nil {
				return nil, errors.New("tls13: the server finished without a certificate")
			}
			if !hmac.Equal(tls13FinishedMAC(hs.serverFinishedKey, transcript), message[4:]) {
				return nil, errors.New("tls13: the server finished message does not verify")
			}
			transcript = append(transcript, message...)
			sawFinished = true
		default:
			return nil, fmt.Errorf("tls13: unexpected handshake message type %d", message[0])
		}
	}

	if cfg.VerifyPeer != nil {
		if err := cfg.VerifyPeer(certs); err != nil {
			return nil, err
		}
	}
	// The application traffic secrets cover the whole handshake, including the
	// server finished message that was just verified.
	app, err := tls13ApplicationSecrets(hs.masterSecret, transcript)
	if err != nil {
		return nil, err
	}
	if err := client.writeRecordProtected(tls13RecordHandshake, tls13FinishedMessage(hs.clientFinishedKey, transcript)); err != nil {
		return nil, err
	}
	client.readAEAD, client.readIV, client.readSeq = app.serverAEAD, app.serverIV, 0
	client.writeAEAD, client.writeIV, client.writeSeq = app.clientAEAD, app.clientIV, 0
	return client, nil
}

// tls13BuildClientHello assembles the ClientHello handshake message.
func tls13BuildClientHello(cfg tls13ClientConfig, random []byte, sessionID [tls13SessionIDLen]byte, keyShare []byte) []byte {
	body := make([]byte, 0, 512)
	body = append(body, tls13LegacyVersion>>8, tls13LegacyVersion&0xff)
	body = append(body, random...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID[:]...)
	body = binary.BigEndian.AppendUint16(body, 2) // one cipher suite
	body = binary.BigEndian.AppendUint16(body, tls13CipherAES128)
	body = append(body, 1, 0) // one compression method: null

	extensions := make([]byte, 0, 256)
	extensions = tls13AppendServerName(extensions, cfg.ServerName)
	extensions = tls13AppendSupportedGroups(extensions)
	extensions = tls13AppendSignatureAlgorithms(extensions)
	if len(cfg.ALPN) > 0 {
		extensions = tls13AppendALPN(extensions, cfg.ALPN)
	}
	extensions = tls13AppendKeyShare(extensions, keyShare)
	extensions = tls13AppendSupportedVersions(extensions)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	out := make([]byte, 0, 4+len(body))
	out = append(out, tls13MsgClientHello)
	out = tls13AppendUint24(out, len(body))
	return append(out, body...)
}

func tls13AppendExtension(dst []byte, typ uint16, payload []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, typ)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(payload)))
	return append(dst, payload...)
}

func tls13AppendServerName(dst []byte, name string) []byte {
	entry := make([]byte, 0, 5+len(name))
	entry = append(entry, 0) // host_name
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(name)))
	entry = append(entry, name...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	list = append(list, entry...)
	return tls13AppendExtension(dst, tls13ExtServerName, list)
}

func tls13AppendSupportedGroups(dst []byte) []byte {
	groups := []uint16{tls13GroupX25519MLKEM768, tls13GroupX25519}
	payload := binary.BigEndian.AppendUint16(nil, uint16(2*len(groups)))
	for _, group := range groups {
		payload = binary.BigEndian.AppendUint16(payload, group)
	}
	return tls13AppendExtension(dst, tls13ExtSupportedGroups, payload)
}

func tls13AppendSignatureAlgorithms(dst []byte) []byte {
	algorithms := []uint16{
		tls13SigEd25519, tls13SigECDSAP256SHA256, tls13SigRSAPSSRSAE256, tls13SigRSAPKCS1SHA256,
	}
	payload := binary.BigEndian.AppendUint16(nil, uint16(2*len(algorithms)))
	for _, algorithm := range algorithms {
		payload = binary.BigEndian.AppendUint16(payload, algorithm)
	}
	return tls13AppendExtension(dst, tls13ExtSignatureAlgs, payload)
}

func tls13AppendALPN(dst []byte, protocols []string) []byte {
	list := make([]byte, 0, 32)
	for _, protocol := range protocols {
		list = append(list, byte(len(protocol)))
		list = append(list, protocol...)
	}
	payload := binary.BigEndian.AppendUint16(nil, uint16(len(list)))
	payload = append(payload, list...)
	return tls13AppendExtension(dst, tls13ExtALPN, payload)
}

func tls13AppendKeyShare(dst []byte, share []byte) []byte {
	entry := binary.BigEndian.AppendUint16(nil, tls13GroupX25519MLKEM768)
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(share)))
	entry = append(entry, share...)
	payload := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	payload = append(payload, entry...)
	return tls13AppendExtension(dst, tls13ExtKeyShare, payload)
}

func tls13AppendSupportedVersions(dst []byte) []byte {
	payload := []byte{2, tls13Version >> 8, tls13Version & 0xff}
	return tls13AppendExtension(dst, tls13ExtSupportedVersions, payload)
}

// tls13ParseServerHello returns the server's X25519 key share.
func tls13ParseServerHello(message []byte, sessionID [tls13SessionIDLen]byte) (uint16, []byte, error) {
	if len(message) < 4 {
		return 0, nil, errors.New("tls13: truncated server hello")
	}
	body := message[4:]
	if len(body) < 2+32+1 {
		return 0, nil, errors.New("tls13: truncated server hello")
	}
	if binary.BigEndian.Uint16(body) != tls13LegacyVersion {
		return 0, nil, errors.New("tls13: server hello has an unexpected legacy version")
	}
	if string(body[2:34]) == tls13HelloRetryRequestRandom {
		return 0, nil, errors.New("tls13: the server sent a hello retry request, which this client does not support")
	}
	rest := body[34:]
	idLen := int(rest[0])
	rest = rest[1:]
	if len(rest) < idLen+3 {
		return 0, nil, errors.New("tls13: truncated server hello")
	}
	if idLen != len(sessionID) || !hmac.Equal(rest[:idLen], sessionID[:]) {
		return 0, nil, errors.New("tls13: the server echoed a different session id")
	}
	rest = rest[idLen:]
	if suite := binary.BigEndian.Uint16(rest); suite != tls13CipherAES128 {
		return 0, nil, fmt.Errorf("tls13: the server chose cipher suite %#04x", suite)
	}
	if rest[2] != 0 {
		return 0, nil, errors.New("tls13: the server chose a compression method")
	}
	rest = rest[3:]
	if len(rest) < 2 {
		return 0, nil, errors.New("tls13: server hello has no extensions")
	}
	extLen := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if len(rest) < extLen {
		return 0, nil, errors.New("tls13: truncated server hello extensions")
	}
	extensions := rest[:extLen]

	var (
		keyShare       []byte
		chosenGroup    uint16
		chosenVersion  uint16
		haveVersionExt bool
	)
	for len(extensions) >= 4 {
		typ := binary.BigEndian.Uint16(extensions)
		length := int(binary.BigEndian.Uint16(extensions[2:]))
		extensions = extensions[4:]
		if len(extensions) < length {
			return 0, nil, errors.New("tls13: truncated server hello extension")
		}
		payload := extensions[:length]
		extensions = extensions[length:]
		switch typ {
		case tls13ExtKeyShare:
			if len(payload) < 4 {
				return 0, nil, errors.New("tls13: truncated key share")
			}
			group := binary.BigEndian.Uint16(payload)
			keyLen := int(binary.BigEndian.Uint16(payload[2:]))
			if len(payload) < 4+keyLen {
				return 0, nil, errors.New("tls13: truncated key share")
			}
			switch group {
			case tls13GroupX25519:
				if keyLen != 32 {
					return 0, nil, errors.New("tls13: the server key share is not an x25519 key")
				}
			case tls13GroupX25519MLKEM768:
				if keyLen != mlkem.CiphertextSize768+32 {
					return 0, nil, errors.New("tls13: the server key share is not an X25519MLKEM768 share")
				}
			default:
				return 0, nil, fmt.Errorf("tls13: the server chose key share group %d", group)
			}
			keyShare = payload[4 : 4+keyLen]
			chosenGroup = group
		case tls13ExtSupportedVersions:
			if len(payload) != 2 {
				return 0, nil, errors.New("tls13: truncated supported versions extension")
			}
			haveVersionExt = true
			chosenVersion = binary.BigEndian.Uint16(payload)
		}
	}
	if !haveVersionExt || chosenVersion != tls13Version {
		return 0, nil, errors.New("tls13: the server did not select TLS 1.3")
	}
	if keyShare == nil {
		return 0, nil, errors.New("tls13: the server hello carries no key share")
	}
	return chosenGroup, keyShare, nil
}

// tls13ParseCertificate returns the certificate chain of a Certificate
// message. Only the DER blobs are kept: what a certificate means is the
// caller's business.
func tls13ParseCertificate(message []byte) ([][]byte, error) {
	if len(message) < 8 {
		return nil, errors.New("tls13: truncated certificate message")
	}
	body := message[4:]
	contextLen := int(body[0])
	body = body[1:]
	if len(body) < contextLen+3 {
		return nil, errors.New("tls13: truncated certificate message")
	}
	body = body[contextLen:]
	listLen := tls13Uint24(body)
	body = body[3:]
	if len(body) < listLen {
		return nil, errors.New("tls13: truncated certificate list")
	}
	list := body[:listLen]
	var certs [][]byte
	for len(list) >= 3 {
		certLen := tls13Uint24(list)
		list = list[3:]
		if certLen == 0 || len(list) < certLen {
			return nil, errors.New("tls13: truncated certificate")
		}
		certs = append(certs, append([]byte(nil), list[:certLen]...))
		list = list[certLen:]
		// Each entry may carry extensions; their length follows the
		// certificate itself.
		if len(list) < 2 {
			break
		}
		extLen := int(binary.BigEndian.Uint16(list))
		list = list[2:]
		if len(list) < extLen {
			return nil, errors.New("tls13: truncated certificate extensions")
		}
		list = list[extLen:]
	}
	if len(certs) == 0 {
		return nil, errors.New("tls13: the certificate list is empty")
	}
	return certs, nil
}

// tls13Secrets holds the traffic keys of one epoch.
type tls13Secrets struct {
	clientAEAD cipher.AEAD
	clientIV   []byte
	serverAEAD cipher.AEAD
	serverIV   []byte
}

// tls13HandshakeState is everything the rest of the handshake needs from the
// key schedule.
type tls13HandshakeState struct {
	tls13Secrets
	masterSecret      []byte
	clientFinishedKey []byte
	serverFinishedKey []byte
}

// tls13HandshakeSecrets derives the handshake traffic keys from the shared
// secret and the transcript of the hello exchange.
func tls13HandshakeSecrets(shared, transcript []byte) (tls13HandshakeState, error) {
	zeros := make([]byte, sha256.Size)
	emptyHash := sha256.Sum256(nil)
	early := hkdfExtract(zeros, zeros)
	derived := hkdfExpandLabel(early, "derived", emptyHash[:], sha256.Size)
	handshake := hkdfExtract(derived, shared)
	transcriptHash := sha256.Sum256(transcript)

	clientTraffic := hkdfExpandLabel(handshake, "c hs traffic", transcriptHash[:], sha256.Size)
	serverTraffic := hkdfExpandLabel(handshake, "s hs traffic", transcriptHash[:], sha256.Size)
	master := hkdfExtract(hkdfExpandLabel(handshake, "derived", emptyHash[:], sha256.Size), zeros)

	clientAEAD, clientIV, err := tls13TrafficKeys(clientTraffic)
	if err != nil {
		return tls13HandshakeState{}, err
	}
	serverAEAD, serverIV, err := tls13TrafficKeys(serverTraffic)
	if err != nil {
		return tls13HandshakeState{}, err
	}
	return tls13HandshakeState{
		tls13Secrets:      tls13Secrets{clientAEAD: clientAEAD, clientIV: clientIV, serverAEAD: serverAEAD, serverIV: serverIV},
		masterSecret:      master,
		clientFinishedKey: hkdfExpandLabel(clientTraffic, "finished", nil, sha256.Size),
		serverFinishedKey: hkdfExpandLabel(serverTraffic, "finished", nil, sha256.Size),
	}, nil
}

// tls13ApplicationSecrets derives the application traffic keys from the
// transcript that ends with the server finished message.
func tls13ApplicationSecrets(master, transcript []byte) (tls13Secrets, error) {
	hash := sha256.Sum256(transcript)
	clientAEAD, clientIV, err := tls13TrafficKeys(hkdfExpandLabel(master, "c ap traffic", hash[:], sha256.Size))
	if err != nil {
		return tls13Secrets{}, err
	}
	serverAEAD, serverIV, err := tls13TrafficKeys(hkdfExpandLabel(master, "s ap traffic", hash[:], sha256.Size))
	if err != nil {
		return tls13Secrets{}, err
	}
	return tls13Secrets{clientAEAD: clientAEAD, clientIV: clientIV, serverAEAD: serverAEAD, serverIV: serverIV}, nil
}

func tls13TrafficKeys(secret []byte) (cipher.AEAD, []byte, error) {
	block, err := aes.NewCipher(hkdfExpandLabel(secret, "key", nil, tls13KeyLen))
	if err != nil {
		return nil, nil, fmt.Errorf("tls13: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("tls13: %w", err)
	}
	return aead, hkdfExpandLabel(secret, "iv", nil, tls13IVLen), nil
}

// tls13FinishedMAC is HMAC over the transcript hash with the finished key.
func tls13FinishedMAC(finishedKey, transcript []byte) []byte {
	hash := sha256.Sum256(transcript)
	mac := hmac.New(sha256.New, finishedKey)
	_, _ = mac.Write(hash[:])
	return mac.Sum(nil)
}

// tls13FinishedMessage builds the Finished handshake message.
func tls13FinishedMessage(finishedKey, transcript []byte) []byte {
	verifyData := tls13FinishedMAC(finishedKey, transcript)
	out := []byte{tls13MsgFinished, 0, 0, byte(len(verifyData))}
	return append(out, verifyData...)
}

// hkdfExtract is RFC 5869 extract with an explicit salt: HMAC(salt, ikm).
func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpand is RFC 5869 expand for SHA-256.
func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var block []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		_, _ = mac.Write(block)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		block = mac.Sum(nil)
		out = append(out, block...)
	}
	return out[:length]
}

// hkdfExpandLabel is the TLS 1.3 variant: the info string carries the label,
// the context and the length.
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	full := "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdfExpand(secret, info, length)
}

// nextMessage returns the next complete handshake message, from the plaintext
// epoch or the encrypted one depending on how far the handshake has got.
func (c *tls13Conn) nextMessage(ctx context.Context) ([]byte, error) {
	for {
		if len(c.handshake) >= 4 {
			length := tls13Uint24(c.handshake[1:4])
			if length > 1<<16 {
				return nil, fmt.Errorf("tls13: handshake message of %d bytes is too large", length)
			}
			if len(c.handshake) >= 4+length {
				message := append([]byte(nil), c.handshake[:4+length]...)
				c.handshake = c.handshake[4+length:]
				return message, nil
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		typ, payload, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		switch typ {
		case tls13RecordHandshake, tls13RecordApplication:
			// Once the handshake keys exist, every message arrives in an
			// application-data record: that is what "encrypted" means at this
			// layer.
			if c.readAEAD == nil {
				if typ != tls13RecordHandshake {
					return nil, errors.New("tls13: an encrypted record arrived before the keys did")
				}
				c.handshake = append(c.handshake, payload...)
				continue
			}
			if typ != tls13RecordApplication {
				return nil, errors.New("tls13: a plaintext handshake record arrived after the keys")
			}
			inner, content, err := c.readEncrypted(payload)
			if err != nil {
				return nil, err
			}
			if inner != tls13RecordHandshake {
				return nil, fmt.Errorf("tls13: unexpected inner content type %d during the handshake", inner)
			}
			c.handshake = append(c.handshake, content...)
		case tls13RecordChangeCipher:
			continue
		case tls13RecordAlert:
			return nil, tls13AlertError(payload)
		default:
			return nil, fmt.Errorf("tls13: unexpected record type %d during the handshake", typ)
		}
	}
}

// readRecord reads one record header and payload.
func (c *tls13Conn) readRecord() (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(c.in, head[:]); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(head[3:]))
	if length > tls13MaxRecord+tls13TagLen+256 {
		return 0, nil, fmt.Errorf("tls13: record of %d bytes is larger than allowed", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.in, payload); err != nil {
		return 0, nil, err
	}
	return head[0], payload, nil
}

// writeRecordLocked writes one plaintext record.
func (c *tls13Conn) writeRecordLocked(typ byte, payload []byte) error {
	record := make([]byte, 5, 5+len(payload))
	record[0] = typ
	binary.BigEndian.PutUint16(record[1:], tls13LegacyVersion)
	binary.BigEndian.PutUint16(record[3:], uint16(len(payload)))
	if _, err := c.conn.Write(append(record, payload...)); err != nil {
		return fmt.Errorf("tls13: write record: %w", err)
	}
	return nil
}

// writeRecordProtected encrypts one record with the current write keys.
func (c *tls13Conn) writeRecordProtected(typ byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writeRecordProtectedLocked(typ, payload)
}

func (c *tls13Conn) writeRecordProtectedLocked(typ byte, payload []byte) error {
	plaintext := make([]byte, 0, len(payload)+1)
	plaintext = append(plaintext, payload...)
	plaintext = append(plaintext, typ)

	head := make([]byte, 5)
	head[0] = tls13RecordApplication
	binary.BigEndian.PutUint16(head[1:], tls13LegacyVersion)
	// The length has to be known before sealing because the header is the
	// additional data of the record.
	binary.BigEndian.PutUint16(head[3:], uint16(len(plaintext)+tls13TagLen))
	sealed := c.writeAEAD.Seal(nil, tls13Nonce(c.writeIV, c.writeSeq), plaintext, head)
	c.writeSeq++
	if _, err := c.conn.Write(append(head, sealed...)); err != nil {
		return fmt.Errorf("tls13: write record: %w", err)
	}
	return nil
}

// readEncrypted decrypts one record and returns its inner content type and
// payload.
func (c *tls13Conn) readEncrypted(payload []byte) (byte, []byte, error) {
	if len(payload) < tls13TagLen {
		return 0, nil, errors.New("tls13: record is shorter than its tag")
	}
	head := make([]byte, 5)
	head[0] = tls13RecordApplication
	binary.BigEndian.PutUint16(head[1:], tls13LegacyVersion)
	binary.BigEndian.PutUint16(head[3:], uint16(len(payload)))
	plaintext, err := c.readAEAD.Open(nil, tls13Nonce(c.readIV, c.readSeq), payload, head)
	if err != nil {
		return 0, nil, errors.New("tls13: a record failed to decrypt")
	}
	c.readSeq++

	// The content type is the last non-zero byte; everything after it is
	// padding, which RFC 8446 allows at any length.
	end := len(plaintext)
	for end > 0 && plaintext[end-1] == 0 {
		end--
	}
	if end == 0 {
		return 0, nil, errors.New("tls13: record has no content type")
	}
	return plaintext[end-1], plaintext[:end-1], nil
}

// tls13Nonce is the per-record nonce: the static IV with the sequence number
// xored into its last eight bytes.
func tls13Nonce(iv []byte, seq uint64) []byte {
	nonce := append([]byte(nil), iv...)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], seq)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-8+i] ^= counter[i]
	}
	return nonce
}

func tls13AlertError(payload []byte) error {
	if len(payload) >= 2 {
		return fmt.Errorf("tls13: the peer sent alert %d (level %d)", payload[1], payload[0])
	}
	return errors.New("tls13: the peer sent a truncated alert")
}

func tls13AppendUint24(dst []byte, n int) []byte {
	return append(dst, byte(n>>16), byte(n>>8), byte(n))
}

func tls13Uint24(b []byte) int {
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

// Read returns application data.
func (c *tls13Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		typ, payload, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		switch typ {
		case tls13RecordApplication:
			inner, content, err := c.readEncrypted(payload)
			if err != nil {
				return 0, err
			}
			switch inner {
			case tls13RecordApplication:
				c.pending = content
			case tls13RecordHandshake:
				// A post-handshake message: a session ticket, in practice.
				// This client has no use for one and the record is already
				// authenticated, so it is dropped. A ticket split over several
				// records is dropped one part at a time, which is harmless
				// only because nothing is ever parsed out of it.
				continue
			case tls13RecordAlert:
				if len(content) >= 2 && content[1] == tls13AlertCloseNotify {
					return 0, io.EOF
				}
				return 0, tls13AlertError(content)
			default:
				return 0, fmt.Errorf("tls13: unexpected inner content type %d", inner)
			}
		case tls13RecordAlert:
			if len(payload) >= 2 && payload[1] == tls13AlertCloseNotify {
				return 0, io.EOF
			}
			return 0, tls13AlertError(payload)
		case tls13RecordChangeCipher:
			continue
		default:
			return 0, fmt.Errorf("tls13: unexpected record type %d", typ)
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// Write encrypts and sends application data, splitting it into records no
// larger than the protocol allows.
func (c *tls13Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > tls13MaxRecord {
			chunk = chunk[:tls13MaxRecord]
		}
		if err := c.writeRecordProtectedLocked(tls13RecordApplication, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// CloseWrite sends close_notify. The connection stays open for reading, which
// is what a half-closed tunnel needs.
func (c *tls13Conn) CloseWrite() error {
	return c.writeRecordProtected(tls13RecordAlert, []byte{1, tls13AlertCloseNotify})
}

// Close sends close_notify and closes the transport. The alert is best effort:
// a peer that is already gone cannot receive it.
func (c *tls13Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		_ = c.CloseWrite()
		err = c.conn.Close()
	})
	return err
}

func (c *tls13Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *tls13Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *tls13Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *tls13Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *tls13Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

var _ net.Conn = (*tls13Conn)(nil)
