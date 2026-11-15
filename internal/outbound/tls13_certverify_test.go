package outbound

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// testCertificateVerifyMessage wraps a signature scheme and a signature in the
// handshake message the client parses.
func testCertificateVerifyMessage(scheme uint16, signature []byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, scheme)
	body = binary.BigEndian.AppendUint16(body, uint16(len(signature)))
	body = append(body, signature...)
	out := []byte{tls13MsgCertVerify}
	out = tls13AppendUint24(out, len(body))
	return append(out, body...)
}

// testLeafCertificate issues a self-signed leaf for the key pair a test just
// generated. Only its SubjectPublicKeyInfo is used by the verifier, but a real
// DER certificate is what the handshake parses.
func testLeafCertificate(t *testing.T, public, private any) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "certificate verify test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatalf("create a leaf certificate: %v", err)
	}
	return der
}

// TestTLS13CertificateVerifyKnownAnswer pins the RFC 8446 §4.4.3 signed
// message for every scheme this client offers, and pins the rejection of a
// signature that was tampered with. The signature is produced here with the
// standard library's own primitives, not with the verifier's code.
func TestTLS13CertificateVerifyKnownAnswer(t *testing.T) {
	transcript := []byte("client hello|server hello|encrypted extensions|certificate")
	input := tls13CertificateVerifyInput(transcript)
	digest := sha256.Sum256(input)

	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate an ed25519 key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate an ecdsa key: %v", err)
	}
	ecSignature, err := ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
	if err != nil {
		t.Fatalf("sign with ecdsa: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate an rsa key: %v", err)
	}
	pssOptions := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	rsaSignature, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, digest[:], pssOptions)
	if err != nil {
		t.Fatalf("sign with rsa-pss: %v", err)
	}

	for _, tc := range []struct {
		name      string
		scheme    uint16
		cert      []byte
		signature []byte
	}{
		{tls13SigEd25519Name, tls13SigEd25519,
			testLeafCertificate(t, edPublic, edPrivate), ed25519.Sign(edPrivate, input)},
		{tls13SigECDSAName, tls13SigECDSAP256SHA256,
			testLeafCertificate(t, &ecKey.PublicKey, ecKey), ecSignature},
		{tls13SigRSAPSSName, tls13SigRSAPSSRSAE256,
			testLeafCertificate(t, &rsaKey.PublicKey, rsaKey), rsaSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			message := testCertificateVerifyMessage(tc.scheme, tc.signature)
			if err := tls13VerifyCertificateVerify([][]byte{tc.cert}, message, transcript); err != nil {
				t.Fatalf("a valid signature was rejected: %v", err)
			}

			// A single flipped bit in the signature must end the handshake.
			tampered := append([]byte(nil), tc.signature...)
			tampered[len(tampered)/2] ^= 0x40
			err := tls13VerifyCertificateVerify([][]byte{tc.cert},
				testCertificateVerifyMessage(tc.scheme, tampered), transcript)
			if err == nil || !strings.Contains(err.Error(), "does not verify") {
				t.Errorf("a tampered signature was accepted: %v", err)
			}

			// The signature covers the transcript, including the certificate
			// the peer just sent. Replaying it over another transcript fails.
			err = tls13VerifyCertificateVerify([][]byte{tc.cert}, message, append(transcript, 'x'))
			if err == nil || !strings.Contains(err.Error(), "does not verify") {
				t.Errorf("a signature was accepted over a different transcript: %v", err)
			}
		})
	}
}

// Names used only to label the subtests above.
const (
	tls13SigEd25519Name = "ed25519"
	tls13SigECDSAName   = "ecdsa_secp256r1_sha256"
	tls13SigRSAPSSName  = "rsa_pss_rsae_sha256"
)

// TestTLS13CertificateVerifyRejectsBadForms covers the fields around the
// signature: a message that is too short, a scheme the client never offered,
// a scheme forbidden in TLS 1.3, a missing certificate and a wrong key type.
func TestTLS13CertificateVerifyRejectsBadForms(t *testing.T) {
	transcript := []byte("a handshake transcript")
	input := tls13CertificateVerifyInput(transcript)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate an ed25519 key: %v", err)
	}
	cert := testLeafCertificate(t, public, private)
	valid := testCertificateVerifyMessage(tls13SigEd25519, ed25519.Sign(private, input))

	for _, tc := range []struct {
		name    string
		certs   [][]byte
		message []byte
		want    string
	}{
		{"no certificate", nil, valid, "without a certificate"},
		{"truncated message", [][]byte{cert}, []byte{tls13MsgCertVerify, 0, 0}, "truncated"},
		{"truncated scheme", [][]byte{cert}, []byte{tls13MsgCertVerify, 0, 0, 2, 0x08}, "truncated"},
		{"length disagrees", [][]byte{cert},
			testCertificateVerifyMessage(tls13SigEd25519, []byte{1, 2})[:9], "signature is"},
		{"scheme not offered", [][]byte{cert}, testCertificateVerifyMessage(0x0808, []byte{1}), "did not offer"},
		{"pkcs1 is forbidden in tls 1.3", [][]byte{cert},
			testCertificateVerifyMessage(tls13SigRSAPKCS1SHA256, []byte{1}), "not allowed"},
		{"wrong key type", [][]byte{cert},
			testCertificateVerifyMessage(tls13SigECDSAP256SHA256, []byte{1}), "was chosen but the leaf carries"},
		{"unparseable leaf", [][]byte{[]byte("not a certificate")}, valid, "parse the leaf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tls13VerifyCertificateVerify(tc.certs, tc.message, transcript)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestTLS13HandshakeRejectsAMismatchedCertificateVerify is the whole-handshake
// negative. crypto/tls signs the CertificateVerify with one private key while
// the certificate it sends carries another public key, so the signature is a
// genuine TLS 1.3 signature that simply does not belong to that certificate.
//
// The matched pair is the control: the same harness must succeed when the two
// keys agree, which proves the failure is the signature check and not the
// listener, the record layer or the certificate parsing.
func TestTLS13HandshakeRejectsAMismatchedCertificateVerify(t *testing.T) {
	first, _ := testCertificate(t)
	second, _ := testCertificate(t)

	for _, tc := range []struct {
		name       string
		serverCert tls.Certificate
		wantErr    bool
	}{
		{
			name: "matching key",
			serverCert: tls.Certificate{
				Certificate: first.Certificate, PrivateKey: first.PrivateKey,
			},
		},
		{
			name: "signature from another key",
			serverCert: tls.Certificate{
				Certificate: second.Certificate, PrivateKey: first.PrivateKey,
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{tc.serverCert},
				NextProtos:   []string{"h2"},
			})
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			// The server answers application data only if the handshake
			// completes. A client that rejects the signature must never get
			// as far as sending any.
			served := make(chan int, 1)
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						buf := make([]byte, 64)
						n, _ := c.Read(buf)
						served <- n
					}(conn)
				}
			}()

			raw, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer raw.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			peerChecked := false
			conn, err := tls13Client(ctx, raw, tls13ClientConfig{
				ServerName: "127.0.0.1",
				ALPN:       []string{"h2"},
				VerifyPeer: func([][]byte) error {
					peerChecked = true
					return nil
				},
			})
			if tc.wantErr {
				if err == nil {
					conn.Close()
					t.Fatal("the handshake accepted a signature made with a different key")
				}
				if !strings.Contains(err.Error(), "certificate verify") {
					t.Errorf("the failure was not the signature check: %v", err)
				}
				if peerChecked {
					t.Error("the peer check ran even though the signature failed")
				}
				if conn != nil {
					t.Error("a connection was returned, so application data could have been sent")
				}
				return
			}
			if err != nil {
				t.Fatalf("the control handshake failed: %v", err)
			}
			defer conn.Close()
			if !peerChecked {
				t.Error("the control handshake never reached the peer check")
			}
			payload := []byte("application data after a verified handshake")
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			select {
			case n := <-served:
				if n <= 0 {
					t.Error("the server saw no application data after the control handshake")
				}
			case <-ctx.Done():
				t.Error("the server never saw application data")
			}
		})
	}
}
