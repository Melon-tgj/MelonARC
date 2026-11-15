package outbound

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests are the negative half of the REALITY handshake. Each one runs a
// scripted TLS 1.3 server that gets one thing wrong, and asserts that no
// connection reaches the VLESS layer. The scripted peer is also used for the
// ordering checks: uTLS enforces the server authentication sequence itself, and
// these cases prove this adapter does not step around that.

// scriptedRealityPeer starts a REALITY server with a fresh static key and
// returns its address and the public key a client has to be configured with.
// A flight that asks for a plain leaf or a fixed certificate is served as it
// is: those cases are about a peer that is not a REALITY server.
func scriptedRealityPeer(t *testing.T, cfg peerFlight) (string, []byte, *peerEvents) {
	t.Helper()
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a static key: %v", err)
	}
	cfg.staticKey = static
	cfg.reality = !cfg.plainLeaf && len(cfg.plainCert) == 0
	addr, events := startTLSPeer(t, cfg)
	return addr, static.PublicKey().Bytes(), events
}

// scriptedDialer builds a REALITY-secured VLESS dialer for the peer at addr.
func scriptedDialer(t *testing.T, addr string, public []byte, shortID []byte) *VLESS {
	t.Helper()
	target, err := ParseTarget(addr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dialer, err := NewVLESS(VLESSOptions{
		Server: target.Host, Port: int(target.Port), UUID: testVLESSID,
		Reality: &RealityOptions{PublicKey: public, ShortID: shortID, ServerName: "localhost"},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewVLESS: %v", err)
	}
	return dialer
}

// dialFailure runs one dial that must fail, and asserts the two things every
// failure owes the caller: an error, and no usable connection.
func dialFailure(t *testing.T, dialer *VLESS, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "example.test:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("the dial succeeded, want a refused handshake")
	}
	if conn != nil {
		_ = conn.Close()
		t.Fatal("a connection was returned together with an error")
	}
	if want != "" && !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want it to mention %q", err, want)
	}
}

// TestScriptedRealityPeerCompletes is the control: the same scripted peer, with
// nothing wrong, must carry a tunnel. Without it a failure in any case below
// could just be a broken harness.
func TestScriptedRealityPeerCompletes(t *testing.T) {
	addr, public, events := scriptedRealityPeer(t, peerFlight{order: "ECVF", echo: true})
	dialer := scriptedDialer(t, addr, public, []byte{0x01})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "example.test:443")
	if err != nil {
		t.Fatalf("DialContext: %v (peer: %v)", err, events.err())
	}
	defer conn.Close()
	payload := []byte("scripted reality")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v (peer: %v)", err, events.err())
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatalf("read: %v (peer: %v)", err, events.err())
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("read %q, want %q", echoed, payload)
	}
	if !events.sawFinished() {
		t.Error("the peer never saw the client finished")
	}
}

// TestRealityRejectsMissingCertificateVerify covers the first negative class:
// the REALITY credential and the Finished are correct, but the server
// authentication segment has no CertificateVerify.
func TestRealityRejectsMissingCertificateVerify(t *testing.T) {
	addr, public, _ := scriptedRealityPeer(t, peerFlight{order: "ECF"})
	dialFailure(t, scriptedDialer(t, addr, public, nil), "reality")
}

// TestRealityRejectsDuplicatedCertificateVerify covers a repeated message in
// the authentication segment.
func TestRealityRejectsDuplicatedCertificateVerify(t *testing.T) {
	addr, public, _ := scriptedRealityPeer(t, peerFlight{order: "ECVVF"})
	dialFailure(t, scriptedDialer(t, addr, public, nil), "reality")
}

// TestRealityRejectsReorderedFlight covers the orders that put a message in
// front of the one that has to come first.
func TestRealityRejectsReorderedFlight(t *testing.T) {
	for _, order := range []string{"CEVF", "EFCV", "CVEF"} {
		t.Run(order, func(t *testing.T) {
			addr, public, _ := scriptedRealityPeer(t, peerFlight{order: order})
			dialFailure(t, scriptedDialer(t, addr, public, nil), "reality")
		})
	}
}

// TestRealityRejectsWrongSignature covers the other half of the first class: a
// genuine TLS 1.3 signature that was made with a key the certificate does not
// carry.
func TestRealityRejectsWrongSignature(t *testing.T) {
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	addr, public, _ := scriptedRealityPeer(t, peerFlight{order: "ECVF", signKey: other})
	dialFailure(t, scriptedDialer(t, addr, public, nil), "reality")
}

// TestRealityRejectsUnusableSignatureScheme covers a scheme the client never
// offered and one TLS 1.3 forbids in a CertificateVerify.
func TestRealityRejectsUnusableSignatureScheme(t *testing.T) {
	for _, scheme := range []uint16{peerSigECDSAP256SHA256, peerSigRSAPKCS1SHA256, 0x0808} {
		t.Run(strconv.Itoa(int(scheme)), func(t *testing.T) {
			addr, public, _ := scriptedRealityPeer(t, peerFlight{order: "ECVF", scheme: scheme})
			dialFailure(t, scriptedDialer(t, addr, public, nil), "reality")
		})
	}
}

// TestRealityRejectsAnotherTranscript covers a signature that is valid for a
// handshake the client never took part in.
func TestRealityRejectsAnotherTranscript(t *testing.T) {
	addr, public, _ := scriptedRealityPeer(t, peerFlight{order: "ECVF", signAnotherTranscript: true})
	dialFailure(t, scriptedDialer(t, addr, public, nil), "reality")
}

// TestRealityRejectsWrongCredential covers the first half of the second class:
// a correct TLS signature over the real transcript, sealed with another
// authentication key.
func TestRealityRejectsWrongCredential(t *testing.T) {
	addr, public, _ := scriptedRealityPeer(t, peerFlight{order: "ECVF", wrongCredential: true})
	dialFailure(t, scriptedDialer(t, addr, public, nil), "authentication key")
}

// TestRealityRejectsATrustedWebsiteCertificate covers the second half of the
// second class: the peer presents an ordinary certificate that a normal TLS
// client would accept. The control at the top proves the chain really is valid,
// so the refusal below can only come from the REALITY check.
func TestRealityRejectsATrustedWebsiteCertificate(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a ca key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "melonarc test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create the ca: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse the ca: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create the leaf: %v", err)
	}
	// The peer has to sign its CertificateVerify with the leaf key, which is
	// what makes it a genuine TLS server rather than a broken one.
	flight := peerFlight{
		order:     "ECVF",
		plainCert: leafDER,
		signKey:   leafKey,
		scheme:    peerSigECDSAP256SHA256,
	}

	// Control: this chain is genuinely trustworthy, so a normal client accepts
	// it. That is what makes the REALITY refusal meaningful.
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	controlAddr, _ := startTLSPeer(t, flight)
	raw, err := net.Dial("tcp", controlAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := tls.Client(raw, &tls.Config{
		ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13,
	}).Handshake(); err != nil {
		t.Fatalf("the control chain was rejected: %v", err)
	}
	_ = raw.Close()

	// The same certificate, reached through a REALITY dialer, must not carry a
	// tunnel: a verifying chain is the imitated site, not the server.
	addr, public, _ := scriptedRealityPeer(t, flight)
	dialFailure(t, scriptedDialer(t, addr, public, nil), "the server certificate")
}

// TestRealityRejectsBadFinished covers the third class: a correct credential
// and a correct signature, but a server Finished that does not verify.
func TestRealityRejectsBadFinished(t *testing.T) {
	addr, public, _ := scriptedRealityPeer(t, peerFlight{order: "ECVF", badFinished: true})
	dialFailure(t, scriptedDialer(t, addr, public, nil), "reality")
}

// peerPostFlightMax is the most a refusing client can write after the server's
// authentication segment: one compatibility change_cipher_spec (a five-byte
// record header and one byte) and one encrypted alert (the same five bytes, the
// two-byte alert, the inner content type and the tag, twenty-four in all).
//
// That budget cannot hold a tunnel preface even in principle: the client
// Finished alone is a four-byte header, thirty-two bytes of verify data and a
// sixteen-byte tag, so it is already twice this size, and the VLESS request may
// only follow it.
const peerPostFlightMax = (5 + 1) + (5 + 2 + 1 + 16)

// TestRealityFailureWritesNoVLESSRequest pins the write boundary: a handshake
// that fails must not put a single byte of the VLESS header, the uuid or a
// payload on the wire. The measurement is the peer's own byte counter, taken
// after the connection ended, so it does not depend on timing.
func TestRealityFailureWritesNoVLESSRequest(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  peerFlight
	}{
		{"plain certificate", peerFlight{order: "ECVF", plainLeaf: true}},
		{"wrong credential", peerFlight{order: "ECVF", wrongCredential: true}},
		{"missing certificate verify", peerFlight{order: "ECF"}},
		{"bad finished", peerFlight{order: "ECVF", badFinished: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, public, events := scriptedRealityPeer(t, tc.cfg)
			dialFailure(t, scriptedDialer(t, addr, public, nil), "")
			events.wait(t)
			state := events.snapshot()
			if state.finished {
				t.Fatal("the peer verified a client finished on a handshake that had to be refused")
			}
			if len(state.appData) != 0 {
				t.Fatalf("the peer received application data: %q", state.appData)
			}
			if state.afterFlight > peerPostFlightMax {
				t.Fatalf("the client wrote %d bytes after the server flight, which is more than a compatibility record and an alert (%d): % x",
					state.afterFlight, peerPostFlightMax, state.afterBytes)
			}
		})
	}
}

// TestRealityDeliversOnlyAfterClientFinished pins the successful boundary: the
// VLESS request must be in a record that starts after the client Finished was
// sent, and the dialer must not return before that.
func TestRealityDeliversOnlyAfterClientFinished(t *testing.T) {
	addr, public, events := scriptedRealityPeer(t, peerFlight{order: "ECVF", echo: true})
	conn, err := scriptedDialer(t, addr, public, nil).DialContext(context.Background(), "example.test:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn, []byte("after the finished"))
	// The peer keeps echoing until the connection ends, so it has to be closed
	// before its counters can be read.
	_ = conn.Close()
	events.wait(t)
	state := events.snapshot()
	if !state.finished {
		t.Fatal("the peer never verified the client finished")
	}
	if state.appAt == 0 {
		t.Fatal("the peer never received the VLESS request")
	}
	if state.appAt <= state.finishedAt {
		t.Fatalf("the request ended at offset %d, at or before the finished at %d", state.appAt, state.finishedAt)
	}
}

// TestRealityHonoursTheConfiguredALPN proves the adapter does not silently send
// the template's ALPN list when the configuration names another one: the
// assertion is on the list the peer read off the wire.
func TestRealityHonoursTheConfiguredALPN(t *testing.T) {
	addr, public, events := scriptedRealityPeer(t, peerFlight{order: "ECVF"})
	target, err := ParseTarget(addr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dialer, err := NewVLESS(VLESSOptions{
		Server: target.Host, Port: int(target.Port), UUID: testVLESSID,
		TLS:     TLSOptions{ALPN: []string{"h2"}},
		Reality: &RealityOptions{PublicKey: public, ServerName: "localhost"},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewVLESS: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "example.test:443")
	if err != nil {
		t.Fatalf("DialContext: %v (peer: %v)", err, events.err())
	}
	_ = conn.Close()
	events.wait(t)
	state := events.snapshot()
	if state.hello == nil {
		t.Fatal("the peer never read a client hello")
	}
	if got := state.hello.alpn; len(got) != 1 || got[0] != "h2" {
		t.Fatalf("the hello offered alpn %v, want [h2]", got)
	}
}

// TestRealityTemplateCarriesEd25519 pins the one adjustment made to the
// template: the credential is an Ed25519 certificate, so the hello has to offer
// that scheme even though the pinned templates do not.
func TestRealityTemplateCarriesEd25519(t *testing.T) {
	addr, public, events := scriptedRealityPeer(t, peerFlight{order: "ECVF"})
	dialer := scriptedDialer(t, addr, public, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "example.test:443")
	if err != nil {
		t.Fatalf("DialContext: %v (peer: %v)", err, events.err())
	}
	_ = conn.Close()
	events.wait(t)
	state := events.snapshot()
	if state.hello == nil {
		t.Fatal("the peer never read a client hello")
	}
	if !slicesContainsUint16(state.hello.sigAlgs, peerSigEd25519) {
		t.Fatalf("the hello offered signature algorithms %#04x, without ed25519", state.hello.sigAlgs)
	}
}
