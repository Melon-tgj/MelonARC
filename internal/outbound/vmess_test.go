package outbound

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

const (
	testVMessUUID      = "b831381d-6324-4d53-ad4f-8cda48b30811"
	testVMessOtherUUID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
)

func testVMessCmdKey(t *testing.T, uuid string) []byte {
	t.Helper()
	id, err := parseVMessUUID(uuid)
	if err != nil {
		t.Fatalf("parse uuid: %v", err)
	}
	h := md5.New()
	_, _ = h.Write(id[:])
	_, _ = h.Write([]byte(vmessCmdKeySuffix))
	return h.Sum(nil)
}

// startTestVMess is a self-written AEAD VMess server. It opens the AEAD
// header, answers with the AEAD response header and then echoes body chunks,
// either as a stream (TCP command) or one datagram per chunk (UDP command).
func startTestVMess(t *testing.T, uuid string, useTLS bool) (string, *x509.CertPool) {
	t.Helper()
	cmdKey := testVMessCmdKey(t, uuid)
	var ln net.Listener
	var err error
	var pool *x509.CertPool
	if useTLS {
		cert, roots := testCertificate(t)
		pool = roots
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		})
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(testServerDeadline))
				serveTestVMess(c, cmdKey)
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	return ln.Addr().String(), pool
}

func serveTestVMess(conn net.Conn, cmdKey []byte) {
	header, err := vmessOpenHeader(cmdKey, conn)
	if err != nil {
		return
	}
	session, target, command, err := vmessParseRequestHeader(header)
	if err != nil {
		return
	}
	if err := vmessWriteResponseHeader(conn, session); err != nil {
		return
	}
	requestAEAD, err := session.bodyAEAD(session.requestKey[:])
	if err != nil {
		return
	}
	responseAEAD, err := session.bodyAEAD(session.responseKey[:])
	if err != nil {
		return
	}
	stream := &vmessChunkConn{
		conn: conn, remote: target,
		writeAEAD: responseAEAD, readAEAD: requestAEAD,
		writeIV: session.responseIV, readIV: session.requestIV,
		datagrams: command == vmessCommandUDP,
	}
	if command == vmessCommandTCP {
		_, _ = io.Copy(stream, stream)
		return
	}
	buf := make([]byte, vmessMaxChunk)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			return
		}
		_, off, err := decodeVMessAddress(buf[:n])
		if err != nil {
			return
		}
		reply := appendVMessAddress(nil, target)
		reply = append(reply, buf[off:n]...)
		if _, err := stream.Write(reply); err != nil {
			return
		}
	}
}

func mustVMess(t *testing.T, address, uuid, security string, tlsOpts TLSOptions) *VMess {
	t.Helper()
	target, err := ParseTarget(address)
	if err != nil {
		t.Fatalf("parse %q: %v", address, err)
	}
	d, err := NewVMess(VMessOptions{
		Server: target.Host, Port: int(target.Port), UUID: uuid,
		Security: security, TLS: tlsOpts, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewVMess: %v", err)
	}
	return d
}

func TestVMessTCPRoundTrip(t *testing.T) {
	echo := startTCPEcho(t)
	for _, useTLS := range []bool{false, true} {
		for _, security := range []string{"aes-128-gcm", "chacha20-poly1305"} {
			name := "plain/" + security
			if useTLS {
				name = "tls/" + security
			}
			t.Run(name, func(t *testing.T) {
				server, pool := startTestVMess(t, testVMessUUID, useTLS)
				tlsOpts := TLSOptions{}
				if useTLS {
					tlsOpts = TLSOptions{Enabled: true, Config: &tls.Config{RootCAs: pool}}
				}
				d := mustVMess(t, server, testVMessUUID, security, tlsOpts)
				conn := dialThrough(t, d, echo)
				payload := bytes.Repeat([]byte("vmess-aead-stream "), 900)
				if _, err := conn.Write(payload); err != nil {
					t.Fatalf("write: %v", err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, got); err != nil {
					t.Fatalf("read echo: %v", err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatal("echo payload differs from what was written")
				}
			})
		}
	}
}

func TestVMessUDPRoundTrip(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "plain"
		if useTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			server, pool := startTestVMess(t, testVMessUUID, useTLS)
			tlsOpts := TLSOptions{}
			if useTLS {
				tlsOpts = TLSOptions{Enabled: true, Config: &tls.Config{RootCAs: pool}}
			}
			d := mustVMess(t, server, testVMessUUID, "", tlsOpts)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pc, err := d.DialPacket(ctx, "example.com:5353")
			if err != nil {
				t.Fatalf("DialPacket: %v", err)
			}
			defer pc.Close()
			_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("vmess datagram echo")
			if _, err := pc.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 512)
			n, err := pc.Read(buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(buf[:n], payload) {
				t.Fatalf("echo = %q, want %q", buf[:n], payload)
			}
		})
	}
}

func TestVMessWrongUUIDFails(t *testing.T) {
	echo := startTCPEcho(t)
	server, _ := startTestVMess(t, testVMessUUID, false)
	d := mustVMess(t, server, testVMessOtherUUID, "", TLSOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := d.DialContext(ctx, echo); err == nil {
		t.Fatal("a wrong account identifier was accepted")
	}
}

func TestVMessRejectsBadConfiguration(t *testing.T) {
	if _, err := NewVMess(VMessOptions{Server: "p.example", Port: 443, UUID: "not-a-uuid"}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("bad uuid error = %v, want ErrInvalidOption", err)
	}
	if _, err := NewVMess(VMessOptions{Server: "p.example", Port: 443,
		UUID: testVMessUUID, Security: "bogus-cipher"}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("bad security error = %v, want ErrInvalidOption", err)
	}
	if _, err := New(Spec{Type: "vmess", Server: "p.example", Port: 443,
		Args: []string{"p.example", "443", "uuid=" + testVMessUUID, "tls=true", "sni=proxy.example"}}); err != nil {
		t.Fatalf("tls form: %v", err)
	}
	if _, err := New(Spec{Type: "vmess", Server: "p.example", Port: 443,
		Args: []string{"p.example", "443", "uuid=" + testVMessUUID, "security=nope"}}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("bad security option error = %v, want ErrInvalidOption", err)
	}
}

// The public VMess definition does not publish numeric KDF vectors, so these
// checks pin down the structural properties the wire format depends on:
// determinism, domain separation, the auth id checksum and tamper detection.
func TestVMessAEADPrimitives(t *testing.T) {
	cmdKey := testVMessCmdKey(t, testVMessUUID)
	a := vmessKDF(cmdKey, kdfHeaderKey, "one", "two")
	b := vmessKDF(cmdKey, kdfHeaderKey, "one", "two")
	if !bytes.Equal(a, b) {
		t.Fatal("KDF is not deterministic")
	}
	if bytes.Equal(a, vmessKDF(cmdKey, kdfHeaderIV, "one", "two")) ||
		bytes.Equal(a, vmessKDF(cmdKey, kdfHeaderKey, "one", "three")) {
		t.Fatal("KDF does not separate its path components")
	}
	if len(a) != 32 || len(vmessKDF16(cmdKey, kdfHeaderKey)) != 16 {
		t.Fatal("KDF output lengths are wrong")
	}

	authID, err := vmessAuthID(cmdKey)
	if err != nil {
		t.Fatalf("vmessAuthID: %v", err)
	}
	if _, err := vmessDecodeAuthID(cmdKey, authID[:]); err != nil {
		t.Fatalf("auth id did not decode: %v", err)
	}
	otherKey := testVMessCmdKey(t, testVMessOtherUUID)
	if _, err := vmessDecodeAuthID(otherKey, authID[:]); err == nil {
		t.Fatal("auth id decoded under a different command key")
	}
	tampered := append([]byte(nil), authID[:]...)
	tampered[3] ^= 0x40
	if _, err := vmessDecodeAuthID(cmdKey, tampered); err == nil {
		t.Fatal("a tampered auth id was accepted")
	}

	header, err := vmessRequestHeader(&vmessSession{security: vmessSecurityAESGCM},
		Target{Host: "example.com", Port: 443}, vmessCommandTCP)
	if err != nil {
		t.Fatalf("request header: %v", err)
	}
	sealed, err := vmessSealHeader(cmdKey, header)
	if err != nil {
		t.Fatalf("seal header: %v", err)
	}
	opened, err := vmessOpenHeader(cmdKey, bytes.NewReader(sealed))
	if err != nil {
		t.Fatalf("open header: %v", err)
	}
	if !bytes.Equal(opened, header) {
		t.Fatal("opened header differs from the sealed one")
	}
	if _, err := vmessOpenHeader(otherKey, bytes.NewReader(sealed)); err == nil {
		t.Fatal("header opened under a different command key")
	}
	session, target, command, err := vmessParseRequestHeader(opened)
	if err != nil {
		t.Fatalf("parse request header: %v", err)
	}
	if target.Host != "example.com" || target.Port != 443 || command != vmessCommandTCP {
		t.Fatalf("parsed request = %v / %d / %d", target, command, session.security)
	}
}
