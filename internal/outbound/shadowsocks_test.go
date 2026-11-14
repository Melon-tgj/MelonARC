package outbound

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// ssTestMethods is the full cipher table phase 9 promises.
var ssTestMethods = []string{
	"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}

func ssTestCredentials(t *testing.T, method string) (cipherInfo, []byte, string) {
	t.Helper()
	info, err := cipherInfoFor(method)
	if err != nil {
		t.Fatalf("cipherInfoFor(%q): %v", method, err)
	}
	secret := "phase9-legacy-secret"
	if info.version22 {
		secret = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5A}, info.keyLen))
	}
	master, err := info.masterKey(secret)
	if err != nil {
		t.Fatalf("masterKey: %v", err)
	}
	return info, master, secret
}

// startTestShadowsocksTCP is a self-written Shadowsocks server. It implements
// the legacy AEAD request format and the 2022 typed request/response headers,
// then echoes every data frame back to the client.
func startTestShadowsocksTCP(t *testing.T, info cipherInfo, master []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				serveTestShadowsocksTCP(c, info, master)
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
	return ln.Addr().String()
}

func serveTestShadowsocksTCP(conn net.Conn, info cipherInfo, master []byte) {
	salt := make([]byte, info.saltLen)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return
	}
	aead, err := info.sessionKey(master, salt)
	if err != nil {
		return
	}
	request := newChunkStream(conn, aead, info.maxPayload)
	if !info.version22 {
		if _, err := request.readFrame(); err != nil { // target address
			return
		}
		// The answer is keyed by a salt of its own: the server direction never
		// shares the request's subkey.
		serverSalt, err := randomBytes(info.saltLen)
		if err != nil {
			return
		}
		if _, err := conn.Write(serverSalt); err != nil {
			return
		}
		responseAEAD, err := info.sessionKey(master, serverSalt)
		if err != nil {
			return
		}
		_, _ = io.Copy(newChunkStream(conn, responseAEAD, info.maxPayload), request)
		return
	}
	fixed, err := request.readChunk(11)
	if err != nil || fixed[0] != 0 {
		return
	}
	varHeader, err := request.readChunk(int(binary.BigEndian.Uint16(fixed[9:11])))
	if err != nil {
		return
	}
	if _, _, err := decodeAddress(varHeader); err != nil {
		return
	}
	serverSalt, err := randomBytes(info.saltLen)
	if err != nil {
		return
	}
	// The first payload travels inside the header chunk: the header carries how
	// long it is, so no length frame precedes it. A reference server answers
	// this way, and only once it has something to say, which is why the client
	// must not wait for the header inside DialContext.
	first, err := request.readFrame()
	if err != nil {
		return
	}
	if _, err := conn.Write(serverSalt); err != nil {
		return
	}
	responseAEAD, err := info.sessionKey(master, serverSalt)
	if err != nil {
		return
	}
	response := newChunkStream(conn, responseAEAD, info.maxPayload)
	header := make([]byte, 0, 11+info.saltLen)
	header = append(header, 1)
	header = binary.BigEndian.AppendUint64(header, uint64(time.Now().Unix()))
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint16(header, uint16(len(first)))
	if err := response.writeChunk(header); err != nil {
		return
	}
	if err := response.writeChunk(first); err != nil {
		return
	}
	for {
		payload, err := request.readFrame()
		if err != nil || len(payload) == 0 {
			return
		}
		if err := response.writeFrame(payload); err != nil {
			return
		}
	}
}

func mustShadowsocks(t *testing.T, address, method, secret string) *Shadowsocks {
	t.Helper()
	target, err := ParseTarget(address)
	if err != nil {
		t.Fatalf("parse %q: %v", address, err)
	}
	d, err := NewShadowsocks(ShadowsocksOptions{
		Server: target.Host, Port: int(target.Port),
		Method: method, Password: secret, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewShadowsocks: %v", err)
	}
	return d
}

func TestShadowsocksTCPRoundTrip(t *testing.T) {
	echo := startTCPEcho(t)
	for _, method := range ssTestMethods {
		t.Run(method, func(t *testing.T) {
			info, master, secret := ssTestCredentials(t, method)
			server := startTestShadowsocksTCP(t, info, master)
			d := mustShadowsocks(t, server, method, secret)
			conn := dialThrough(t, d, echo)
			// Larger than one chunk so the frame loop is exercised.
			payload := bytes.Repeat([]byte("shadowsocks-round-trip "), 4000)
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

func TestShadowsocksWrongPasswordFails(t *testing.T) {
	echo := startTCPEcho(t)
	for _, method := range ssTestMethods {
		t.Run(method, func(t *testing.T) {
			info, master, _ := ssTestCredentials(t, method)
			server := startTestShadowsocksTCP(t, info, master)
			wrong := "definitely-not-the-secret"
			if info.version22 {
				wrong = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, info.keyLen))
			}
			d := mustShadowsocks(t, server, method, wrong)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := d.DialContext(ctx, echo)
			if err == nil {
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, err = conn.Write([]byte("probe"))
				if err == nil {
					var one [1]byte
					_, err = io.ReadFull(conn, one[:])
				}
				_ = conn.Close()
			}
			if err == nil {
				t.Fatal("a wrong password was accepted")
			}
		})
	}
}

func TestShadowsocksRejectsBadConfiguration(t *testing.T) {
	if _, err := NewShadowsocks(ShadowsocksOptions{
		Server: "127.0.0.1", Port: 8388, Method: "aes-999-gcm", Password: "x",
	}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("unsupported cipher error = %v, want ErrInvalidOption", err)
	}
	if _, err := NewShadowsocks(ShadowsocksOptions{
		Server: "127.0.0.1", Port: 8388, Method: "2022-blake3-aes-128-gcm",
		Password: base64.StdEncoding.EncodeToString(make([]byte, 8)),
	}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("short pre-shared key error = %v, want ErrInvalidOption", err)
	}
	positional, err := New(Spec{Type: "ss", Server: "p.example", Port: 8388,
		Args: []string{"p.example", "8388", "aes-128-gcm", "positional-secret"}})
	if err != nil {
		t.Fatalf("positional form: %v", err)
	}
	if _, ok := positional.(*Shadowsocks); !ok {
		t.Fatalf("positional form returned %T", positional)
	}
	// A secret with "=" is unambiguous when written with its key.
	keyed, err := New(Spec{Type: "ss", Server: "p.example", Port: 8388,
		Args: []string{"p.example", "8388", "method=aes-128-gcm", "password=pass=word"}})
	if err != nil {
		t.Fatalf("keyed form with '=' in the secret: %v", err)
	}
	if ss, ok := keyed.(*Shadowsocks); !ok || !bytes.Equal(ss.master, evpBytesToKey([]byte("pass=word"), 16)) {
		t.Fatal("keyed form did not keep the whole secret")
	}
	if _, err := New(Spec{Type: "ss", Server: "p.example", Port: 8388,
		Args: []string{"p.example", "8388", "method=aes-128-gcm"}}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("missing password error = %v, want ErrInvalidOption", err)
	}
	if _, err := New(Spec{Type: "ss", Server: "p.example", Port: 8388,
		Args: []string{"p.example", "8388", "aes-128-gcm", "secret", "sni=example.com"}}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("unknown option error = %v, want ErrInvalidOption", err)
	}
}

// ssUDPHandler answers one encrypted datagram with an encrypted echo, using
// the same wire rules each cipher family defines for UDP.
func ssUDPHandler(info cipherInfo, master []byte) func([]byte) []byte {
	return func(packet []byte) []byte {
		if !info.version22 {
			if len(packet) < info.saltLen+16 {
				return nil
			}
			aead, err := info.sessionKey(master, packet[:info.saltLen])
			if err != nil {
				return nil
			}
			body, err := aead.Open(nil, make([]byte, 12), packet[info.saltLen:], nil)
			if err != nil {
				return nil
			}
			if _, _, err := decodeAddress(body); err != nil {
				return nil
			}
			salt, err := randomBytes(info.saltLen)
			if err != nil {
				return nil
			}
			replyAEAD, err := info.sessionKey(master, salt)
			if err != nil {
				return nil
			}
			return append(salt, replyAEAD.Seal(nil, make([]byte, 12), body, nil)...)
		}
		if !info.chacha22 {
			return ssUDPReply2022AES(packet, info, master)
		}
		return ssUDPReply2022ChaCha(packet, info, master)
	}
}

func ssUDPReply2022AES(packet []byte, info cipherInfo, master []byte) []byte {
	if len(packet) < 32 {
		return nil
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil
	}
	separate := make([]byte, 16)
	block.Decrypt(separate, packet[:16])
	clientSession := append([]byte(nil), separate[:8]...)
	key := blake3DeriveKey(ss2022Context, append(append([]byte(nil), master...), separate[:8]...))
	aead, err := info.newAEAD(key[:info.keyLen])
	if err != nil {
		return nil
	}
	body, err := aead.Open(nil, separate[4:16], packet[16:], nil)
	if err != nil || len(body) < 11 {
		return nil
	}
	padding := int(binary.BigEndian.Uint16(body[9:11]))
	off := 11 + padding
	if off > len(body) {
		return nil
	}
	_, n, err := decodeAddress(body[off:])
	if err != nil {
		return nil
	}
	address := body[off : off+n]
	payload := body[off+n:]

	replySeparate := make([]byte, 16)
	fresh, err := randomBytes(8)
	if err != nil {
		return nil
	}
	copy(replySeparate, fresh)
	encrypted := make([]byte, 16)
	block.Encrypt(encrypted, replySeparate)
	replyKey := blake3DeriveKey(ss2022Context, append(append([]byte(nil), master...), replySeparate[:8]...))
	replyAEAD, err := info.newAEAD(replyKey[:info.keyLen])
	if err != nil {
		return nil
	}
	response := ss2022PacketBody(1, uint64(time.Now().Unix()), clientSession, address, payload)
	return append(encrypted, replyAEAD.Seal(nil, replySeparate[4:16], response, nil)...)
}

func ssUDPReply2022ChaCha(packet []byte, info cipherInfo, master []byte) []byte {
	if len(packet) < 24+16 {
		return nil
	}
	aead, err := chacha20poly1305.NewX(master)
	if err != nil {
		return nil
	}
	body, err := aead.Open(nil, packet[:24], packet[24:], nil)
	if err != nil || len(body) < 16+11 {
		return nil
	}
	clientSession := append([]byte(nil), body[:8]...)
	padding := int(binary.BigEndian.Uint16(body[16+9 : 16+11]))
	off := 16 + 11 + padding
	if off > len(body) {
		return nil
	}
	_, n, err := decodeAddress(body[off:])
	if err != nil {
		return nil
	}
	address := body[off : off+n]
	payload := body[off+n:]

	header := make([]byte, 0, 16+11+len(address)+len(payload))
	fresh, err := randomBytes(8)
	if err != nil {
		return nil
	}
	header = append(header, fresh...)
	header = binary.BigEndian.AppendUint64(header, 0)
	header = append(header, 1)
	header = binary.BigEndian.AppendUint64(header, uint64(time.Now().Unix()))
	header = append(header, clientSession...)
	header = binary.BigEndian.AppendUint16(header, 0)
	header = append(header, address...)
	header = append(header, payload...)
	nonce, err := randomBytes(24)
	if err != nil {
		return nil
	}
	return append(nonce, aead.Seal(nil, nonce, header, nil)...)
}

func TestShadowsocksUDPRoundTrip(t *testing.T) {
	for _, method := range ssTestMethods {
		t.Run(method, func(t *testing.T) {
			info, master, secret := ssTestCredentials(t, method)
			server := startConnectedUDPEcho(t, ssUDPHandler(info, master))
			d := mustShadowsocks(t, server, method, secret)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pc, err := d.DialPacket(ctx, "127.0.0.1:5353")
			if err != nil {
				t.Fatalf("DialPacket: %v", err)
			}
			defer pc.Close()
			_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("shadowsocks datagram echo")
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

// TestShadowsocks2022RejectsTamperedResponseSalt checks that the client binds
// the response header to its own request salt rather than trusting any header.
func TestShadowsocks2022RejectsTamperedResponseSalt(t *testing.T) {
	method := "2022-blake3-aes-128-gcm"
	info, master, secret := ssTestCredentials(t, method)
	address := startScriptedServer(t, func(conn net.Conn) {
		salt := make([]byte, info.saltLen)
		if _, err := io.ReadFull(conn, salt); err != nil {
			return
		}
		aead, _ := info.sessionKey(master, salt)
		request := newChunkStream(conn, aead, info.maxPayload)
		fixed, err := request.readChunk(11)
		if err != nil {
			return
		}
		if _, err := request.readChunk(int(binary.BigEndian.Uint16(fixed[9:11]))); err != nil {
			return
		}
		other, _ := randomBytes(info.saltLen)
		_, _ = conn.Write(other)
		responseAEAD, _ := info.sessionKey(master, other)
		response := newChunkStream(conn, responseAEAD, info.maxPayload)
		header := make([]byte, 0, 11+info.saltLen)
		header = append(header, 1)
		header = binary.BigEndian.AppendUint64(header, uint64(time.Now().Unix()))
		header = append(header, bytes.Repeat([]byte{0xEE}, info.saltLen)...)
		header = binary.BigEndian.AppendUint16(header, 0)
		_ = response.writeChunk(header)
	})
	d := mustShadowsocks(t, address, method, secret)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, startTCPEcho(t))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// The response header is only read when the first payload arrives, so the
	// mismatch surfaces on the read rather than at dial time.
	buf := make([]byte, 8)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("a response header naming a different request salt was accepted")
	}
}
