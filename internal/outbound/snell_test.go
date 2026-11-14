package outbound

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

const testSnellPSK = "phase9-snell-psk"

type testSnellServer struct {
	addr     string
	mu       sync.Mutex
	commands []byte
}

func (s *testSnellServer) record(command byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, command)
}

func (s *testSnellServer) recorded() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.commands...)
}

// startTestSnell is a self-written Snell v4/v5 server. It uses the same frame
// codec as the outbound, answers READY and echoes either the stream or one
// framed datagram at a time.
func startTestSnell(t *testing.T, psk string, version int, cipherName string) *testSnellServer {
	t.Helper()
	definition, err := NewSnell(SnellOptions{
		Server: "127.0.0.1", Port: 1080, PSK: psk,
		Version: version, Cipher: cipherName,
	})
	if err != nil {
		t.Fatalf("server definition: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testSnellServer{addr: ln.Addr().String()}
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
				serveTestSnell(c, definition, s)
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
	return s
}

func serveTestSnell(conn net.Conn, definition *Snell, s *testSnellServer) {
	sc := newSnellConn(conn, definition)
	var head [3]byte
	if _, err := io.ReadFull(sc, head[:]); err != nil {
		return
	}
	if head[0] != snellHeaderVersion || head[2] != 0 {
		return
	}
	s.record(head[1])
	command := head[1]
	var target Target
	if command == snellCommandUDP {
		target = Target{Host: "127.0.0.1", Port: 0}
	} else {
		var length [1]byte
		if _, err := io.ReadFull(sc, length[:]); err != nil {
			return
		}
		host := make([]byte, int(length[0]))
		if _, err := io.ReadFull(sc, host); err != nil {
			return
		}
		var port [2]byte
		if _, err := io.ReadFull(sc, port[:]); err != nil {
			return
		}
		target = Target{Host: string(host), Port: binary.BigEndian.Uint16(port[:])}
	}
	if _, err := sc.Write([]byte{snellResponseTunnel}); err != nil {
		return
	}
	if command == snellCommandConnect || command == snellCommandConnectV2 {
		_, _ = io.Copy(sc, sc)
		return
	}
	for {
		frame, err := sc.takePacketFrame()
		if err != nil {
			return
		}
		_, payload, err := parseSnellUDPRequest(frame)
		if err != nil {
			return
		}
		reply, err := snellUDPResponse(target, payload)
		if err != nil {
			return
		}
		if err := sc.writePacketFrame(reply); err != nil {
			return
		}
	}
}

func mustSnell(t *testing.T, address, psk string, version int, cipherName string) *Snell {
	t.Helper()
	target, err := ParseTarget(address)
	if err != nil {
		t.Fatalf("parse %q: %v", address, err)
	}
	d, err := NewSnell(SnellOptions{
		Server: target.Host, Port: int(target.Port), PSK: psk,
		Version: version, Cipher: cipherName, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSnell: %v", err)
	}
	return d
}

func TestSnellTCPRoundTrip(t *testing.T) {
	echo := startTCPEcho(t)
	for _, version := range []int{4, 5} {
		for _, cipherName := range []string{"aes-128-gcm", "chacha20-ietf-poly1305"} {
			name := "v" + string(rune('0'+version)) + "/" + cipherName
			t.Run(name, func(t *testing.T) {
				server := startTestSnell(t, testSnellPSK, version, cipherName)
				d := mustSnell(t, server.addr, testSnellPSK, version, cipherName)
				conn := dialThrough(t, d, echo)
				payload := bytes.Repeat([]byte("snell framed stream "), 1200)
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
				wantCommand := byte(snellCommandConnect)
				if version == 5 {
					wantCommand = snellCommandConnectV2
				}
				seen := server.recorded()
				if len(seen) == 0 || seen[0] != wantCommand {
					t.Fatalf("server saw commands %v, want %#x for version %d", seen, wantCommand, version)
				}
			})
		}
	}
}

func TestSnellUDPRoundTrip(t *testing.T) {
	for _, version := range []int{4, 5} {
		t.Run("v"+string(rune('0'+version)), func(t *testing.T) {
			server := startTestSnell(t, testSnellPSK, version, "aes-128-gcm")
			d := mustSnell(t, server.addr, testSnellPSK, version, "aes-128-gcm")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pc, err := d.DialPacket(ctx, "127.0.0.1:5353")
			if err != nil {
				t.Fatalf("DialPacket: %v", err)
			}
			defer pc.Close()
			_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("snell datagram echo")
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

func TestSnellWrongPSKAndBadCipherFail(t *testing.T) {
	echo := startTCPEcho(t)
	server := startTestSnell(t, testSnellPSK, 5, "aes-128-gcm")
	d := mustSnell(t, server.addr, "a-different-psk", 5, "aes-128-gcm")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := d.DialContext(ctx, echo); err == nil {
		t.Fatal("a wrong pre-shared key was accepted")
	}
	if _, err := NewSnell(SnellOptions{Server: "p.example", Port: 1080,
		PSK: testSnellPSK, Version: 5, Cipher: "bogus-cipher"}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("bad cipher error = %v, want ErrInvalidOption", err)
	}
	if _, err := NewSnell(SnellOptions{Server: "p.example", Port: 1080,
		PSK: testSnellPSK, Version: 3}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("bad version error = %v, want ErrInvalidOption", err)
	}
	positional, err := New(Spec{Type: "snell", Server: "p.example", Port: 1080,
		Args: []string{"p.example", "1080", "secret", "version=5", "cipher=aes-128-gcm"}})
	if err != nil {
		t.Fatalf("positional form: %v", err)
	}
	if _, ok := positional.(*Snell); !ok {
		t.Fatalf("positional form returned %T", positional)
	}
}

// TestSnellVersionFraming checks the raw first frame on the wire: v5 adds the
// initial padding block and uses the smaller first record, v4 sends neither.
func TestSnellVersionFraming(t *testing.T) {
	for _, version := range []int{4, 5} {
		t.Run("v"+string(rune('0'+version)), func(t *testing.T) {
			definition, err := NewSnell(SnellOptions{
				Server: "127.0.0.1", Port: 1080, PSK: testSnellPSK, Version: version,
			})
			if err != nil {
				t.Fatalf("definition: %v", err)
			}
			client, wire := net.Pipe()
			defer wire.Close()
			sc := newSnellConn(client, definition)
			written := make(chan error, 1)
			go func() {
				_, err := sc.Write([]byte("first record"))
				_ = client.Close()
				written <- err
			}()

			_ = wire.SetDeadline(time.Now().Add(5 * time.Second))
			salt := make([]byte, snellSaltSize)
			if _, err := io.ReadFull(wire, salt); err != nil {
				t.Fatalf("read salt: %v", err)
			}
			headerCipher := make([]byte, snellHeaderCipherSize)
			if _, err := io.ReadFull(wire, headerCipher); err != nil {
				t.Fatalf("read header: %v", err)
			}
			key := snellKDF(definition.psk, salt, definition.keyLen)
			aead, err := definition.newAEAD(key)
			if err != nil {
				t.Fatalf("aead: %v", err)
			}
			header, err := aead.Open(nil, make([]byte, 12), headerCipher, nil)
			if err != nil {
				t.Fatalf("open header: %v", err)
			}
			if header[0] != snellFrameVersion {
				t.Fatalf("frame version = %d, want %d", header[0], snellFrameVersion)
			}
			padding := int(binary.BigEndian.Uint16(header[3:5]))
			length := int(binary.BigEndian.Uint16(header[5:7]))
			if length != len("first record") {
				t.Fatalf("payload length = %d", length)
			}
			if version == 4 && padding != 0 {
				t.Fatalf("v4 sent %d padding bytes", padding)
			}
			if version == 5 && (padding < snellInitialPaddingMin || padding > snellInitialPaddingMax) {
				t.Fatalf("v5 padding = %d, want %d..%d", padding, snellInitialPaddingMin, snellInitialPaddingMax)
			}
			rest := make([]byte, padding+length+aead.Overhead())
			if _, err := io.ReadFull(wire, rest); err != nil {
				t.Fatalf("read frame body: %v", err)
			}
			if err := <-written; err != nil {
				t.Fatalf("client write: %v", err)
			}
		})
	}
}

func TestSnellFrameCodecRoundTrip(t *testing.T) {
	definition, err := NewSnell(SnellOptions{
		Server: "127.0.0.1", Port: 1080, PSK: testSnellPSK, Version: 5,
	})
	if err != nil {
		t.Fatalf("definition: %v", err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	a := newSnellConn(left, definition)
	b := newSnellConn(right, definition)
	payload := bytes.Repeat([]byte("snell-frame-codec "), 2000)
	written := make(chan error, 1)
	go func() {
		_, err := a.Write(payload)
		written <- err
	}()
	_ = right.SetDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read framed stream: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatalf("write framed stream: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("framed stream differs from what was written")
	}
	padding := bytes.Repeat([]byte{1, 2, 3, 4}, 40)
	ciphertext := bytes.Repeat([]byte{9, 8, 7, 6}, 40)
	originalPadding := append([]byte(nil), padding...)
	originalCiphertext := append([]byte(nil), ciphertext...)
	snellSwapPadding(padding, ciphertext)
	snellSwapPadding(padding, ciphertext)
	if !bytes.Equal(padding, originalPadding) || !bytes.Equal(ciphertext, originalCiphertext) {
		t.Fatal("the padding swap is not its own inverse")
	}
}
