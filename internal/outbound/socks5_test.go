package outbound

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAppendAddressRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		target Target
		want   []byte
	}{
		{
			name:   "ipv4",
			target: Target{Host: "192.0.2.1", Port: 443},
			want:   []byte{atypIPv4, 192, 0, 2, 1, 0x01, 0xbb},
		},
		{
			name:   "ipv6",
			target: Target{Host: "2001:db8::1", Port: 53},
			want: append([]byte{atypIPv6},
				append(net.ParseIP("2001:db8::1").To16(), 0x00, 0x35)...),
		},
		{
			name:   "name",
			target: Target{Host: "example.com", Port: 8080},
			want: append([]byte{atypDomain, 11},
				append([]byte("example.com"), 0x1f, 0x90)...),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AppendAddress(nil, tc.target)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("AppendAddress = %v, want %v", got, tc.want)
			}
			host, err := readAddress(bytes.NewReader(got[1:]), got[0])
			if err != nil {
				t.Fatalf("readAddress: %v", err)
			}
			if host != tc.target.Host {
				t.Fatalf("readAddress = %q, want %q", host, tc.target.Host)
			}
		})
	}
}

func TestReadReply(t *testing.T) {
	t.Run("ipv4 bound address", func(t *testing.T) {
		raw := []byte{5, 0, 0, atypIPv4, 10, 0, 0, 1, 0x04, 0x38}
		got, err := readReply(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("readReply: %v", err)
		}
		if got != (Target{Host: "10.0.0.1", Port: 1080}) {
			t.Fatalf("bound = %+v, want 10.0.0.1:1080", got)
		}
	})
	t.Run("name bound address", func(t *testing.T) {
		raw := append([]byte{5, 0, 0, atypDomain, 10}, []byte("relay.test")...)
		raw = append(raw, 0x00, 0x50)
		got, err := readReply(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("readReply: %v", err)
		}
		if got != (Target{Host: "relay.test", Port: 80}) {
			t.Fatalf("bound = %+v, want relay.test:80", got)
		}
	})
	t.Run("refused", func(t *testing.T) {
		_, err := readReply(bytes.NewReader([]byte{5, 0x05, 0, atypIPv4, 0, 0, 0, 0, 0, 0}))
		if err == nil || !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("error = %v, want a refusal", err)
		}
	})
	t.Run("version mismatch", func(t *testing.T) {
		_, err := readReply(bytes.NewReader([]byte{4, 0, 0, atypIPv4, 0, 0, 0, 0, 0, 0}))
		if err == nil || !strings.Contains(err.Error(), "version") {
			t.Fatalf("error = %v, want a version complaint", err)
		}
	})
	t.Run("unsupported address type", func(t *testing.T) {
		_, err := readReply(bytes.NewReader([]byte{5, 0, 0, 0x09, 0, 0}))
		if err == nil || !strings.Contains(err.Error(), "address type") {
			t.Fatalf("error = %v, want an address type complaint", err)
		}
	})
	t.Run("empty name", func(t *testing.T) {
		_, err := readReply(bytes.NewReader([]byte{5, 0, 0, atypDomain, 0, 0, 0}))
		if err == nil {
			t.Fatal("readReply accepted an empty name")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		_, err := readReply(bytes.NewReader([]byte{5, 0, 0, atypIPv4, 10}))
		if err == nil {
			t.Fatal("readReply accepted a truncated reply")
		}
	})
}

func TestDecodeUDPDatagram(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		raw := []byte{0, 0, 0, atypIPv4, 192, 0, 2, 7, 0x1f, 0x90}
		raw = append(raw, "payload"...)
		payload, from, frag, err := DecodeUDPDatagram(raw)
		if err != nil {
			t.Fatalf("DecodeUDPDatagram: %v", err)
		}
		if frag != 0 {
			t.Fatalf("frag = %d, want 0", frag)
		}
		if string(payload) != "payload" {
			t.Fatalf("payload = %q, want payload", payload)
		}
		if from != (Target{Host: "192.0.2.7", Port: 8080}) {
			t.Fatalf("from = %+v, want 192.0.2.7:8080", from)
		}
	})
	t.Run("name", func(t *testing.T) {
		raw := append([]byte{0, 0, 0, atypDomain, 11}, []byte("example.com")...)
		raw = append(raw, 0x00, 0x35)
		raw = append(raw, 1, 2, 3)
		payload, from, _, err := DecodeUDPDatagram(raw)
		if err != nil {
			t.Fatalf("DecodeUDPDatagram: %v", err)
		}
		if !bytes.Equal(payload, []byte{1, 2, 3}) {
			t.Fatalf("payload = %v, want [1 2 3]", payload)
		}
		if from != (Target{Host: "example.com", Port: 53}) {
			t.Fatalf("from = %+v, want example.com:53", from)
		}
	})
	t.Run("fragment is reported", func(t *testing.T) {
		raw := []byte{0, 0, 1, atypIPv4, 192, 0, 2, 7, 0, 53, 9}
		_, _, frag, err := DecodeUDPDatagram(raw)
		if err != nil {
			t.Fatalf("DecodeUDPDatagram: %v", err)
		}
		if frag != 1 {
			t.Fatalf("frag = %d, want 1", frag)
		}
	})
	t.Run("reserved bytes", func(t *testing.T) {
		raw := []byte{1, 0, 0, atypIPv4, 192, 0, 2, 7, 0, 53}
		if _, _, _, err := DecodeUDPDatagram(raw); err == nil {
			t.Fatal("DecodeUDPDatagram accepted reserved bytes")
		}
	})
	t.Run("truncated header", func(t *testing.T) {
		for _, raw := range [][]byte{
			{0, 0},
			{0, 0, 0, atypIPv4, 192},
			{0, 0, 0, atypDomain, 5, 'a'},
			{0, 0, 0, 0x07, 0, 0},
		} {
			if _, _, _, err := DecodeUDPDatagram(raw); err == nil {
				t.Fatalf("DecodeUDPDatagram accepted %v", raw)
			}
		}
	})
}

func TestUDPDatagramFraming(t *testing.T) {
	tests := []struct {
		name    string
		to      Target
		payload []byte
		want    []byte
	}{
		{
			name:    "ipv4",
			to:      Target{Host: "192.0.2.7", Port: 8080},
			payload: []byte("hi"),
			want: []byte{0, 0, 0, atypIPv4, 192, 0, 2, 7, 0x1f, 0x90,
				'h', 'i'},
		},
		{
			name:    "name",
			to:      Target{Host: "example.com", Port: 53},
			payload: []byte{0xff},
			want: append([]byte{0, 0, 0, atypDomain, 11},
				append(append([]byte("example.com"), 0x00, 0x35), 0xff)...),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AppendUDPDatagram(nil, tc.to, tc.payload)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("framed datagram = %v, want %v", got, tc.want)
			}
			payload, from, frag, err := DecodeUDPDatagram(got)
			if err != nil {
				t.Fatalf("DecodeUDPDatagram: %v", err)
			}
			if frag != 0 || from != tc.to || !bytes.Equal(payload, tc.payload) {
				t.Fatalf("round trip = %+v/%v/%d, want %+v/%v", from, payload, frag, tc.to, tc.payload)
			}
		})
	}
}

func TestSOCKS5HandshakeWithoutAuth(t *testing.T) {
	server := startTestSOCKS5(t, "", "")
	echo := startTCPEcho(t)
	conn := dialThrough(t, mustSocks5(t, server.addr, "", ""), echo)

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}
	if greeting := server.Greeting(); !bytes.Equal(greeting, []byte{socks5Version, 1, methodNoAuth}) {
		t.Fatalf("greeting = %v, want one no-auth method", greeting)
	}
	target, err := ParseTarget(echo)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	requests := server.Requests()
	if len(requests) != 1 || requests[0].Command != cmdConnect || requests[0].Target != target {
		t.Fatalf("requests = %+v, want one CONNECT to %+v", requests, target)
	}
}

func TestSOCKS5HandshakeWithAuth(t *testing.T) {
	server := startTestSOCKS5(t, "alice", "s3cret")
	echo := startTCPEcho(t)
	conn := dialThrough(t, mustSocks5(t, server.addr, "alice", "s3cret"), echo)

	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if greeting := server.Greeting(); !bytes.Equal(greeting, []byte{socks5Version, 2, methodNoAuth, methodUserPassword}) {
		t.Fatalf("greeting = %v, want both methods offered", greeting)
	}
	user, pass := server.Credentials()
	if user != "alice" || pass != "s3cret" {
		t.Fatalf("credentials = %q/%q, want alice/s3cret", user, pass)
	}
}

func TestSOCKS5AuthenticationFailure(t *testing.T) {
	server := startTestSOCKS5(t, "alice", "s3cret")
	dialer := mustSocks5(t, server.addr, "alice", "wrong")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := dialer.DialContext(ctx, "example.com:80"); err == nil {
		t.Fatal("dial with a wrong password succeeded")
	} else if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("error = %v, want an authentication failure", err)
	}
}

func TestSOCKS5PassesNameToTheServer(t *testing.T) {
	server := startTestSOCKS5(t, "", "")
	echo := startTCPEcho(t)
	target, err := ParseTarget(echo)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	// The name is never resolved locally: it is handed to the server as a
	// domain, which is what keeps a proxied lookup out of the local resolver.
	conn := dialThrough(t, mustSocks5(t, server.addr, "", ""),
		net.JoinHostPort("localhost", strconv.Itoa(int(target.Port))))
	if _, err := conn.Write([]byte("y")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	requests := server.Requests()
	if len(requests) != 1 {
		t.Fatalf("requests = %+v, want one", requests)
	}
	if requests[0].Target.Host != "localhost" {
		t.Fatalf("server saw host %q, want localhost", requests[0].Target.Host)
	}
}

func TestSOCKS5RejectsAnUnacceptableMethod(t *testing.T) {
	address := startScriptedServer(t, func(conn net.Conn) {
		head := make([]byte, 3)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		_, _ = conn.Write([]byte{socks5Version, methodNoAcceptable})
	})
	dialer := mustSocks5(t, address, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := dialer.DialContext(ctx, "example.com:80"); err == nil {
		t.Fatal("dial succeeded although no method was acceptable")
	} else if !strings.Contains(err.Error(), "accepted none") {
		t.Fatalf("error = %v, want a method complaint", err)
	}
}

func TestSOCKS5RejectsAnUnknownMethodSelection(t *testing.T) {
	address := startScriptedServer(t, func(conn net.Conn) {
		head := make([]byte, 3)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		_, _ = conn.Write([]byte{socks5Version, 0x07})
	})
	dialer := mustSocks5(t, address, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := dialer.DialContext(ctx, "example.com:80"); err == nil {
		t.Fatal("dial succeeded although the method was unknown")
	} else if !strings.Contains(err.Error(), "unsupported method") {
		t.Fatalf("error = %v, want an unsupported method complaint", err)
	}
}

func TestSOCKS5RejectsAGreetingVersionMismatch(t *testing.T) {
	address := startScriptedServer(t, func(conn net.Conn) {
		head := make([]byte, 3)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		_, _ = conn.Write([]byte{4, methodNoAuth})
	})
	dialer := mustSocks5(t, address, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := dialer.DialContext(ctx, "example.com:80"); err == nil {
		t.Fatal("dial succeeded although the version was wrong")
	} else if !strings.Contains(err.Error(), "version") {
		t.Fatalf("error = %v, want a version complaint", err)
	}
}

func TestSOCKS5SurfacesARefusedConnect(t *testing.T) {
	address := startScriptedServer(t, func(conn net.Conn) {
		head := make([]byte, 3)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		_, _ = conn.Write([]byte{socks5Version, methodNoAuth})
		request := make([]byte, 10)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}
		// Code 5: connection refused.
		_, _ = conn.Write([]byte{5, 0x05, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	})
	dialer := mustSocks5(t, address, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := dialer.DialContext(ctx, "example.com:80"); err == nil {
		t.Fatal("dial succeeded although the server refused")
	} else if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("error = %v, want a refusal", err)
	}
}

func TestSOCKS5HandshakeHonoursContext(t *testing.T) {
	// A server that accepts the greeting and then says nothing must not keep
	// the dialer waiting past the context deadline.
	address := startScriptedServer(t, func(conn net.Conn) {
		head := make([]byte, 3)
		_, _ = io.ReadFull(conn, head)
		<-time.After(2 * time.Second)
	})
	dialer := mustSocks5(t, address, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := dialer.DialContext(ctx, "example.com:80"); err == nil {
		t.Fatal("dial succeeded although the handshake never finished")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("dial took %v, want it bounded by the context", elapsed)
	}
}

func TestSOCKS5UDPAssociate(t *testing.T) {
	if !datagramSendAllowed(t) {
		t.Skip("the environment does not allow the relay to answer")
	}
	server := startTestSOCKS5(t, "", "")
	echo := startUDPEcho(t)
	dialer := mustSocks5(t, server.addr, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	packet, err := dialer.DialPacket(ctx, echo)
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer packet.Close()

	if _, err := packet.Write([]byte("udp payload")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := packet.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, err := packet.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "udp payload" {
		t.Fatalf("echo = %q, want udp payload", buf[:n])
	}
	requests := server.Requests()
	if len(requests) != 1 || requests[0].Command != cmdUDPAssociate {
		t.Fatalf("requests = %+v, want one UDP ASSOCIATE", requests)
	}
}

func TestUDPRelayRoundTripThroughServer(t *testing.T) {
	if !datagramSendAllowed(t) {
		t.Skip("the environment does not allow the relay to answer")
	}
	// The relay is exercised through a real association because the framing
	// lives on the wire, not in a helper.
	server := startTestSOCKS5(t, "", "")
	echo := startUDPEcho(t)
	dialer := mustSocks5(t, server.addr, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relay, err := dialer.DialUDP(ctx)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer relay.Close()

	destination, err := ParseTarget(echo)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if _, err := relay.WriteTo([]byte("first"), destination); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if err := relay.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, from, err := relay.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "first" {
		t.Fatalf("payload = %q, want first", buf[:n])
	}
	if from.Port != destination.Port {
		t.Fatalf("from = %+v, want the port of %+v", from, destination)
	}
	if relay.RemoteAddr().String() == "" {
		t.Fatal("RemoteAddr is empty")
	}
}

// TestUDPRelayFramingOnSockets drives the relay over a real datagram pair. Both
// sockets are connected to each other up front, so the test needs no
// address-based send and runs in environments that deny it.
func TestUDPRelayFramingOnSockets(t *testing.T) {
	relayConn, peer := connectedDatagramPair(t)
	defer relayConn.Close()
	defer peer.Close()
	control, controlPeer := net.Pipe()
	defer control.Close()
	defer controlPeer.Close()

	relay := &UDPRelay{control: control, conn: relayConn, server: Target{Host: "127.0.0.1", Port: 1}}
	destination := Target{Host: "192.0.2.9", Port: 5353}

	payload := []byte("payload")
	n, err := relay.WriteTo(payload, destination)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteTo wrote %d, want %d", n, len(payload))
	}

	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 256)
	read, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if want := AppendUDPDatagram(nil, destination, payload); !bytes.Equal(buf[:read], want) {
		t.Fatalf("wire datagram = %v, want %v", buf[:read], want)
	}

	// A fragmented datagram must be dropped, not delivered as a payload, and
	// the scan has to go on to the next whole datagram.
	fragmented := AppendUDPDatagram(nil, destination, []byte("dropped"))
	fragmented[2] = 1
	if _, err := peer.Write(fragmented); err != nil {
		t.Fatalf("peer write fragmented: %v", err)
	}
	if _, err := peer.Write(AppendUDPDatagram(nil, destination, []byte("kept"))); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	if err := relay.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	got := make([]byte, 64)
	read, from, err := relay.ReadFrom(got)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(got[:read]) != "kept" {
		t.Fatalf("payload = %q, want kept", got[:read])
	}
	if from != destination {
		t.Fatalf("from = %+v, want %+v", from, destination)
	}

	// A malformed datagram is skipped as well.
	if _, err := peer.Write([]byte{1, 2, 3}); err != nil {
		t.Fatalf("peer write malformed: %v", err)
	}
	if _, err := peer.Write(AppendUDPDatagram(nil, destination, []byte("after"))); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	read, _, err = relay.ReadFrom(got)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(got[:read]) != "after" {
		t.Fatalf("payload = %q, want after", got[:read])
	}
}

// connectedDatagramPair returns two datagram sockets that are connected to each
// other. The ports are reserved first because each socket must know the address
// of the other before it is created.
func connectedDatagramPair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	loopback := net.IPv4(127, 0, 0, 1)
	for attempt := 0; attempt < 3; attempt++ {
		first, second := reserveUDPPort(t), reserveUDPPort(t)
		if first == second {
			continue
		}
		a, err := net.DialUDP("udp4",
			&net.UDPAddr{IP: loopback, Port: first},
			&net.UDPAddr{IP: loopback, Port: second})
		if err != nil {
			continue
		}
		b, err := net.DialUDP("udp4",
			&net.UDPAddr{IP: loopback, Port: second},
			&net.UDPAddr{IP: loopback, Port: first})
		if err != nil {
			_ = a.Close()
			continue
		}
		return a, b
	}
	t.Fatal("could not build a connected datagram pair")
	return nil, nil
}

// reserveUDPPort finds a free loopback port and releases it again.
func reserveUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserve a udp port: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port
}

func TestSOCKS5DialPacketKeepsOneDestination(t *testing.T) {
	server := startTestSOCKS5(t, "", "")
	echo := startUDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	packet, err := mustSocks5(t, server.addr, "", "").DialPacket(ctx, echo)
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer packet.Close()
	if got := packet.RemoteAddr().String(); got != echo {
		t.Fatalf("RemoteAddr = %s, want %s", got, echo)
	}
	if got := packet.LocalAddr(); got == nil {
		t.Fatal("LocalAddr is nil")
	}
	if err := packet.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := packet.Write([]byte("z")); err != nil {
		t.Fatalf("write: %v", err)
	}
}
