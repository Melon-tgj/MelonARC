package inbound

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// mustSOCKS5Client builds a SOCKS5 outbound pointed at a listener. Using the
// outbound implementation as the client exercises both halves of the protocol
// against each other.
func mustSOCKS5Client(t *testing.T, address, username, password string) *outbound.SOCKS5 {
	t.Helper()
	target, err := outbound.ParseTarget(address)
	if err != nil {
		t.Fatalf("parse %q: %v", address, err)
	}
	client, err := outbound.NewSOCKS5(outbound.SOCKS5Options{
		Server:   target.Host,
		Port:     int(target.Port),
		Username: username,
		Password: password,
		Timeout:  testDeadline,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5: %v", err)
	}
	return client
}

// dialThrough opens a stream with a dialer under a bounded context.
func dialThrough(t *testing.T, dialer outbound.Dialer, address string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	conn, err := dialer.DialContext(ctx, address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// rawClient is a SOCKS5 client that sends exactly the bytes a test asks for,
// which is what the error paths need.
type rawClient struct {
	conn   net.Conn
	reader *bufio.Reader
}

// dialRaw connects to a listener without sending anything.
func dialRaw(t *testing.T, address string) *rawClient {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(testDeadline))
	return &rawClient{conn: conn, reader: bufio.NewReader(conn)}
}

// greet sends a greeting and returns the method the server selected, or 0 when
// the server closed the connection.
func (c *rawClient) greet(t *testing.T, methods ...byte) byte {
	t.Helper()
	if _, err := c.conn.Write(append([]byte{socks5Version, byte(len(methods))}, methods...)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(c.reader, reply[:]); err != nil {
		return 0
	}
	return reply[1]
}

// request sends a command request and returns the reply code together with the
// address the server reported as bound.
func (c *rawClient) request(t *testing.T, command byte, target outbound.Target) (byte, outbound.Target) {
	t.Helper()
	req := []byte{socks5Version, command, 0x00}
	req = outbound.AppendAddress(req, target)
	if _, err := c.conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return c.readReply(t)
}

// readReply reads one command reply.
func (c *rawClient) readReply(t *testing.T) (byte, outbound.Target) {
	t.Helper()
	var head [4]byte
	if _, err := io.ReadFull(c.reader, head[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if head[0] != socks5Version {
		t.Fatalf("reply has version %d", head[0])
	}
	host, err := readAddress(c.reader, head[3])
	if err != nil {
		t.Fatalf("read bound address: %v", err)
	}
	var port [2]byte
	if _, err := io.ReadFull(c.reader, port[:]); err != nil {
		t.Fatalf("read bound port: %v", err)
	}
	return head[1], outbound.Target{Host: host, Port: uint16(port[0])<<8 | uint16(port[1])}
}

// TestSOCKS5Connect drives a stream through the listener with the outbound
// client as the peer, for a destination given as an address and as a name.
func TestSOCKS5Connect(t *testing.T) {
	echo := startEcho(t)
	target, err := outbound.ParseTarget(echo)
	if err != nil {
		t.Fatalf("parse echo address: %v", err)
	}
	named := net.JoinHostPort("localhost", strconv.Itoa(int(target.Port)))

	proxy := startSOCKS5Service(t, directEnv(t))
	client := mustSOCKS5Client(t, proxy.Addr(), "", "")

	for _, address := range []string{echo, named} {
		t.Run(address, func(t *testing.T) {
			conn := dialThrough(t, client, address)
			payload := bytes.Repeat([]byte("socks "), 256)
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("echoed %d bytes differ from what was sent", len(got))
			}
		})
	}
}

// TestSOCKS5HalfClose checks that the half close of the client only ends the
// write direction of the stream.
func TestSOCKS5HalfClose(t *testing.T) {
	proxy := startSOCKS5Service(t, directEnv(t))
	testHalfClose(t, func(backend string) (net.Conn, io.Reader) {
		client := mustSOCKS5Client(t, proxy.Addr(), "", "")
		conn := dialThrough(t, client, backend)
		return conn, conn
	})
}

// TestSOCKS5Authentication covers the credential combinations: no
// authentication, the right pair, the wrong pair, a client that offers
// credentials to a listener that does not need them, and a client that offers
// none to one that does.
func TestSOCKS5Authentication(t *testing.T) {
	echo := startEcho(t)
	tests := []struct {
		name       string
		serverUser string
		serverPass string
		clientUser string
		clientPass string
		wantErr    bool
	}{
		{name: "no authentication"},
		{
			name:       "correct credentials",
			serverUser: "alice", serverPass: "s3cret",
			clientUser: "alice", clientPass: "s3cret",
		},
		{
			name:       "wrong password",
			serverUser: "alice", serverPass: "s3cret",
			clientUser: "alice", clientPass: "wrong",
			wantErr: true,
		},
		{
			name:       "wrong username",
			serverUser: "alice", serverPass: "s3cret",
			clientUser: "bob", clientPass: "s3cret",
			wantErr: true,
		},
		{
			name:       "credentials offered but not needed",
			clientUser: "alice", clientPass: "s3cret",
		},
		{
			name:       "credentials required but not offered",
			serverUser: "alice", serverPass: "s3cret",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proxy := startSOCKS5Service(t, directEnv(t), func(opts *SOCKS5Options) {
				opts.Username, opts.Password = tc.serverUser, tc.serverPass
			})
			client := mustSOCKS5Client(t, proxy.Addr(), tc.clientUser, tc.clientPass)
			ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
			defer cancel()
			conn, err := client.DialContext(ctx, echo)
			if err == nil {
				conn.Close()
			}
			switch {
			case tc.wantErr && err == nil:
				t.Fatal("the connection was accepted with credentials that should not be")
			case !tc.wantErr && err != nil:
				t.Fatalf("dial: %v", err)
			}
		})
	}
}

// TestSOCKS5NegotiationErrors covers the greetings a client must not get away
// with.
func TestSOCKS5NegotiationErrors(t *testing.T) {
	t.Run("wrong version", func(t *testing.T) {
		proxy := startSOCKS5Service(t, directEnv(t))
		client := dialRaw(t, proxy.Addr())
		if _, err := client.conn.Write([]byte{0x04, 0x01, methodNoAuth}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		if _, err := client.reader.ReadByte(); err == nil {
			t.Fatal("the listener answered a version it does not speak")
		}
	})

	t.Run("no methods", func(t *testing.T) {
		proxy := startSOCKS5Service(t, directEnv(t))
		client := dialRaw(t, proxy.Addr())
		if _, err := client.conn.Write([]byte{socks5Version, 0x00}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		if _, err := client.reader.ReadByte(); err == nil {
			t.Fatal("the listener answered a greeting with no methods")
		}
	})

	t.Run("no acceptable method", func(t *testing.T) {
		proxy := startSOCKS5Service(t, directEnv(t), func(opts *SOCKS5Options) {
			opts.Username, opts.Password = "alice", "s3cret"
		})
		client := dialRaw(t, proxy.Addr())
		if got := client.greet(t, methodNoAuth); got != methodUnacceptable {
			t.Fatalf("selected method = %#x, want %#x", got, methodUnacceptable)
		}
	})

	t.Run("wrong authentication version", func(t *testing.T) {
		proxy := startSOCKS5Service(t, directEnv(t), func(opts *SOCKS5Options) {
			opts.Username, opts.Password = "alice", "s3cret"
		})
		client := dialRaw(t, proxy.Addr())
		if got := client.greet(t, methodUserPassword); got != methodUserPassword {
			t.Fatalf("selected method = %#x, want username and password", got)
		}
		if _, err := client.conn.Write([]byte{0x02, 0x05, 'a', 'l', 'i', 'c', 'e', 0x00}); err != nil {
			t.Fatalf("write authentication: %v", err)
		}
		if _, err := client.reader.ReadByte(); err == nil {
			t.Fatal("the listener answered an authentication version it does not speak")
		}
	})
}

// TestSOCKS5CommandErrors covers the requests that cannot be served and the
// reply code each one earns.
func TestSOCKS5CommandErrors(t *testing.T) {
	echo := startEcho(t)
	target, err := outbound.ParseTarget(echo)
	if err != nil {
		t.Fatalf("parse echo address: %v", err)
	}

	t.Run("bind is not supported", func(t *testing.T) {
		proxy := startSOCKS5Service(t, directEnv(t))
		client := dialRaw(t, proxy.Addr())
		if got := client.greet(t, methodNoAuth); got != methodNoAuth {
			t.Fatalf("selected method = %#x, want none", got)
		}
		code, _ := client.request(t, commandBind, target)
		if code != replyCommandNotSupported {
			t.Fatalf("reply = %#x, want %#x", code, replyCommandNotSupported)
		}
	})

	t.Run("unknown address type", func(t *testing.T) {
		proxy := startSOCKS5Service(t, directEnv(t))
		client := dialRaw(t, proxy.Addr())
		if got := client.greet(t, methodNoAuth); got != methodNoAuth {
			t.Fatalf("selected method = %#x, want none", got)
		}
		// ATYP 0x09 is not part of the protocol.
		if _, err := client.conn.Write([]byte{socks5Version, commandConnect, 0x00, 0x09}); err != nil {
			t.Fatalf("write request: %v", err)
		}
		code, _ := client.readReply(t)
		if code != replyAddressNotSupported {
			t.Fatalf("reply = %#x, want %#x", code, replyAddressNotSupported)
		}
	})

	t.Run("rejected by a rule", func(t *testing.T) {
		env := newTestEnv(t, envOptions{
			rules: []string{"FINAL,REJECT"},
			leaves: map[string]outbound.Dialer{
				"DIRECT": outbound.NewDirect(),
				"REJECT": outbound.NewReject(),
			},
		})
		proxy := startSOCKS5Service(t, env)
		client := dialRaw(t, proxy.Addr())
		if got := client.greet(t, methodNoAuth); got != methodNoAuth {
			t.Fatalf("selected method = %#x, want none", got)
		}
		code, _ := client.request(t, commandConnect, target)
		if code != replyNotAllowed {
			t.Fatalf("reply = %#x, want %#x", code, replyNotAllowed)
		}
	})

	t.Run("unreachable destination", func(t *testing.T) {
		proxy := startSOCKS5Service(t, directEnv(t))
		client := dialRaw(t, proxy.Addr())
		if got := client.greet(t, methodNoAuth); got != methodNoAuth {
			t.Fatalf("selected method = %#x, want none", got)
		}
		// Port 1 on the loopback interface has nothing listening.
		code, _ := client.request(t, commandConnect, outbound.Target{Host: "127.0.0.1", Port: 1})
		if code == replySucceeded {
			t.Fatal("the listener reported success for a destination it could not reach")
		}
	})
}

// TestSOCKS5UDPAssociateReply checks the association handshake: the listener
// must answer with an address the client can send datagrams to.
func TestSOCKS5UDPAssociateReply(t *testing.T) {
	proxy := startSOCKS5Service(t, directEnv(t))
	client := dialRaw(t, proxy.Addr())
	if got := client.greet(t, methodNoAuth); got != methodNoAuth {
		t.Fatalf("selected method = %#x, want none", got)
	}
	code, bound := client.request(t, commandUDPAssociate, outbound.Target{Host: "0.0.0.0"})
	if code != replySucceeded {
		t.Fatalf("reply = %#x, want success", code)
	}
	if bound.Port == 0 {
		t.Fatal("the association reported no port")
	}
	if ip := net.ParseIP(bound.Host); ip == nil || !ip.IsLoopback() {
		t.Fatalf("bound address = %q, want the loopback the control connection came in on", bound.Host)
	}
}

// TestSOCKS5UDPRelay sends one datagram through an association and reads the
// answer back.
func TestSOCKS5UDPRelay(t *testing.T) {
	if !datagramSendAllowed(t) {
		t.Skip("this environment denies sendto to an unconnected peer; the datagram path needs it")
	}
	destination, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer destination.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := destination.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = destination.WriteToUDP(buf[:n], from)
		}
	}()

	proxy := startSOCKS5Service(t, directEnv(t))
	client := dialRaw(t, proxy.Addr())
	if got := client.greet(t, methodNoAuth); got != methodNoAuth {
		t.Fatalf("selected method = %#x, want none", got)
	}
	code, bound := client.request(t, commandUDPAssociate, outbound.Target{Host: "0.0.0.0"})
	if code != replySucceeded {
		t.Fatalf("reply = %#x, want success", code)
	}
	relayAddr, err := net.ResolveUDPAddr("udp", bound.String())
	if err != nil {
		t.Fatalf("resolve relay address: %v", err)
	}
	socket, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer socket.Close()
	_ = socket.SetDeadline(time.Now().Add(testDeadline))

	dest := outbound.Target{Host: "127.0.0.1", Port: uint16(destination.LocalAddr().(*net.UDPAddr).Port)}
	payload := []byte("datagram")
	if _, err := socket.Write(outbound.AppendUDPDatagram(nil, dest, payload)); err != nil {
		t.Fatalf("write datagram: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := socket.Read(buf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	got, from, frag, err := outbound.DecodeUDPDatagram(buf[:n])
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if frag != 0 {
		t.Fatalf("reply carries fragment %d", frag)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	if from.String() != dest.String() {
		t.Fatalf("reply source = %s, want the destination %s", from, dest)
	}
}
