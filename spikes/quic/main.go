// Command quicspike validates that the QUIC stack can run a local round trip:
// it starts a server on 127.0.0.1 with a self-signed certificate, dials it from
// a client that trusts that certificate, sends a string over a bidirectional
// stream, and checks that the byte sequence coming back is identical.
//
// Everything runs in one process so the spike is a single command:
//
//	go run ./spikes/quic
//
// The -connected-udp flag exists for sandboxes that deny sendto/sendmsg on
// unconnected UDP sockets: both endpoints then bind a port, connect to each
// other, and hand quic-go a thin net.PacketConn adapter that only uses
// read/write on the connected socket.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/sys/unix"
)

const (
	alpnProto = "melonarc-echo"
	payload   = "melonarc-quic-echo-ping"
	timeout   = 8 * time.Second
)

var connectedUDP = flag.Bool("connected-udp", false,
	"connect both UDP sockets to each other instead of using unconnected sockets (workaround for sandboxes that deny sendto)")

func main() {
	log.SetFlags(0)
	log.SetPrefix("quicspike: ")
	flag.Parse()
	if err := run(); err != nil {
		log.Fatalf("FAIL: %v", err)
	}
}

func run() error {
	cert, err := selfSignedCert()
	if err != nil {
		return fmt.Errorf("generate certificate: %w", err)
	}

	listener, dial, cleanup, err := setupEndpoints(cert)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- serveEcho(ctx, listener) }()

	conn, err := dial(ctx)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseWithError(0, "")

	state := conn.ConnectionState()
	log.Printf("connected: version=%s alpn=%q tls=%s",
		state.Version, state.TLS.NegotiatedProtocol, tls.VersionName(state.TLS.Version))

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	if _, err := stream.Write([]byte(payload)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	// Closing the stream closes the write direction only, so the echo can still
	// be read back and the server sees EOF.
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close write side: %w", err)
	}

	echoed, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if err := <-errCh; err != nil {
		return fmt.Errorf("server: %w", err)
	}

	fmt.Printf("sent:     %q\n", payload)
	fmt.Printf("received: %q\n", string(echoed))
	if !bytes.Equal(echoed, []byte(payload)) {
		return fmt.Errorf("echo mismatch: sent %q, got %q", payload, echoed)
	}
	fmt.Println("OK: echo round trip over QUIC matches")
	return nil
}

// setupEndpoints binds the loopback sockets, starts the server listener and
// returns a dial function plus a cleanup hook. Both sockets live in this
// process, which is what makes the spike a single command.
func setupEndpoints(cert tls.Certificate) (*quic.Listener, func(context.Context) (*quic.Conn, error), func(), error) {
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpnProto},
		MinVersion:   tls.VersionTLS13,
	}
	clientTLS := &tls.Config{
		NextProtos: []string{alpnProto},
		MinVersion: tls.VersionTLS13,
	}

	clientPC, clientAddr, err := listenLoopback()
	if err != nil {
		return nil, nil, nil, err
	}
	serverPC, serverAddr, err := listenLoopback()
	if err != nil {
		clientPC.Close()
		return nil, nil, nil, err
	}
	clientTLS.RootCAs = certPool(cert)

	var serverConn, clientConn net.PacketConn = serverPC, clientPC
	if *connectedUDP {
		if err := connectUDP(serverPC, clientAddr); err != nil {
			serverPC.Close()
			clientPC.Close()
			return nil, nil, nil, fmt.Errorf("connect server socket: %w", err)
		}
		if err := connectUDP(clientPC, serverAddr); err != nil {
			serverPC.Close()
			clientPC.Close()
			return nil, nil, nil, fmt.Errorf("connect client socket: %w", err)
		}
		serverConn = &connectedConn{conn: serverPC, peer: clientAddr}
		clientConn = &connectedConn{conn: clientPC, peer: serverAddr}
	}

	serverTransport := &quic.Transport{Conn: serverConn}
	clientTransport := &quic.Transport{Conn: clientConn}

	listener, err := serverTransport.Listen(serverTLS, nil)
	if err != nil {
		serverTransport.Close()
		clientTransport.Close()
		return nil, nil, nil, fmt.Errorf("listen on %s: %w", serverAddr, err)
	}
	log.Printf("server listening on %s (udp), alpn %q, connected sockets: %v",
		serverAddr, alpnProto, *connectedUDP)

	dial := func(ctx context.Context) (*quic.Conn, error) {
		return clientTransport.Dial(ctx, serverAddr, clientTLS, nil)
	}
	cleanup := func() {
		listener.Close()
		serverTransport.Close()
		clientTransport.Close()
	}
	return listener, dial, cleanup, nil
}

// serveEcho accepts one connection and one stream, then writes the request back.
// The connection is left open on purpose: tearing it down here can push a
// CONNECTION_CLOSE ahead of the buffered stream data, and the client would see
// the echo as lost.
func serveEcho(ctx context.Context, listener *quic.Listener) error {
	conn, err := listener.Accept(ctx)
	if err != nil {
		return fmt.Errorf("accept connection: %w", err)
	}

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept stream: %w", err)
	}
	req, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	log.Printf("server read %d bytes on stream %d", len(req), stream.StreamID())

	if _, err := stream.Write(req); err != nil {
		return fmt.Errorf("write echo: %w", err)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close stream: %w", err)
	}
	return nil
}

// listenLoopback binds a UDP socket on an ephemeral loopback port.
func listenLoopback() (*net.UDPConn, *net.UDPAddr, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, fmt.Errorf("bind loopback udp: %w", err)
	}
	return conn, conn.LocalAddr().(*net.UDPAddr), nil
}

// connectUDP connects an already bound socket to peer. net has no exported
// Connect for a bound UDP socket, so the descriptor is used directly.
func connectUDP(conn *net.UDPConn, peer *net.UDPAddr) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	ip := peer.IP.To4()
	if ip == nil {
		return fmt.Errorf("peer %s is not IPv4", peer)
	}
	var connectErr error
	if err := raw.Control(func(fd uintptr) {
		connectErr = unix.Connect(int(fd), &unix.SockaddrInet4{Port: peer.Port, Addr: [4]byte(ip)})
	}); err != nil {
		return err
	}
	return connectErr
}

// connectedConn adapts a connected UDP socket to net.PacketConn. Reads and
// writes go through read(2)/write(2) instead of recvfrom(2)/sendto(2), and the
// peer address is implied by the connection.
type connectedConn struct {
	conn *net.UDPConn
	peer net.Addr
}

func (c *connectedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.conn.Read(p)
	return n, c.peer, err
}

func (c *connectedConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.conn.Write(p) }
func (c *connectedConn) Close() error                              { return c.conn.Close() }
func (c *connectedConn) LocalAddr() net.Addr                       { return c.conn.LocalAddr() }
func (c *connectedConn) SetDeadline(t time.Time) error             { return c.conn.SetDeadline(t) }
func (c *connectedConn) SetReadDeadline(t time.Time) error         { return c.conn.SetReadDeadline(t) }
func (c *connectedConn) SetWriteDeadline(t time.Time) error        { return c.conn.SetWriteDeadline(t) }

func certPool(cert tls.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	return pool
}

// selfSignedCert builds a throwaway certificate for 127.0.0.1. The client gets
// it through a pool, so the chain is really verified instead of skipped.
func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "melonarc-spike", Organization: []string{"MelonARC"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf = leaf
	return cert, nil
}
