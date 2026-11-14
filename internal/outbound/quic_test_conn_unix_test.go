//go:build !windows

package outbound

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// This sandbox blocks sendto on an unconnected datagram socket, which is how
// QUIC normally writes: quic-go hands a single socket to every peer it talks
// to. A connected socket may still use sendmsg (the name argument is ignored),
// so the QUIC tests run over sockets that are connected to their one peer.
//
// The hook below changes the dial used by the package's QUIC outbounds for
// every test in this package. Production keeps the default dial, which creates
// a socket per connection and can use GSO and ECN.
func init() {
	dialQUICAddr = dialQUICConnected
}

// connectedPacketConn adapts a datagram socket that has one peer: reads report
// that peer and writes go out on the connected socket.
type connectedPacketConn struct {
	pc   *net.UDPConn
	peer *net.UDPAddr

	mu sync.Mutex
}

func (c *connectedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, from, err := c.pc.ReadFromUDP(b)
	if err != nil {
		return 0, nil, err
	}
	c.mu.Lock()
	if c.peer == nil {
		c.peer = from
		if err := connectUDPPeer(c.pc, from); err != nil {
			c.mu.Unlock()
			return 0, nil, err
		}
	}
	peer := c.peer
	c.mu.Unlock()
	return n, peer, nil
}

func (c *connectedPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.pc.Write(b) }
func (c *connectedPacketConn) Close() error                              { return c.pc.Close() }
func (c *connectedPacketConn) LocalAddr() net.Addr                       { return c.pc.LocalAddr() }
func (c *connectedPacketConn) SetDeadline(t time.Time) error             { return c.pc.SetDeadline(t) }
func (c *connectedPacketConn) SetReadDeadline(t time.Time) error         { return c.pc.SetReadDeadline(t) }
func (c *connectedPacketConn) SetWriteDeadline(t time.Time) error        { return c.pc.SetWriteDeadline(t) }
func (c *connectedPacketConn) SetReadBuffer(n int) error                 { return c.pc.SetReadBuffer(n) }
func (c *connectedPacketConn) SetWriteBuffer(n int) error                { return c.pc.SetWriteBuffer(n) }

// dialQUICConnected dials over a socket that is connected before the handshake
// starts, which is what makes the first flight possible here.
func dialQUICConnected(ctx context.Context, server string, tlsConfig *tls.Config, conf *quic.Config) (*quic.Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	pc, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	wrapped := &clientPacketConn{pc: pc, peer: addr}
	conn, err := quic.Dial(ctx, wrapped, addr, tlsConfig, conf)
	if err != nil {
		_ = wrapped.Close()
		return nil, err
	}
	return conn, nil
}

// clientPacketConn is the client side of connectedPacketConn: the peer is known
// from the start, so there is nothing to learn.
type clientPacketConn struct {
	pc   *net.UDPConn
	peer *net.UDPAddr
}

func (c *clientPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.pc.Read(b)
	if err != nil {
		return 0, nil, err
	}
	return n, c.peer, nil
}

func (c *clientPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.pc.Write(b) }
func (c *clientPacketConn) Close() error                              { return c.pc.Close() }
func (c *clientPacketConn) LocalAddr() net.Addr                       { return c.pc.LocalAddr() }
func (c *clientPacketConn) SetDeadline(t time.Time) error             { return c.pc.SetDeadline(t) }
func (c *clientPacketConn) SetReadDeadline(t time.Time) error         { return c.pc.SetReadDeadline(t) }
func (c *clientPacketConn) SetWriteDeadline(t time.Time) error        { return c.pc.SetWriteDeadline(t) }
func (c *clientPacketConn) SetReadBuffer(n int) error                 { return c.pc.SetReadBuffer(n) }
func (c *clientPacketConn) SetWriteBuffer(n int) error                { return c.pc.SetWriteBuffer(n) }

// testQUICPacketConn is the socket a test QUIC server listens on.
func testQUICPacketConn(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	return &connectedPacketConn{pc: pc}
}
