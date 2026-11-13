package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// DefaultTimeout bounds a dial or handshake whose context carries no deadline.
const DefaultTimeout = 10 * time.Second

// Errors reported by dialers.
var (
	// ErrUnsupported is returned by a dialer whose protocol this build does
	// not implement.
	ErrUnsupported = errors.New("outbound: protocol is not implemented")
	// ErrRejected is returned by the REJECT action.
	ErrRejected = errors.New("outbound: target is rejected")
	// ErrUnknownDialer is returned for a name that has no dialer.
	ErrUnknownDialer = errors.New("outbound: no dialer for target")
	// ErrInvalidAddress is returned for an address that is not host:port.
	ErrInvalidAddress = errors.New("outbound: invalid address")
	// ErrInvalidOption is returned for a [Proxy] argument the protocol does
	// not understand.
	ErrInvalidOption = errors.New("outbound: invalid proxy option")
)

// Dialer is the shared outbound abstraction. Every protocol implements it, and
// the rest of the core only ever names a dialer, never a protocol: a rule
// resolves to a name, the registry resolves the name to a dialer, and the
// inbound layer calls DialContext or DialPacket without knowing what sits
// behind it.
type Dialer interface {
	// DialContext opens a stream to address, which is "host:port". A name is
	// resolved by whoever can resolve it: the peer for a proxy protocol, the
	// local resolver for a direct connection. The call honours ctx
	// cancellation and the dialer's own timeout.
	DialContext(ctx context.Context, address string) (net.Conn, error)

	// DialPacket opens a datagram association with address. The returned
	// connection carries payloads to and from that one destination.
	DialPacket(ctx context.Context, address string) (PacketConn, error)
}

// PacketConn is a datagram association with a single destination: reads return
// payloads that came from it, writes go to it, and the framing the protocol
// needs is applied underneath. It is the UDP counterpart of net.Conn so the
// inbound and TUN paths can treat both transports alike.
type PacketConn interface {
	net.Conn
}

// Target is a destination address: an IP literal, or a name the peer is left to
// resolve. The host and the port are kept apart so a name never has to be split
// at a colon again.
//
// Target implements net.Addr so datagram APIs can report where a payload came
// from. The network name is the project-wide "melonarc" because a target may be
// reached over either transport.
type Target struct {
	Host string
	Port uint16
}

// ParseTarget reads "host:port". An IPv6 literal must carry brackets, as
// net.SplitHostPort expects.
func ParseTarget(address string) (Target, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return Target{}, fmt.Errorf("%w: %q: %v", ErrInvalidAddress, address, err)
	}
	if host == "" {
		return Target{}, fmt.Errorf("%w: %q has an empty host", ErrInvalidAddress, address)
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return Target{}, fmt.Errorf("%w: %q has whitespace in the host", ErrInvalidAddress, address)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return Target{}, fmt.Errorf("%w: %q has an invalid port", ErrInvalidAddress, address)
	}
	return Target{Host: host, Port: uint16(n)}, nil
}

// String renders the target as "host:port", bracketing an IPv6 literal.
func (t Target) String() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
}

// Network implements net.Addr.
func (t Target) Network() string { return "melonarc" }

// IsIP reports whether the host is an IP literal rather than a name.
func (t Target) IsIP() bool { return net.ParseIP(t.Host) != nil }

// setConnDeadline applies the caller's deadline to a connection that is about
// to run a protocol handshake. Without a deadline in the context the dialer's
// own timeout is used, so a silent peer cannot block a handshake forever.
func setConnDeadline(conn net.Conn, ctx context.Context, fallback time.Duration) {
	deadline := time.Time{}
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else if fallback > 0 {
		deadline = time.Now().Add(fallback)
	}
	_ = conn.SetDeadline(deadline)
}

// guardConn closes conn if ctx is cancelled while a handshake is in progress,
// which is what makes a cancelled dial return promptly instead of waiting for
// the timeout. The returned release function stops the guard; when it reports
// false the connection has already been closed and must not be handed to the
// caller.
func guardConn(ctx context.Context, conn net.Conn) (release func() bool) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return func() bool { return stop() }
}

// validateServer checks the proxy endpoint shared by the tunnelling protocols.
func validateServer(host string, port int) error {
	if strings.TrimSpace(host) == "" {
		return errors.New("outbound: proxy has no server")
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return fmt.Errorf("outbound: server %q contains whitespace", host)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("outbound: port %d is outside 1-65535", port)
	}
	return nil
}
