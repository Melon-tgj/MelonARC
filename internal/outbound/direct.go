package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// LookupFunc resolves a name into the addresses a direct connection may use. It
// is how the DNS layer's cache, [Host] table and request coalescing reach the
// dialer without this package depending on the resolver: the daemon injects the
// resolver's Lookup method, a test injects a function, and a nil function leaves
// the system resolver in charge.
type LookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// Direct opens connections from the local host: the DIRECT action. It is the
// only dialer that always resolves names itself, because there is no peer to
// hand the name to.
type Direct struct {
	// Timeout bounds a dial whose context has no deadline. Zero means
	// DefaultTimeout.
	Timeout time.Duration
	// Lookup resolves a name when the target is not an IP literal. Nil means
	// the system resolver, which net.Dialer already uses.
	Lookup LookupFunc
}

// NewDirect returns the DIRECT dialer.
func NewDirect() *Direct { return &Direct{} }

// DialContext implements Dialer.
func (d *Direct) DialContext(ctx context.Context, address string) (net.Conn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	conn, err := d.open(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("direct: %w", err)
	}
	return conn, nil
}

// DialPacket implements Dialer. The returned connection is a connected UDP
// socket, so it reads only from the destination it was opened for.
func (d *Direct) DialPacket(ctx context.Context, address string) (PacketConn, error) {
	target, err := ParseTarget(address)
	if err != nil {
		return nil, err
	}
	conn, err := d.open(ctx, "udp", target)
	if err != nil {
		return nil, fmt.Errorf("direct: %w", err)
	}
	packet, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("direct: udp dial returned a non datagram connection")
	}
	return packet, nil
}

// open dials target, resolving the name first when a lookup function is
// configured. The resolved addresses are tried in the order the answer listed
// them, which is the preference the resolver reported; the timeout applies to
// each attempt, so a name with many dead addresses can outlast one timeout when
// the context carries no deadline of its own.
func (d *Direct) open(ctx context.Context, network string, target Target) (net.Conn, error) {
	if target.IsIP() || d.Lookup == nil {
		dialer := d.dialer()
		return dialer.DialContext(ctx, network, target.String())
	}
	addrs, err := d.Lookup(ctx, target.Host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", target.Host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: the answer carries no address", target.Host)
	}
	var lastErr error
	for _, ip := range addrs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dialer := d.dialer()
		conn, err := dialer.DialContext(ctx, network,
			net.JoinHostPort(ip.String(), strconv.Itoa(int(target.Port))))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// dialer builds the net.Dialer with the effective timeout.
func (d *Direct) dialer() net.Dialer {
	return net.Dialer{Timeout: d.timeout()}
}

// timeout is the effective dial timeout.
func (d *Direct) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return DefaultTimeout
}

// Reject is the REJECT action: every dial fails, which is how a rule that blocks
// traffic behaves at the dialer level.
type Reject struct{}

// NewReject returns the REJECT dialer.
func NewReject() *Reject { return &Reject{} }

// DialContext implements Dialer.
func (r *Reject) DialContext(context.Context, string) (net.Conn, error) {
	return nil, ErrRejected
}

// DialPacket implements Dialer.
func (r *Reject) DialPacket(context.Context, string) (PacketConn, error) {
	return nil, ErrRejected
}

// Unsupported stands in for a protocol this build does not implement yet. It is
// a dialer rather than a startup error on purpose: a configuration may list
// protocols of later stages, and the honest outcome is a member that never
// becomes healthy, not a daemon that refuses to start.
type Unsupported struct {
	// Protocol is the [Proxy] type that is not implemented.
	Protocol string
}

// DialContext implements Dialer.
func (u *Unsupported) DialContext(context.Context, string) (net.Conn, error) {
	return nil, fmt.Errorf("%w: %s", ErrUnsupported, u.Protocol)
}

// DialPacket implements Dialer.
func (u *Unsupported) DialPacket(context.Context, string) (PacketConn, error) {
	return nil, fmt.Errorf("%w: %s", ErrUnsupported, u.Protocol)
}
