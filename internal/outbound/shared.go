package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

// maxSharedPayload is the largest datagram a shared association will read. A
// UDP datagram cannot carry more than this on IPv4.
const maxSharedPayload = 65507

// SharedPacketConn is one datagram association that serves any number of
// destinations. WriteTo names the destination for each payload and ReadFrom
// reports where a payload came from, so one association can be reused by an
// inbound that sees raw IP packets (where there is no per-destination header to
// demultiplex on).
type SharedPacketConn interface {
	ReadFrom(p []byte) (int, Target, error)
	WriteTo(payload []byte, destination Target) (int, error)
	Close() error
}

// SharedDialer is a Dialer that can open a shared association. A dialer that
// does not implement it still works through DialPacket; the inbound layer wraps
// that single-destination connection into a SharedPacketConn.
//
// The method has its own name because SOCKS5.DialUDP already returns the
// concrete *UDPRelay its callers want; Go does not allow a covariant return
// type, so the shared view is a second, one-line method over the same object.
type SharedDialer interface {
	DialSharedUDP(ctx context.Context) (SharedPacketConn, error)
}

// Compile-time checks that the SOCKS5 association is exactly a shared one.
var (
	_ SharedPacketConn = (*UDPRelay)(nil)
	_ SharedDialer     = (*SOCKS5)(nil)
	_ SharedDialer     = (*Direct)(nil)
)

// DialSharedUDP implements SharedDialer for DIRECT.
//
// One relay object carries every destination, but each destination gets its own
// connected UDP socket underneath. A connected socket can be written with Write
// and only accepts replies from its peer, which is both cheaper and safer than
// an unconnected socket: no sendto to an arbitrary address, and a datagram from
// an unrelated host cannot enter the association. Names go through the
// injected Lookup (the DNS layer), so DIRECT uses the same [Host] table, cache
// and upstream answers as a stream dial.
func (d *Direct) DialSharedUDP(ctx context.Context) (SharedPacketConn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return &directRelay{
		ctx:      ctx,
		direct:   d,
		dests:    make(map[string]*directRelayDestination),
		incoming: make(chan directDatagram, 128),
		done:     make(chan struct{}),
	}, nil
}

type directDatagram struct {
	payload []byte
	from    Target
}

type directRelayDestination struct {
	conn      *net.UDPConn
	requested Target
}

type directRelay struct {
	ctx      context.Context
	direct   *Direct
	mu       sync.Mutex
	dests    map[string]*directRelayDestination
	incoming chan directDatagram
	done     chan struct{}
	closed   bool
	once     sync.Once
}

// WriteTo sends payload to destination, opening its socket on first use.
func (r *directRelay) WriteTo(payload []byte, destination Target) (int, error) {
	key := destination.String()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return 0, net.ErrClosed
	}
	dest := r.dests[key]
	r.mu.Unlock()
	if dest == nil {
		addr, err := r.resolve(r.ctx, destination)
		if err != nil {
			return 0, err
		}
		conn, err := net.DialUDP("udp4", nil, addr)
		if err != nil {
			return 0, fmt.Errorf("direct: open a datagram association to %s: %w", destination, err)
		}
		candidate := &directRelayDestination{conn: conn, requested: destination}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			_ = conn.Close()
			return 0, net.ErrClosed
		}
		if existing := r.dests[key]; existing != nil {
			r.mu.Unlock()
			_ = conn.Close()
			dest = existing
		} else {
			r.dests[key] = candidate
			r.mu.Unlock()
			dest = candidate
			go r.readDestination(dest)
		}
	}
	n, err := dest.conn.Write(payload)
	return n, err
}

// resolve turns a destination into the address of a connected socket. A name is
// resolved by the injected lookup, which is the daemon's DNS resolver; a nil
// lookup falls back to the system resolver exactly as Direct.open does.
func (r *directRelay) resolve(ctx context.Context, destination Target) (*net.UDPAddr, error) {
	if destination.IsIP() {
		ip := net.ParseIP(destination.Host).To4()
		if ip == nil {
			return nil, errors.New("direct: a shared datagram association needs an IPv4 destination")
		}
		return &net.UDPAddr{IP: ip, Port: int(destination.Port)}, nil
	}
	var ips []net.IP
	if r.direct.Lookup != nil {
		var err error
		ips, err = r.direct.Lookup(ctx, destination.Host)
		if err != nil {
			return nil, fmt.Errorf("direct: resolve %s: %w", destination.Host, err)
		}
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, destination.Host)
		if err != nil {
			return nil, fmt.Errorf("direct: resolve %s: %w", destination.Host, err)
		}
		for _, addr := range addrs {
			ips = append(ips, addr.IP)
		}
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return &net.UDPAddr{IP: v4, Port: int(destination.Port)}, nil
		}
	}
	return nil, fmt.Errorf("direct: resolve %s: the answer carries no IPv4 address", destination.Host)
}

// readDestination carries one destination's replies into the shared stream.
func (r *directRelay) readDestination(dest *directRelayDestination) {
	buf := make([]byte, maxSharedPayload)
	for {
		n, err := dest.conn.Read(buf)
		if err != nil {
			return
		}
		payload := append([]byte(nil), buf[:n]...)
		select {
		case r.incoming <- directDatagram{payload: payload, from: dest.requested}:
		case <-r.done:
			return
		}
	}
}

// ReadFrom reads the next reply from any destination of this association.
func (r *directRelay) ReadFrom(p []byte) (int, Target, error) {
	select {
	case d := <-r.incoming:
		return copy(p, d.payload), d.from, nil
	case <-r.done:
		return 0, Target{}, net.ErrClosed
	}
}

// Close closes every destination socket and wakes a blocked ReadFrom.
func (r *directRelay) Close() error {
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		dests := make([]*net.UDPConn, 0, len(r.dests))
		for _, dest := range r.dests {
			dests = append(dests, dest.conn)
		}
		r.mu.Unlock()
		close(r.done)
		for _, conn := range dests {
			_ = conn.Close()
		}
	})
	return nil
}
