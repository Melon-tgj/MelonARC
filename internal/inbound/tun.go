package inbound

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// Defaults of the TUN inbound. It is off unless the configuration says
// otherwise: creating a device and changing routes is a privileged operation,
// and a configuration from an earlier stage must not acquire one by surprise.
const (
	DefaultTUNName       = "melonarc0"
	DefaultTUNAddress    = "198.18.0.1/24"
	DefaultTUNMTU        = 1500
	DefaultTUNUDPTimeout = 30 * time.Second

	// fakeIPPrefix is the /24 the DNS responder allocates name addresses from.
	// It is deliberately separate from the device prefix: a fake address is
	// never dialled, it is only a token that maps back to a name.
	fakeIPPrefix = "198.18.1.0/24"

	// maxTUNPacket is the largest raw IP packet the read loop accepts.
	maxTUNPacket = 65535
	// maxUDPSessions bounds the TUN session table. A long-running TUN sees a
	// lot of one-off destinations; without a bound the table is a leak.
	maxUDPSessions = 512
)

// tunDevice is the platform boundary of the TUN inbound. A read returns one raw
// IP packet, or (0, nil) when the device was idle and the caller should check
// for shutdown. A write injects one raw IP packet towards the kernel.
type tunDevice interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
	Name() string
	MTU() int
}

// deviceConfig is the platform-independent description of a TUN device. The
// build-tagged openDevice turns it into a device the packet loop can read.
type deviceConfig struct {
	Name    string
	Address string // host address with prefix, for example 198.18.0.1/24
	MTU     int
	Routes  []string
}

// TUNOptions configures a TUN inbound. Device is the platform boundary: a test
// supplies an in-memory device, and the daemon leaves it nil so openDevice
// creates and configures a real one.
type TUNOptions struct {
	Name       string
	Address    string
	MTU        int
	Routes     []string
	UDPTimeout time.Duration
	Handler    *Handler
	// Resolver answers intercepted DNS questions and, through the DIRECT
	// dialer, every name a TUN destination maps to. It is the resolver the
	// service starts with; a reload replaces it through Resolvers.
	Resolver Resolver
	// Resolvers is the shared holder the service reads the current resolver
	// from. The device is created once and never rebuilt by a reload, so the
	// resolver it answers with has to be looked up per query. Nil wraps
	// Resolver in a holder of its own, which is what a test wants and what a
	// daemon without a reload would use.
	Resolvers *ResolverHolder
	Metrics   *Metrics
	Logger    *slog.Logger

	// Device is nil in production. It is an injection point, not a test branch:
	// the packet loop never behaves differently because of it.
	Device tunDevice
	// Now supplies the clock for session expiry; nil means time.Now.
	Now func() time.Time
}

// TUNService owns one TUN device and the packet loop that reads it. It is the
// third kind of inbound: HTTP and SOCKS5 accept sockets, this one accepts raw IP
// packets and hands each destination to the same Handler pipeline.
type TUNService struct {
	dev       tunDevice
	handler   *Handler
	resolvers *ResolverHolder
	metrics   *Metrics
	logger    *slog.Logger
	local     ip4
	mtu       int
	now       func() time.Time

	ctx    context.Context
	cancel context.CancelFunc

	writeMu sync.Mutex
	mu      sync.Mutex
	closed  bool
	wg      sync.WaitGroup

	tcp *tcpStack
	udp *udpDispatcher
	dns *dnsResponder

	closeOnce sync.Once
	closeErr  error
}

// NewTUN opens and configures a device, then starts the packet loop. A failure
// at any point closes the device and returns an error: the daemon never keeps a
// half-configured interface behind.
func NewTUN(opts TUNOptions) (*TUNService, error) {
	if opts.Handler == nil {
		return nil, errors.New("inbound: a TUN inbound needs a routing handler")
	}
	name := opts.Name
	if name == "" {
		name = DefaultTUNName
	}
	address := opts.Address
	if address == "" {
		address = DefaultTUNAddress
	}
	mtu := opts.MTU
	if mtu == 0 {
		mtu = DefaultTUNMTU
	}
	addr, network, err := net.ParseCIDR(address)
	if err != nil {
		return nil, fmt.Errorf("inbound: TUN address %q: %w", address, err)
	}
	if addr.To4() == nil {
		return nil, fmt.Errorf("inbound: TUN address %q is not IPv4", address)
	}
	routes := opts.Routes
	if len(routes) == 0 {
		ones, _ := network.Mask.Size()
		routes = []string{fmt.Sprintf("%s/%d", network.IP.String(), ones), fakeIPPrefix}
	}
	timeout := opts.UDPTimeout
	if timeout <= 0 {
		timeout = DefaultTUNUDPTimeout
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	dev := opts.Device
	if dev == nil {
		dev, err = openDevice(deviceConfig{Name: name, Address: address, MTU: mtu, Routes: routes})
		if err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	resolvers := opts.Resolvers
	if resolvers == nil {
		resolvers = NewResolverHolder(opts.Resolver)
	}
	s := &TUNService{
		dev:       dev,
		handler:   opts.Handler,
		resolvers: resolvers,
		metrics:   opts.Metrics,
		logger:    loggerOrDiscard(opts.Logger),
		local:     toIP4(addr),
		mtu:       mtu,
		now:       now,
		ctx:       ctx,
		cancel:    cancel,
	}
	deviceMTU := dev.MTU()
	if deviceMTU > 0 {
		s.mtu = deviceMTU
	}
	s.metrics.listen(protocolTUN)
	s.dns = newDNSResponder(s)
	s.tcp = newTCPStack(s)
	s.udp = newUDPDispatcher(s, timeout)
	s.spawn(s.readLoop)
	s.spawn(s.reapLoop)
	s.logger.Info("tun inbound listening", "device", dev.Name(), "address", address, "mtu", s.mtu,
		"routes", routes, "udp_timeout", timeout)
	return s, nil
}

// Protocol names the listener for logs and metrics.
func (s *TUNService) Protocol() string { return protocolTUN }

// resolver returns the resolver a query must use right now. A reload replaces it
// in the shared holder, which is the only way the DNS answer of a device that
// was opened once can follow a configuration change.
func (s *TUNService) resolver() Resolver { return s.resolvers.Load() }

// Name reports the device the service owns.
func (s *TUNService) Name() string { return s.dev.Name() }

// spawn runs fn under the service wait group. Close sets closed first, so no
// goroutine can be added after the wait has begun.
func (s *TUNService) spawn(fn func()) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		fn()
	}()
}

// readLoop takes packets from the device until it is closed. A failed read is
// retried with the same bounded backoff a socket listener uses, so a transient
// error does not spin a core.
func (s *TUNService) readLoop() {
	buf := make([]byte, maxTUNPacket)
	backoff := time.Duration(0)
	for {
		if s.ctx.Err() != nil {
			return
		}
		n, err := s.dev.Read(buf)
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			backoff = nextBackoff(backoff)
			s.logger.Warn("tun read failed", "device", s.dev.Name(), "error", err, "retry_in", backoff)
			select {
			case <-time.After(backoff):
			case <-s.ctx.Done():
				return
			}
			continue
		}
		backoff = 0
		if n == 0 {
			continue
		}
		s.dispatch(buf[:n])
	}
}

// dispatch classifies one packet. Payloads alias the read buffer, so every path
// that keeps one past this call makes its own copy.
func (s *TUNService) dispatch(raw []byte) {
	pkt, err := decodeIPv4(raw)
	if err != nil {
		s.logger.Debug("tun packet dropped", "error", err)
		return
	}
	switch pkt.Protocol {
	case protoTCP:
		s.tcp.handle(pkt)
	case protoUDP:
		seg, err := decodeUDP(pkt.Payload)
		if err != nil {
			s.logger.Debug("tun udp packet dropped", "error", err)
			return
		}
		if seg.DstPort == 53 && s.resolver() != nil {
			// A lookup may take seconds. Keeping it off the read loop means one
			// slow name cannot delay every TCP connection on the device.
			query := append([]byte(nil), seg.Data...)
			p := pkt
			s.spawn(func() { s.dns.handle(p, seg, query) })
			return
		}
		s.udp.handle(pkt, seg)
	case protoICMP:
		reply, err := appendICMPEchoReply(nil, pkt.Dst, pkt.Src, pkt.Payload)
		if err == nil {
			_ = s.writePacket(reply)
		}
	default:
		s.logger.Debug("tun packet dropped", "protocol", pkt.Protocol)
	}
}

// reapLoop expires idle UDP sessions. The interval is a fraction of the timeout
// so a session does not outlive its limit by a whole extra period.
func (s *TUNService) reapLoop() {
	interval := s.udp.timeout / 4
	if interval < time.Second {
		interval = time.Second
	}
	if interval > 10*time.Second {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := s.now()
			s.udp.expire(now)
			s.dns.sweep(now)
		case <-s.ctx.Done():
			return
		}
	}
}

// writePacket injects one packet towards the kernel. Every stack writes through
// this one lock, so two replies can never interleave on the device.
func (s *TUNService) writePacket(p []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.dev.Write(p)
	return err
}

// destinationForSession turns a packet's IP and port into the target the rule
// pipeline sees. An address from the fake pool maps back to the name the DNS
// responder handed out, so domain rules and the DIRECT resolver both see a name
// rather than a token address.
//
// A name address is claimed on the way, so the mapping cannot be reclaimed from
// under a stream that is already carrying traffic to it. The claim is returned
// rather than kept here: the session that opens owns it, and the one that ends
// has to give it back. A zero value means the destination was a literal address
// and there is nothing to release.
func (s *TUNService) destinationForSession(pkt ipv4Packet, port uint16) (target outbound.Target, claimed ip4, ok bool) {
	if !s.dns.isFake(pkt.Dst) {
		return outbound.Target{Host: pkt.Dst.String(), Port: port}, ip4{}, true
	}
	name, ok := s.dns.claim(pkt.Dst)
	if !ok {
		s.logger.Debug("tun session for an expired name address dropped", "address", pkt.Dst.String())
		return outbound.Target{}, ip4{}, false
	}
	return outbound.Target{Host: name, Port: port}, pkt.Dst, true
}

// releaseClaim gives back the reference destinationForSession took.
func (s *TUNService) releaseClaim(addr ip4) {
	if addr == (ip4{}) {
		return
	}
	s.dns.release(addr)
}

// Close stops the packet loop, closes the device and drains the sessions and
// connections that were in flight. A second call returns the result of the
// first.
func (s *TUNService) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.cancel()
		if err := s.dev.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.closeErr = err
		}
		s.udp.close()
		s.tcp.close()
		done := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			if s.closeErr == nil {
				s.closeErr = ctx.Err()
			}
		}
	})
	return s.closeErr
}
