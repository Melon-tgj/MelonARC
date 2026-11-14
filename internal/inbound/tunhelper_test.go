package inbound

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/outbound"
)

// memoryDevice is a TUN device made of two packet queues. It is an injection
// point, not a code path: the service uses exactly the same decoder, dispatcher
// and stacks as it does with a real device.
type memoryDevice struct {
	mu       sync.Mutex
	cond     *sync.Cond
	incoming [][]byte // kernel -> service
	outgoing [][]byte // service -> kernel
	closed   bool
}

func newMemoryDevice() *memoryDevice {
	d := &memoryDevice{}
	d.cond = sync.NewCond(&d.mu)
	return d
}

func (d *memoryDevice) Name() string { return "memtun0" }
func (d *memoryDevice) MTU() int     { return 1500 }

func (d *memoryDevice) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for len(d.incoming) == 0 && !d.closed {
		d.cond.Wait()
	}
	if d.closed {
		return 0, net.ErrClosed
	}
	pkt := d.incoming[0]
	d.incoming = d.incoming[1:]
	return copy(p, pkt), nil
}

func (d *memoryDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, net.ErrClosed
	}
	d.outgoing = append(d.outgoing, append([]byte(nil), p...))
	d.cond.Broadcast()
	return len(p), nil
}

func (d *memoryDevice) Close() error {
	d.mu.Lock()
	d.closed = true
	d.cond.Broadcast()
	d.mu.Unlock()
	return nil
}

func (d *memoryDevice) inject(pkt []byte) {
	d.mu.Lock()
	if !d.closed {
		d.incoming = append(d.incoming, append([]byte(nil), pkt...))
		d.cond.Broadcast()
	}
	d.mu.Unlock()
}

func (d *memoryDevice) written() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([][]byte(nil), d.outgoing...)
}

// waitPacket returns the first packet written after from that matches. It
// polls, so a test never hangs forever on a stack that stopped replying.
func waitPacket(t *testing.T, d *memoryDevice, from int, match func(ipv4Packet) bool) (int, ipv4Packet) {
	t.Helper()
	deadline := time.Now().Add(testDeadline)
	for {
		all := d.written()
		for i := from; i < len(all); i++ {
			pkt, err := decodeIPv4(all[i])
			if err != nil {
				continue
			}
			if match == nil || match(pkt) {
				return i + 1, pkt
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no matching packet after %s (%d packets written)", testDeadline, len(all))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitUntil polls a condition the service updates on its own goroutines.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testDeadline)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// sharedWrite is one payload a shared association was asked to send.
type sharedWrite struct {
	dest    outbound.Target
	payload string
}

type sharedReply struct {
	from    outbound.Target
	payload []byte
}

// memorySharedConn is an in-memory outbound.SharedPacketConn. Replies are fed
// explicitly, so a test can assert both directions without any UDP socket.
type memorySharedConn struct {
	mu      sync.Mutex
	writes  []sharedWrite
	replies chan sharedReply
	closed  chan struct{}
	once    sync.Once
	closeN  atomic.Int32
}

func newMemorySharedConn() *memorySharedConn {
	return &memorySharedConn{replies: make(chan sharedReply, 16), closed: make(chan struct{})}
}

func (c *memorySharedConn) WriteTo(payload []byte, dest outbound.Target) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.mu.Lock()
	c.writes = append(c.writes, sharedWrite{dest: dest, payload: string(payload)})
	c.mu.Unlock()
	return len(payload), nil
}

func (c *memorySharedConn) ReadFrom(p []byte) (int, outbound.Target, error) {
	select {
	case r := <-c.replies:
		return copy(p, r.payload), r.from, nil
	case <-c.closed:
		return 0, outbound.Target{}, net.ErrClosed
	}
}

func (c *memorySharedConn) Close() error {
	c.once.Do(func() {
		c.closeN.Add(1)
		close(c.closed)
	})
	return nil
}

func (c *memorySharedConn) respond(from outbound.Target, payload string) {
	select {
	case c.replies <- sharedReply{from: from, payload: []byte(payload)}:
	case <-c.closed:
	}
}

func (c *memorySharedConn) written() []sharedWrite {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]sharedWrite(nil), c.writes...)
}

// fakeSharedDialer implements outbound.SharedDialer. It counts how many
// associations were opened, which is how a test proves that several
// destinations reused one of them.
type fakeSharedDialer struct {
	mu    sync.Mutex
	conns []*memorySharedConn
}

func (d *fakeSharedDialer) DialContext(context.Context, string) (net.Conn, error) {
	return nil, errors.New("test dialer: streams are not used by this UDP test")
}

func (d *fakeSharedDialer) DialPacket(context.Context, string) (outbound.PacketConn, error) {
	return nil, errors.New("test dialer: the shared association should be used")
}

func (d *fakeSharedDialer) DialSharedUDP(context.Context) (outbound.SharedPacketConn, error) {
	conn := newMemorySharedConn()
	d.mu.Lock()
	d.conns = append(d.conns, conn)
	d.mu.Unlock()
	return conn, nil
}

func (d *fakeSharedDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.conns)
}

func (d *fakeSharedDialer) last() *memorySharedConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.conns) == 0 {
		return nil
	}
	return d.conns[len(d.conns)-1]
}

// tunCountingResolver wraps a real DNS resolver and records every name it is
// asked. The wrapper is used for both rule matching and the DIRECT dialer, so a
// nonzero count proves the TUN path went through the DNS layer.
type tunCountingResolver struct {
	inner *dns.Resolver
	mu    sync.Mutex
	names []string
}

func (r *tunCountingResolver) Resolve(ctx context.Context, host string) (dns.Result, error) {
	r.mu.Lock()
	r.names = append(r.names, host)
	r.mu.Unlock()
	return r.inner.Resolve(ctx, host)
}

func (r *tunCountingResolver) Lookup(ctx context.Context, host string) ([]net.IP, error) {
	r.mu.Lock()
	r.names = append(r.names, host)
	r.mu.Unlock()
	return r.inner.Lookup(ctx, host)
}

func (r *tunCountingResolver) asked() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.names...)
}

func newTunCountingResolver(t *testing.T, hosts map[string][]net.IP) *tunCountingResolver {
	t.Helper()
	resolver, err := dns.New(dns.Options{Hosts: hosts})
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	return &tunCountingResolver{inner: resolver}
}

// dnsQuery builds one A question for name, in the wire format the responder
// parses.
func dnsQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	msg := make([]byte, 12)
	msg[0], msg[1] = 0x12, 0x34
	msg[5] = 1 // QDCOUNT
	for _, label := range splitLabels(name) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = append(msg, byte(qtype>>8), byte(qtype), 0, 1)
	return msg
}

func splitLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			out = append(out, name[start:i])
			start = i + 1
		}
	}
	if start < len(name) {
		out = append(out, name[start:])
	}
	return out
}

// fakeClock is an injectable clock for session expiry tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// lockedBuffer collects debug logs from a service that writes on several
// goroutines, so a failing test can show what the stacks actually did.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// synthTCP is the kernel side of one TCP connection in the in-memory tests. It
// speaks just enough of the protocol to drive a real handshake, send a request
// and acknowledge the response, which is what makes the userspace stack's
// sequence numbers and checksums actually be checked.
type synthTCP struct {
	t     *testing.T
	dev   *memoryDevice
	src   ip4
	dst   ip4
	sport uint16
	dport uint16
	seq   uint32
	ack   uint32
	// ackSet makes the first segment from the stack the baseline. Comparing a
	// random initial sequence number against a zero ack would be wrong half
	// the time, because TCP sequence comparisons are signed 32-bit wraps.
	ackSet bool
	next   int
}

func (p *synthTCP) send(flags uint8, payload []byte, mss uint16) {
	p.dev.inject(appendTCPPacket(nil, p.src, p.dst, p.sport, p.dport, p.seq, p.ack, flags, mss, payload))
	p.seq += uint32(len(payload))
	if flags&tcpFlagSYN != 0 {
		p.seq++
	}
	if flags&tcpFlagFIN != 0 {
		p.seq++
	}
}

// take returns every new segment from the service and advances the cumulative
// acknowledgement to cover all of them.
func (p *synthTCP) take() []tcpSegment {
	all := p.dev.written()
	var out []tcpSegment
	for i := p.next; i < len(all); i++ {
		pkt, err := decodeIPv4(all[i])
		if err != nil || pkt.Protocol != protoTCP || pkt.Src != p.dst || pkt.Dst != p.src {
			continue
		}
		seg, err := decodeTCP(pkt.Payload)
		if err != nil {
			continue
		}
		advance := uint32(len(seg.Data))
		if seg.Flags&tcpFlagSYN != 0 {
			advance++
		}
		if seg.Flags&tcpFlagFIN != 0 {
			advance++
		}
		if !p.ackSet {
			p.ack, p.ackSet = seg.Seq+advance, true
		} else if seqAfter(seg.Seq+advance, p.ack) {
			p.ack = seg.Seq + advance
		}
		out = append(out, seg)
	}
	p.next = len(all)
	return out
}

func (p *synthTCP) waitFor(t *testing.T, what string, match func(tcpSegment) bool) tcpSegment {
	t.Helper()
	deadline := time.Now().Add(testDeadline)
	for {
		for _, seg := range p.take() {
			if match(seg) {
				return seg
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (p *synthTCP) handshake(t *testing.T) {
	t.Helper()
	p.send(tcpFlagSYN, nil, 1460)
	synack := p.waitFor(t, "SYN-ACK", func(seg tcpSegment) bool {
		return seg.Flags&tcpFlagSYN != 0 && seg.Flags&tcpFlagACK != 0
	})
	if synack.Ack != p.seq {
		t.Fatalf("SYN-ACK ack = %d, want %d", synack.Ack, p.seq)
	}
	p.send(tcpFlagACK, nil, 0)
}

// tunEnv bundles a service with the pieces a test needs to inspect it.
type tunEnv struct {
	svc      *TUNService
	device   *memoryDevice
	clock    *fakeClock
	shutdown func()
}

func newTunEnv(t *testing.T, opts TUNOptions) *tunEnv {
	t.Helper()
	dev := newMemoryDevice()
	clock := &fakeClock{now: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
	opts.Device = dev
	opts.Now = clock.Now
	if opts.Logger == nil {
		opts.Logger = testLogger()
	}
	svc, err := NewTUN(opts)
	if err != nil {
		t.Fatalf("NewTUN: %v", err)
	}
	env := &tunEnv{svc: svc, device: dev, clock: clock}
	env.shutdown = func() {
		ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
		defer cancel()
		if err := svc.Close(ctx); err != nil {
			t.Errorf("TUNService.Close: %v", err)
		}
	}
	t.Cleanup(env.shutdown)
	return env
}
