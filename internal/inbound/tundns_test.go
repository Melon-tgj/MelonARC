package inbound

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/outbound"
)

// constResolver answers every name with the same address. The pool tests do not
// care what a name resolves to — only whether the responder can hand out a token
// for it — and a resolver that never fails keeps the negative paths out of the
// way.
type constResolver struct{ ips []net.IP }

func (r constResolver) Resolve(context.Context, string) (dns.Result, error) {
	return dns.Result{IPs: r.ips}, nil
}

// poolRefs returns how many sessions hold addr, and whether the pool still maps
// it at all.
func poolRefs(pool *dnsResponder, addr ip4) (refs int, mapped bool) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	entry, ok := pool.byIP[addr]
	return entry.refs, ok
}

// poolSizeOf counts the live entries of the pool.
func poolSizeOf(pool *dnsResponder) int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return len(pool.byIP)
}

// fillNames allocates n names that are all fresh at the current clock.
func fillNames(t *testing.T, pool *dnsResponder, from, n int) map[ip4]string {
	t.Helper()
	out := make(map[ip4]string, n)
	for i := from; i < from+n; i++ {
		name := fmt.Sprintf("filler%d.test", i)
		addr, ok := pool.allocate(name)
		if !ok {
			t.Fatalf("the pool refused filler %d while %d of %d tokens were taken", i, len(out), poolSize)
		}
		out[addr] = name
	}
	return out
}

// TestTUNFakeIPPoolRefusesToReassignALiveLease is the first half of the lease
// contract: a full pool of unexpired leases fails the next allocation instead of
// taking somebody else's token, and the 253 mappings stay exactly as they were.
func TestTUNFakeIPPoolRefusesToReassignALiveLease(t *testing.T) {
	metrics := NewMetrics(0)
	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,DIRECT"},
		leaves: map[string]outbound.Dialer{"DIRECT": &fakeSharedDialer{}},
	})
	tun := newTunEnv(t, TUNOptions{
		Handler: env.handler,
		Resolver: constResolver{
			ips: []net.IP{net.IPv4(127, 0, 0, 1)},
		},
		Metrics: metrics,
	})
	pool := tun.svc.dns

	// Fill every slot. The clock never moves, so nothing is reclaimable.
	assigned := fillNames(t, pool, 0, poolSize)
	if got := poolSizeOf(pool); got != poolSize {
		t.Fatalf("pool holds %d entries after %d allocations", got, poolSize)
	}
	before := make(map[ip4]string, len(assigned))
	for addr, name := range assigned {
		before[addr] = name
	}

	// The 254th name cannot be served.
	addr, ok := pool.allocate("overflow.test")
	if ok {
		t.Fatalf("a full pool handed out %s for a %dth name", addr.String(), poolSize+1)
	}
	if addr != (ip4{}) {
		t.Fatalf("a refused allocation returned %s", addr.String())
	}

	// Not one of the 253 mappings moved: each still answers with its own name.
	for ip, name := range before {
		got, ok := pool.nameFor(ip)
		if !ok || got != name {
			t.Fatalf("token %s now maps to %q (present %v), want %q", ip.String(), got, ok, name)
		}
	}
	if got := poolSizeOf(pool); got != poolSize {
		t.Fatalf("pool holds %d entries after the refused allocation, want %d", got, poolSize)
	}

	// A question for the name the pool could not serve is answered SERVFAIL,
	// and the counter says how often that happened.
	if got := metrics.Snapshot().NameAddressExhausted; got != 1 {
		t.Fatalf("exhaustion counter = %d after one refused allocation, want 1", got)
	}
	rcode := askTUNDNS(t, tun, "overflow.test")
	if rcode != dns.RcodeServFail {
		t.Fatalf("a name the full pool cannot serve was answered with rcode %d, want SERVFAIL", rcode)
	}
	if got := metrics.Snapshot().NameAddressExhausted; got != 2 {
		t.Fatalf("exhaustion counter = %d after the SERVFAIL answer, want 2", got)
	}

	// Nothing was disturbed on the way out either.
	for ip, name := range before {
		if got, ok := pool.nameFor(ip); !ok || got != name {
			t.Fatalf("token %s maps to %q (present %v) after a SERVFAIL, want %q", ip.String(), got, ok, name)
		}
	}
}

// TestTUNFakeIPPoolKeepsALeaseInUse is the second half: a lease that has run out
// while a session still carries traffic to it is neither swept nor reused, and
// becomes reclaimable the moment that session ends.
func TestTUNFakeIPPoolKeepsALeaseInUse(t *testing.T) {
	dialer := &fakeSharedDialer{}
	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,DIRECT"},
		leaves: map[string]outbound.Dialer{"DIRECT": dialer},
	})
	tun := newTunEnv(t, TUNOptions{
		Handler: env.handler,
		Resolver: constResolver{
			ips: []net.IP{net.IPv4(127, 0, 0, 1)},
		},
		// The session has to outlive the lease, or the test would be proving
		// that a session that ended can be reclaimed — which is not the point.
		UDPTimeout: time.Hour,
	})
	pool := tun.svc.dns

	held, ok := pool.allocate("held.test")
	if !ok {
		t.Fatal("the pool refused the first allocation")
	}

	// One UDP session to the token. This is what a client does after it has
	// been given the address by the responder.
	tun.device.inject(appendUDPPacket(nil, testClientIP, held, 42000, 9999, []byte("one")))
	waitUntil(t, "the UDP session to open", func() bool {
		refs, mapped := poolRefs(pool, held)
		return mapped && refs == 1
	})

	// Let the lease run out while the session is idle, then fill the rest of the
	// pool with leases that are still fresh: from here on the only token that is
	// expired is the one in use.
	tun.clock.Advance(fakeIPTTL - time.Minute)
	fillNames(t, pool, 0, poolSize-1)
	tun.clock.Advance(2 * time.Minute)
	now := tun.clock.Now()
	pool.sweep(now)
	if refs, mapped := poolRefs(pool, held); !mapped || refs != 1 {
		t.Fatalf("the sweeper touched a token a session still holds (refs %d, mapped %v)", refs, mapped)
	}
	if name, ok := pool.nameFor(held); !ok || name != "held.test" {
		t.Fatalf("an expired token in use maps to %q (present %v), want held.test", name, ok)
	}

	// The pool is full of live or held tokens, so a new name is refused. This is
	// the case the old allocator served by taking the oldest mapping, which is
	// exactly the mapping this session is using.
	if addr, ok := pool.allocate("overflow.test"); ok {
		t.Fatalf("the pool handed out %s to another name while every token was live or held", addr.String())
	}

	// End the session the way a failed write or a shutdown ends it, and give the
	// last reference back.
	removeUDPFlow(t, tun.svc, held, 42000)
	waitUntil(t, "the reference to be given back", func() bool {
		refs, mapped := poolRefs(pool, held)
		return refs == 0 && !mapped
	})
	if _, ok := pool.nameFor(held); ok {
		t.Fatal("a released, expired token is still mapped")
	}

	// The token is free again, and it is the only free one: 252 leases are still
	// live. The next name must get exactly the address the session released.
	next, ok := pool.allocate("late.test")
	if !ok {
		t.Fatal("the pool refused an allocation after the token was released")
	}
	if next != held {
		t.Fatalf("the released token %s was not reused; the next name got %s", held.String(), next.String())
	}
}

// TestTUNFakeIPTCPStreamHoldsItsLease checks the same reference counting on the
// stream side: a TCP flow claims the token when it opens and gives it back when
// it closes, so a connection keeps its destination name for its whole lifetime.
func TestTUNFakeIPTCPStreamHoldsItsLease(t *testing.T) {
	local, far := net.Pipe()
	t.Cleanup(func() { _ = far.Close() })
	dialer := &fakeDialer{streamFn: func(string) (net.Conn, error) { return local, nil }}
	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,DIRECT"},
		leaves: map[string]outbound.Dialer{"DIRECT": dialer},
	})
	tun := newTunEnv(t, TUNOptions{Handler: env.handler})
	pool := tun.svc.dns

	held, ok := pool.allocate("stream.test")
	if !ok {
		t.Fatal("the pool refused the allocation")
	}

	peer := &synthTCP{t: t, dev: tun.device, src: testClientIP, dst: held, sport: 41000, dport: 443, seq: 7000}
	peer.handshake(t)
	waitUntil(t, "the flow to claim its name address", func() bool {
		refs, mapped := poolRefs(pool, held)
		return mapped && refs == 1
	})

	// The lease runs out under the connection; the mapping stays because the
	// flow is still open, and the packet that follows still resolves to a name.
	tun.clock.Advance(fakeIPTTL + time.Second)
	pool.sweep(tun.clock.Now())
	if refs, mapped := poolRefs(pool, held); !mapped || refs != 1 {
		t.Fatalf("the sweeper released a name address a flow holds (refs %d, mapped %v)", refs, mapped)
	}
	if name, ok := pool.nameFor(held); !ok || name != "stream.test" {
		t.Fatalf("token in use by a stream maps to %q (present %v)", name, ok)
	}

	// The client closes its side and the far end of the upstream goes away: the
	// relay ends, the flow closes with it, and the token is released.
	peer.send(tcpFlagFIN|tcpFlagACK, nil, 0)
	_ = far.Close()
	waitUntil(t, "the flow to release its name address", func() bool {
		refs, mapped := poolRefs(pool, held)
		return refs == 0 && !mapped
	})
	if dialed := dialer.Streams(); len(dialed) != 1 || dialed[0] != "stream.test:443" {
		t.Fatalf("the flow dialed %v, want the name address mapped back to stream.test:443", dialed)
	}
}

// askTUNDNS sends one A question through the device's DNS path and returns the
// response code, so a test can assert on what the client would actually see.
func askTUNDNS(t *testing.T, tun *tunEnv, name string) int {
	t.Helper()
	from := len(tun.device.written())
	query := dnsQuery(t, name, dns.QueryTypeA)
	tun.device.inject(appendUDPPacket(nil, testClientIP, testDeviceIP, 43000, 53, query))
	_, answer := waitPacket(t, tun.device, from, func(pkt ipv4Packet) bool {
		return pkt.Protocol == protoUDP && pkt.Src == testDeviceIP && pkt.Dst == testClientIP
	})
	seg, err := decodeUDP(answer.Payload)
	if err != nil {
		t.Fatalf("decode dns answer: %v", err)
	}
	if len(seg.Data) < 12 {
		t.Fatalf("dns answer is %d bytes", len(seg.Data))
	}
	// The question section has to come back verbatim, or the client discards the
	// answer; that is also what makes the rcode trustworthy here.
	if got := binary.BigEndian.Uint16(seg.Data[6:8]); got != 0 && got != 1 {
		t.Fatalf("dns answer has %d answers, want 0 or 1", got)
	}
	return int(seg.Data[3] & 0x0f)
}

// removeUDPFlow ends one session through the dispatcher's removal path, which is
// the same release the idle reaper performs. The flow is identified the way the
// device sees it, so the test never reaches into the session table for a pointer.
func removeUDPFlow(t *testing.T, svc *TUNService, dst ip4, sport uint16) {
	t.Helper()
	flow := udpFlow{src: testClientIP, dst: dst, sport: sport, dport: 9999}
	svc.udp.mu.Lock()
	session := svc.udp.sessions[flow]
	svc.udp.mu.Unlock()
	if session == nil {
		t.Fatalf("no UDP session for %s:%d", dst.String(), sport)
	}
	svc.udp.remove(flow, session)
}
