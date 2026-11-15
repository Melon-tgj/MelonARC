package inbound

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/outbound"
)

var (
	testClientIP = ip4{198, 18, 0, 2}
	testOtherIP  = ip4{198, 18, 0, 3}
	testDeviceIP = ip4{198, 18, 0, 1}
	testTargetIP = ip4{198, 18, 0, 9}
)

// TestTUNTCPPipelineLoopback drives a complete TUN exchange on an in-memory
// device: a DNS question is answered with a name address, a TCP connection to
// that address is mapped back to the name, the compiled rules classify the
// name, and the DIRECT dialer resolves it through the DNS layer to reach a real
// local server. The response comes back as IP packets with correct checksums.
func TestTUNTCPPipelineLoopback(t *testing.T) {
	const request = "request\n"
	origin := startTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("hello:" + string(buf[:n])))
	})
	_, portText, err := net.SplitHostPort(origin)
	if err != nil {
		t.Fatalf("split %q: %v", origin, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("port %q: %v", portText, err)
	}

	resolver := newTunCountingResolver(t, map[string][]net.IP{
		"service.test": {net.IPv4(127, 0, 0, 1)},
	})
	direct := &outbound.Direct{Lookup: resolver.Lookup}
	env := newTestEnv(t, envOptions{
		rules: []string{
			"DOMAIN,service.test,DIRECT",
			"IP-CIDR,127.0.0.1/32,DIRECT",
			"FINAL,REJECT",
		},
		leaves:   map[string]outbound.Dialer{"DIRECT": direct},
		resolver: resolver,
	})
	var logs lockedBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tun := newTunEnv(t, TUNOptions{Handler: env.handler, Resolver: resolver, Logger: logger})

	// 1. Ask the device's DNS responder for the name.
	query := dnsQuery(t, "service.test", dns.QueryTypeA)
	tun.device.inject(appendUDPPacket(nil, testClientIP, testDeviceIP, 43000, 53, query))
	index, answer := waitPacket(t, tun.device, 0, func(pkt ipv4Packet) bool {
		return pkt.Protocol == protoUDP && pkt.Src == testDeviceIP && pkt.Dst == testClientIP
	})
	answerSeg, err := decodeUDP(answer.Payload)
	if err != nil {
		t.Fatalf("decode dns answer: %v", err)
	}
	if answerSeg.SrcPort != 53 || answerSeg.DstPort != 43000 || len(answerSeg.Data) < 16 {
		t.Fatalf("dns answer = %+v, %d bytes", answerSeg, len(answerSeg.Data))
	}
	if answerSeg.Data[3]&0x0f != 0 || binary.BigEndian.Uint16(answerSeg.Data[6:8]) != 1 {
		t.Fatalf("dns answer is not one A record: %v", answerSeg.Data[:12])
	}
	token := ip4(answerSeg.Data[len(answerSeg.Data)-4:])
	if !tun.svc.dns.isFake(token) {
		t.Fatalf("dns answer %s is not from the name address range", token.String())
	}
	if name, ok := tun.svc.dns.nameFor(token); !ok || name != "service.test" {
		t.Fatalf("name address %s maps to %q (present: %v)", token.String(), name, ok)
	}

	// 2. Connect to the name address. A real kernel peer is not needed here:
	// synthTCP checks the exact sequence numbers, flags and checksums.
	peer := &synthTCP{
		t:     t,
		dev:   tun.device,
		src:   testClientIP,
		dst:   token,
		sport: 41000,
		dport: uint16(port),
		seq:   5000,
		next:  index,
	}
	peer.handshake(t)
	peer.send(tcpFlagACK|tcpFlagPSH, []byte(request), 0)

	var received string
	deadline := time.Now().Add(testDeadline)
	for !strings.Contains(received, "hello:"+request) {
		for _, seg := range peer.take() {
			received += string(seg.Data)
			if len(seg.Data) > 0 {
				// The userspace stack waits for a cumulative ACK before it
				// considers a write complete, exactly as a real peer would.
				peer.send(tcpFlagACK, nil, 0)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("response through the TUN pipeline = %q, want hello:%q\nlogs:\n%s", received, request, logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 3. The name, not the token address, reached the DNS layer: once for the
	// question, once for address rules and once for the DIRECT dial.
	asked := resolver.asked()
	if len(asked) < 3 {
		t.Fatalf("DNS layer was asked %d times (%v), want at least 3", len(asked), asked)
	}
	for _, name := range asked {
		if name != "service.test" {
			t.Fatalf("DNS layer was asked for %q, want the mapped name", name)
		}
	}

	// 4. A FIN from the client is acknowledged, so the connection can close
	// cleanly instead of hanging until a timeout.
	peer.send(tcpFlagFIN|tcpFlagACK, nil, 0)
	peer.waitFor(t, "FIN acknowledgement", func(seg tcpSegment) bool {
		return seg.Flags&tcpFlagACK != 0
	})
}

// TestTUNUDPSessionsShareOneAssociationAndExpire checks the session table:
// growth, reuse of one shared association across destinations, reply
// demultiplexing, and idle timeout reclamation with the association released.
func TestTUNUDPSessionsShareOneAssociationAndExpire(t *testing.T) {
	dialer := &fakeSharedDialer{}
	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,DIRECT"},
		leaves: map[string]outbound.Dialer{"DIRECT": dialer},
	})
	timeout := 30 * time.Second
	tun := newTunEnv(t, TUNOptions{Handler: env.handler, UDPTimeout: timeout})

	sessionCount := func() int {
		tun.svc.udp.mu.Lock()
		defer tun.svc.udp.mu.Unlock()
		return len(tun.svc.udp.sessions)
	}

	tun.device.inject(appendUDPPacket(nil, testClientIP, testTargetIP, 42000, 9999, []byte("one")))
	waitUntil(t, "the first UDP session", func() bool { return sessionCount() == 1 })
	first := dialer.last()
	if first == nil {
		t.Fatal("no shared association was opened")
	}
	waitUntil(t, "the first payload", func() bool { return len(first.written()) == 1 })
	if got := first.written()[0]; got.payload != "one" || got.dest.Host != testTargetIP.String() {
		t.Fatalf("first write = %+v", got)
	}

	// A second destination from the same source must reuse the association.
	other := ip4{198, 18, 0, 10}
	tun.device.inject(appendUDPPacket(nil, testClientIP, other, 42000, 9999, []byte("two")))
	waitUntil(t, "the second UDP session", func() bool { return sessionCount() == 2 })
	if got := dialer.count(); got != 1 {
		t.Fatalf("%d associations opened for two destinations of one source, want 1", got)
	}
	waitUntil(t, "the second payload", func() bool { return len(first.written()) == 2 })

	// A different source gets its own association, so a reply cannot be
	// delivered to the wrong client.
	tun.device.inject(appendUDPPacket(nil, testOtherIP, testTargetIP, 42001, 9999, []byte("three")))
	waitUntil(t, "the third UDP session", func() bool { return sessionCount() == 3 })
	if got := dialer.count(); got != 2 {
		t.Fatalf("%d associations for two sources, want 2", got)
	}

	// Replies are wrapped back into IP/UDP packets with mirrored addresses.
	first.respond(outbound.Target{Host: testTargetIP.String(), Port: 9999}, "pong-one")
	_, reply := waitPacket(t, tun.device, 0, func(pkt ipv4Packet) bool {
		return pkt.Protocol == protoUDP && pkt.Dst == testClientIP
	})
	replySeg, err := decodeUDP(reply.Payload)
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if replySeg.SrcPort != 9999 || replySeg.DstPort != 42000 || string(replySeg.Data) != "pong-one" {
		t.Fatalf("reply = %+v payload %q", replySeg, replySeg.Data)
	}

	// Idle sessions are reclaimed and their associations closed with the last
	// reference. The clock is injected, so no sleeping is involved.
	tun.clock.Advance(timeout + time.Second)
	tun.svc.udp.expire(tun.clock.Now())
	if got := sessionCount(); got != 0 {
		t.Fatalf("%d sessions left after the timeout, want 0", got)
	}
	waitUntil(t, "the association to close", func() bool { return first.closeN.Load() == 1 })
	tun.svc.udp.mu.Lock()
	relays := len(tun.svc.udp.relays)
	tun.svc.udp.mu.Unlock()
	if relays != 0 {
		t.Fatalf("%d relay states left after all sessions expired", relays)
	}
}

// TestTUNDNSAnswersCoverAAAAAndUnknownNames checks the responder's negative
// paths: a non-A question gets a NODATA answer, and a name the resolver does
// not know gets NXDOMAIN without allocating a name address.
func TestTUNDNSAnswersCoverAAAAAndUnknownNames(t *testing.T) {
	resolver, err := dns.New(dns.Options{
		Hosts: map[string][]net.IP{"known.test": {net.IPv4(127, 0, 0, 1)}},
		Lookup: func(ctx context.Context, host string) ([]net.IP, error) {
			return nil, dns.ErrNotFound
		},
	})
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,DIRECT"},
		leaves: map[string]outbound.Dialer{"DIRECT": &fakeSharedDialer{}},
	})
	tun := newTunEnv(t, TUNOptions{Handler: env.handler, Resolver: resolver})

	ask := func(t *testing.T, from int, name string, qtype uint16) (int, udpSegment) {
		t.Helper()
		query := dnsQuery(t, name, qtype)
		tun.device.inject(appendUDPPacket(nil, testClientIP, testDeviceIP, 43000, 53, query))
		index, pkt := waitPacket(t, tun.device, from, func(pkt ipv4Packet) bool {
			return pkt.Protocol == protoUDP && pkt.Src == testDeviceIP && pkt.Dst == testClientIP
		})
		seg, err := decodeUDP(pkt.Payload)
		if err != nil {
			t.Fatalf("decode answer: %v", err)
		}
		return index, seg
	}

	index, seg := ask(t, 0, "known.test", 28) // AAAA
	if seg.Data[3]&0x0f != 0 || binary.BigEndian.Uint16(seg.Data[6:8]) != 0 {
		t.Fatalf("AAAA answer should be NODATA, got %v", seg.Data[:12])
	}
	_, seg = ask(t, index, "missing.test", dns.QueryTypeA)
	if seg.Data[3]&0x0f != dns.RcodeNXDomain || binary.BigEndian.Uint16(seg.Data[6:8]) != 0 {
		t.Fatalf("unknown name should be NXDOMAIN, got %v", seg.Data[:12])
	}
	tun.svc.dns.mu.Lock()
	allocated := len(tun.svc.dns.byIP)
	tun.svc.dns.mu.Unlock()
	if allocated != 0 {
		t.Fatalf("%d name addresses allocated for negative answers", allocated)
	}
}

// TestTUNFakeIPPoolReusesAndSweeps covers the pool directly: a name keeps its
// address, different names get different addresses and expired entries leave.
func TestTUNFakeIPPoolReusesAndSweeps(t *testing.T) {
	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,DIRECT"},
		leaves: map[string]outbound.Dialer{"DIRECT": &fakeSharedDialer{}},
	})
	tun := newTunEnv(t, TUNOptions{Handler: env.handler})
	pool := tun.svc.dns

	first, ok := pool.allocate("One.Test")
	if !ok {
		t.Fatal("the pool refused the first allocation")
	}
	again, ok := pool.allocate("one.test.")
	if !ok {
		t.Fatal("the pool refused a repeated name")
	}
	second, ok := pool.allocate("two.test")
	if !ok {
		t.Fatal("the pool refused a second name")
	}
	if first != again {
		t.Fatalf("the same name got %s then %s", first, again)
	}
	if first == second || !pool.isFake(first) || !pool.isFake(second) {
		t.Fatalf("addresses %s and %s are not distinct name addresses", first, second)
	}
	if name, ok := pool.nameFor(first); !ok || name != "one.test" {
		t.Fatalf("nameFor(%s) = %q, %v", first, name, ok)
	}

	tun.clock.Advance(fakeIPTTL + time.Second)
	pool.sweep(tun.clock.Now())
	if _, ok := pool.nameFor(first); ok {
		t.Fatal("an expired name address is still mapped")
	}
	pool.mu.Lock()
	byIP, byName := len(pool.byIP), len(pool.byName)
	pool.mu.Unlock()
	if byIP != 0 || byName != 0 {
		t.Fatalf("pool still holds %d addresses and %d names", byIP, byName)
	}
}
