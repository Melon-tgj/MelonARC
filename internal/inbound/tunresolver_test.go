package inbound

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/outbound"
)

// tableResolver records every name it was asked and answers from a fixed
// table. A name outside the table is "not found", which is what makes it
// possible to tell two resolvers apart from the DNS answer alone.
type tableResolver struct {
	hosts map[string]net.IP

	mu    sync.Mutex
	asked []string
}

func (r *tableResolver) Resolve(_ context.Context, host string) (dns.Result, error) {
	r.mu.Lock()
	r.asked = append(r.asked, host)
	r.mu.Unlock()
	if ip, ok := r.hosts[host]; ok {
		return dns.Result{IPs: []net.IP{ip}}, nil
	}
	return dns.Result{}, dns.ErrNotFound
}

func (r *tableResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.asked)
}

// TestTUNDNSFollowsTheResolverHolder checks that the DNS path of a device that was
// opened at startup answers with whatever resolver is current now.
//
// The device is created once and a reload never rebuilds it, so the responder
// must not hold the resolver it was constructed with. It reads the shared holder
// per question, and install writes that holder at the commit point. This test
// covers the responder half of the chain: the same name is unknown before the
// swap and known after it, which is exactly what a changed [Host] entry looks
// like from inside the device.
func TestTUNDNSFollowsTheResolverHolder(t *testing.T) {
	before := &tableResolver{hosts: map[string]net.IP{}}
	after := &tableResolver{hosts: map[string]net.IP{
		"switch.test": net.IPv4(10, 9, 9, 9),
	}}
	holder := NewResolverHolder(before)

	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,DIRECT"},
		leaves: map[string]outbound.Dialer{"DIRECT": &fakeSharedDialer{}},
	})
	tun := newTunEnv(t, TUNOptions{Handler: env.handler, Resolvers: holder})

	rcode, answers := askTUNQuestion(t, tun, "switch.test")
	if rcode != dns.RcodeNXDomain || answers != 0 {
		t.Fatalf("before the swap the name answered with rcode %d and %d records, want NXDOMAIN", rcode, answers)
	}
	if before.count() != 1 || after.count() != 0 {
		t.Fatalf("before the swap the resolvers were asked %d and %d times, want 1 and 0", before.count(), after.count())
	}

	// This is what a reload commit does: the holder is repointed, and nothing
	// else about the service changes.
	holder.Store(after)

	rcode, answers = askTUNQuestion(t, tun, "switch.test")
	if rcode != dns.RcodeOK || answers != 1 {
		t.Fatalf("after the swap the name answered with rcode %d and %d records, want one A record", rcode, answers)
	}
	if got := after.count(); got != 1 {
		t.Fatalf("after the swap the new resolver was asked %d times, want 1", got)
	}
	if got := before.count(); got != 1 {
		t.Fatalf("the replaced resolver was asked again after the swap (%d questions)", got)
	}
}

// gatedResolver holds every lookup until the test lets it go, so a swap can be
// placed inside a question that is already running.
type gatedResolver struct {
	ip      net.IP
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	asked   []string
}

func newGatedResolver(ip net.IP) *gatedResolver {
	return &gatedResolver{ip: ip, entered: make(chan struct{}), release: make(chan struct{})}
}

func (r *gatedResolver) Resolve(_ context.Context, host string) (dns.Result, error) {
	r.mu.Lock()
	r.asked = append(r.asked, host)
	r.mu.Unlock()
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return dns.Result{IPs: []net.IP{r.ip}}, nil
}

func (r *gatedResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.asked)
}

// TestTUNDNSQueryInFlightKeepsItsResolver checks the other half of reading the
// holder: a question that is already running when the swap happens finishes on
// the resolver it started with. One load per question is what keeps a single
// answer from being a mixture of two configurations.
func TestTUNDNSQueryInFlightKeepsItsResolver(t *testing.T) {
	slow := newGatedResolver(net.IPv4(10, 1, 1, 1))
	next := &tableResolver{hosts: map[string]net.IP{"held.test": net.IPv4(10, 2, 2, 2)}}
	holder := NewResolverHolder(slow)

	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,DIRECT"},
		leaves: map[string]outbound.Dialer{"DIRECT": &fakeSharedDialer{}},
	})
	tun := newTunEnv(t, TUNOptions{Handler: env.handler, Resolvers: holder})

	// Start a question and wait until it is inside the resolver.
	from := len(tun.device.written())
	tun.device.inject(appendUDPPacket(nil, testClientIP, testDeviceIP, 43000, 53, dnsQuery(t, "held.test", dns.QueryTypeA)))
	select {
	case <-slow.entered:
	case <-time.After(testDeadline):
		t.Fatal("the question never reached the resolver")
	}

	// Swap while the question is running, then let it finish.
	holder.Store(next)
	close(slow.release)

	rcode, answers := waitAnswer(t, tun, from)
	if rcode != dns.RcodeOK || answers != 1 {
		t.Fatalf("the in-flight question answered with rcode %d and %d records, want one A record", rcode, answers)
	}
	if got := slow.count(); got != 1 {
		t.Fatalf("the resolver in force when the question started was asked %d times, want 1", got)
	}
	if got := next.count(); got != 0 {
		t.Fatalf("the new resolver answered a question that was already running (%d lookups)", got)
	}

	// The next question is the new resolver's.
	rcode, answers = askTUNQuestion(t, tun, "held.test")
	if rcode != dns.RcodeOK || answers != 1 {
		t.Fatalf("the next question answered with rcode %d and %d records", rcode, answers)
	}
	if got := next.count(); got != 1 {
		t.Fatalf("after the swap the new resolver was asked %d times, want 1", got)
	}
	if got := slow.count(); got != 1 {
		t.Fatalf("the replaced resolver was asked %d times, want the single question it started with", got)
	}
}

// askTUNQuestion sends one A question through the device's DNS path and reports
// the response code and the number of records in the answer.
func askTUNQuestion(t *testing.T, tun *tunEnv, name string) (rcode, answers int) {
	t.Helper()
	from := len(tun.device.written())
	tun.device.inject(appendUDPPacket(nil, testClientIP, testDeviceIP, 43000, 53, dnsQuery(t, name, dns.QueryTypeA)))
	return waitAnswer(t, tun, from)
}

// waitAnswer reads the next DNS answer the device writes after packet index from.
func waitAnswer(t *testing.T, tun *tunEnv, from int) (rcode, answers int) {
	t.Helper()
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
	return int(seg.Data[3] & 0x0f), int(seg.Data[6])<<8 | int(seg.Data[7])
}
