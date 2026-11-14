package inbound

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/melon-tgj/melonarc/internal/dns"
)

const (
	// fakeIPTTL is how long a name address stays mapped. It has to outlive the
	// application's own DNS cache but not the process: a stale mapping is
	// dropped rather than silently reused for a different name.
	fakeIPTTL = 10 * time.Minute
	// fakeAnswerTTL is what the DNS answer tells the application. Keeping it
	// short means a name that changes its rule or its answer is looked up again
	// instead of staying attached to an old name address.
	fakeAnswerTTL = 60
)

var fakeNetwork = mustCIDR(fakeIPPrefix)

func mustCIDR(s string) *net.IPNet {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		panic("inbound: invalid built-in fake address range: " + err.Error())
	}
	return network
}

// nameAddress is one entry of the name address pool.
type nameAddress struct {
	name    string
	expires time.Time
}

// dnsResponder answers DNS questions that arrive on the TUN device itself and
// keeps the name-to-address pool those answers create.
//
// The answer is a token address, never the real one. A real address would have
// to be routed into the device for the application to reach it, and dialling it
// from inside the proxy would send the request back into the device: a loop.
// With a token address the packet carries a name again by the time it reaches
// the rule pipeline, which is what makes domain rules and the DIRECT resolver
// work for TUN traffic.
type dnsResponder struct {
	svc *TUNService

	mu     sync.Mutex
	byName map[string]ip4
	byIP   map[ip4]nameAddress
	cursor uint16
}

func newDNSResponder(svc *TUNService) *dnsResponder {
	return &dnsResponder{
		svc:    svc,
		byName: make(map[string]ip4),
		byIP:   make(map[ip4]nameAddress),
		cursor: 2,
	}
}

func (d *dnsResponder) isFake(addr ip4) bool { return fakeNetwork.Contains(addr.IP()) }

// nameFor returns the name a token address stands for, or false when the
// mapping has expired. Expiring here as well as in the sweeper means a token can
// never be used after its lifetime even if no other query arrived in between.
func (d *dnsResponder) nameFor(addr ip4) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.byIP[addr]
	if !ok {
		return "", false
	}
	if !d.svc.now().Before(entry.expires) {
		delete(d.byIP, addr)
		delete(d.byName, entry.name)
		return "", false
	}
	return entry.name, true
}

// allocate returns the token address for name, reusing a live mapping or
// taking the next slot of the /24. When the pool is full the oldest slot is
// reused: a name address is a cache entry, not an allocation that must last.
func (d *dnsResponder) allocate(name string) ip4 {
	key := normaliseName(name)
	now := d.svc.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if addr, ok := d.byName[key]; ok {
		if now.Before(d.byIP[addr].expires) {
			return addr
		}
		delete(d.byIP, addr)
		delete(d.byName, key)
	}
	var chosen ip4
	var oldest ip4
	var oldestWhen time.Time
	for i := 0; i < 253; i++ {
		host := uint16(2 + (int(d.cursor)-2+i)%253)
		addr := ip4{198, 18, 1, byte(host)}
		entry, taken := d.byIP[addr]
		if !taken || !now.Before(entry.expires) {
			chosen = addr
			d.cursor = host + 1
			if d.cursor > 254 {
				d.cursor = 2
			}
			break
		}
		if oldest == (ip4{}) || entry.expires.Before(oldestWhen) {
			oldest, oldestWhen = addr, entry.expires
		}
	}
	if chosen == (ip4{}) {
		chosen = oldest
	}
	if previous, ok := d.byIP[chosen]; ok {
		delete(d.byName, previous.name)
	}
	d.byIP[chosen] = nameAddress{name: key, expires: now.Add(fakeIPTTL)}
	d.byName[key] = chosen
	return chosen
}

// sweep drops expired mappings. It is called from the session reaper so the two
// tables share one clock and one ticker.
func (d *dnsResponder) sweep(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for addr, entry := range d.byIP {
		if !now.Before(entry.expires) {
			delete(d.byIP, addr)
			delete(d.byName, entry.name)
		}
	}
}

func normaliseName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// handle answers one intercepted DNS query. query is a copy of the UDP payload,
// because it is handled on its own goroutine while the read loop reuses its
// buffer.
func (d *dnsResponder) handle(pkt ipv4Packet, seg udpSegment, query []byte) {
	q, err := dns.ParseQuestion(query)
	if err != nil {
		d.svc.logger.Debug("tun dns query dropped", "error", err)
		return
	}
	var (
		rcode int = dns.RcodeOK
		ips   []net.IP
	)
	switch {
	case q.Type != dns.QueryTypeA:
		// A NODATA answer: this responder only carries IPv4 name addresses.
		// Clients then use the A answer instead of waiting for an AAAA one.
	default:
		ctx, cancel := context.WithTimeout(d.svc.ctx, 5*time.Second)
		res, resolveErr := d.svc.resolver.Resolve(ctx, normaliseName(q.Name))
		cancel()
		switch {
		case resolveErr != nil:
			if errors.Is(resolveErr, dns.ErrNotFound) {
				rcode = dns.RcodeNXDomain
			} else {
				rcode = dns.RcodeServFail
			}
			d.svc.logger.Debug("tun dns lookup failed", "name", q.Name, "error", resolveErr)
		case len(res.IPs) == 0:
			rcode = dns.RcodeNXDomain
		default:
			addr := d.allocate(q.Name)
			ips = []net.IP{addr.IP()}
		}
	}
	answer := dns.AnswerQuestion(q, rcode, fakeAnswerTTL, ips)
	reply := appendUDPPacket(nil, pkt.Dst, pkt.Src, seg.DstPort, seg.SrcPort, answer)
	if err := d.svc.writePacket(reply); err != nil {
		d.svc.logger.Debug("tun dns answer not written", "name", q.Name, "error", err)
		return
	}
	d.svc.logger.Debug("tun dns answered", "name", q.Name, "type", q.Type, "rcode", rcode)
}
