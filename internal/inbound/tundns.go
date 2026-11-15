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
	// poolSize is how many tokens the /24 can hand out: .2 through .254. .0 and
	// .1 are the network address and the device's own address.
	poolSize = 253
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
	// refs is how many TUN sessions are carrying traffic to this address right
	// now. A token whose lease has run out but whose refs are not zero belongs
	// to a stream that is still open: handing it to another name would make
	// every following packet of that stream resolve to the wrong destination.
	refs int
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
	// exhausted records that the last allocation found no reclaimable token,
	// so the warning is written once per episode rather than once per question.
	exhausted bool
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
//
// A token a session still holds a reference on stays readable past its lease:
// the stream was opened against that name and cutting the mapping would turn
// its next packet into an unroutable address.
func (d *dnsResponder) nameFor(addr ip4) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.byIP[addr]
	if !ok {
		return "", false
	}
	if !d.svc.now().Before(entry.expires) && entry.refs == 0 {
		delete(d.byIP, addr)
		delete(d.byName, entry.name)
		return "", false
	}
	return entry.name, true
}

// claim returns the name a token stands for and takes a reference on it, so the
// token cannot be reclaimed while the session that asked for it is open.
//
// It is one step rather than "look up, then count" on purpose: between those two
// calls a sweeper could drop a lease that has just run out, and the session would
// then be carrying traffic to an address nobody maps to a name any more.
func (d *dnsResponder) claim(addr ip4) (string, bool) {
	now := d.svc.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.byIP[addr]
	if !ok {
		return "", false
	}
	if !now.Before(entry.expires) {
		if entry.refs == 0 {
			delete(d.byIP, addr)
			delete(d.byName, entry.name)
			return "", false
		}
		// Still in use: the lease is renewed rather than left dead, so the
		// token keeps answering for as long as somebody is talking to it.
		entry.expires = now.Add(fakeIPTTL)
	}
	entry.refs++
	d.byIP[addr] = entry
	return entry.name, true
}

// release gives one reference back. A token whose lease has already run out is
// dropped by the last release, which is the moment it becomes reclaimable.
func (d *dnsResponder) release(addr ip4) {
	now := d.svc.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.byIP[addr]
	if !ok || entry.refs == 0 {
		return
	}
	entry.refs--
	if entry.refs == 0 && !now.Before(entry.expires) {
		delete(d.byIP, addr)
		delete(d.byName, entry.name)
		return
	}
	d.byIP[addr] = entry
}

// allocate returns the token address for name, reusing a live mapping or taking
// the next slot of the /24.
//
// A token is reclaimable only when its lease has run out *and* no session holds
// it: a name address is a cache entry, but it is also the only thing that maps a
// stream's packets back to a name. Reusing one that is still in use would move
// every following packet of the old stream to the new name, so a pool with
// nothing reclaimable refuses the allocation instead. The caller answers
// SERVFAIL; the error surface stays "this name has no address right now", which
// is what the client can retry.
func (d *dnsResponder) allocate(name string) (ip4, bool) {
	key := normaliseName(name)
	now := d.svc.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if addr, ok := d.byName[key]; ok {
		entry := d.byIP[addr]
		if now.Before(entry.expires) || entry.refs > 0 {
			if !now.Before(entry.expires) {
				entry.expires = now.Add(fakeIPTTL)
				d.byIP[addr] = entry
			}
			d.noteRoomLocked()
			return addr, true
		}
		delete(d.byIP, addr)
		delete(d.byName, key)
	}
	for i := 0; i < poolSize; i++ {
		host := uint16(2 + (int(d.cursor)-2+i)%poolSize)
		addr := ip4{198, 18, 1, byte(host)}
		if entry, taken := d.byIP[addr]; taken && (now.Before(entry.expires) || entry.refs > 0) {
			continue
		}
		d.cursor = host + 1
		if d.cursor > 254 {
			d.cursor = 2
		}
		d.assignLocked(addr, key, now)
		d.noteRoomLocked()
		return addr, true
	}
	d.noteExhaustedLocked()
	return ip4{}, false
}

// assignLocked points a token at a name, forgetting the name it used to carry.
// The caller holds d.mu.
func (d *dnsResponder) assignLocked(addr ip4, key string, now time.Time) {
	if previous, ok := d.byIP[addr]; ok {
		delete(d.byName, previous.name)
	}
	d.byIP[addr] = nameAddress{name: key, expires: now.Add(fakeIPTTL)}
	d.byName[key] = addr
}

// noteExhaustedLocked counts one allocation the pool could not serve and says so
// once per episode: a full pool is an operational fact, and a warning per
// question would bury it. The caller holds d.mu.
func (d *dnsResponder) noteExhaustedLocked() {
	d.svc.metrics.nameAddressExhausted()
	if d.exhausted {
		d.svc.logger.Debug("tun dns name address pool is full")
		return
	}
	d.exhausted = true
	d.svc.logger.Warn("tun dns name address pool is full: every token is either leased or still in use, " +
		"new names are answered with SERVFAIL until one is released")
}

// noteRoomLocked clears the exhaustion episode. The caller holds d.mu.
func (d *dnsResponder) noteRoomLocked() {
	if !d.exhausted {
		return
	}
	d.exhausted = false
	d.svc.logger.Info("tun dns name address pool has room again")
}

// sweep drops expired mappings. It is called from the session reaper so the two
// tables share one clock and one ticker. A token a session still holds is kept:
// the same rule allocate follows, so the sweeper can never free an address the
// allocator would have refused to reuse.
func (d *dnsResponder) sweep(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for addr, entry := range d.byIP {
		if !now.Before(entry.expires) && entry.refs == 0 {
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
		// The resolver is read once per question: a reload that lands while
		// this lookup runs may replace it, and either the old or the new one
		// answering a single question is acceptable — but never a mix within
		// one question.
		resolver := d.svc.resolver()
		if resolver == nil {
			rcode = dns.RcodeServFail
			break
		}
		ctx, cancel := context.WithTimeout(d.svc.ctx, 5*time.Second)
		res, resolveErr := resolver.Resolve(ctx, normaliseName(q.Name))
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
			addr, ok := d.allocate(q.Name)
			if !ok {
				// The pool has nothing to give: every token is leased or still
				// in use. Failing is the only honest answer — reusing one would
				// silently move another name's traffic.
				rcode = dns.RcodeServFail
				break
			}
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
