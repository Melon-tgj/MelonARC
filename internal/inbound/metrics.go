package inbound

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// DefaultFailureCapacity is how many recent failures the inbound layer keeps for
// the local API.
//
// The bound is fixed rather than configurable: its whole purpose is that the
// record can never grow with traffic. A few dozen entries are enough to tell a
// broken member from a destination a rule blocks, which is what the endpoint is
// for.
const DefaultFailureCapacity = 64

// The listener names. They label the counters and appear in the API.
const (
	protocolHTTP   = "http"
	protocolSOCKS5 = "socks5"
	protocolTUN    = "tun"
)

// protocolCounters is the counter set of one listener. Every field is atomic:
// the accept loop, the handlers and whoever reads a snapshot all touch it from
// different goroutines, and a mutex on this path would serialise connections
// that have nothing to do with each other.
type protocolCounters struct {
	// enabled is set when a listener of this protocol is bound, so a snapshot
	// reports the protocols that exist instead of every protocol there is.
	enabled atomic.Bool
	// open is the number of connections being served right now.
	open atomic.Int64
	// accepted is the number of connections accepted since startup.
	accepted atomic.Uint64
	// datagrams is the number of open UDP associations.
	datagrams atomic.Int64
	// datagramTotal is the number of UDP associations opened since startup.
	datagramTotal atomic.Uint64
}

// ProtocolStats is one listener's counters at a point in time.
type ProtocolStats struct {
	// Protocol is "http" or "socks5".
	Protocol string
	// Open is the number of connections being served right now.
	Open int64
	// Accepted is the number of connections accepted since startup.
	Accepted uint64
	// Datagrams is the number of open UDP associations. Only the SOCKS5
	// listener has them; the HTTP listener always reports zero.
	Datagrams int64
	// DatagramTotal is the number of associations opened since startup.
	DatagramTotal uint64
}

// Snapshot is every inbound counter at a point in time.
type Snapshot struct {
	// Protocols lists the bound listeners, HTTP first.
	Protocols []ProtocolStats
	// Failures counts the requests that failed for an operational reason.
	Failures uint64
	// Rejected counts the requests a rule blocked on purpose. They are kept
	// apart from Failures because a REJECT rule doing its job is not a fault.
	Rejected uint64
	// NameAddressExhausted counts the TUN DNS questions that were answered with
	// SERVFAIL because the name address pool had nothing to hand out.
	//
	// It is its own counter rather than a Failure: a failure record describes a
	// request the daemon could not carry, while this is a DNS answer that says
	// "no address right now". It reaches the operator twice: as the log line
	// the responder writes once per episode, and as
	// fake_ip_pool_exhausted_queries_total on /v1/inbound.
	NameAddressExhausted uint64
	// FailureCapacity and FailureCount describe the failure record: how many
	// entries it holds and how many it can hold.
	FailureCapacity int
	FailureCount    int
}

// ConnectionRecord is one connection the inbound layer carried, reported when it
// ends.
//
// It is an observation and nothing else: the pipeline never reads it, and a
// record that cannot be kept is not a request that failed. The destination is
// kept as the client asked for it, so a name stays a name — that is what a rule
// matched, and an address would not say why the connection took the path it did.
type ConnectionRecord struct {
	// Protocol is the listener that accepted the connection: "http", "socks5"
	// or "tun".
	Protocol string
	// Target is the destination the client asked for.
	Target outbound.Target
	// Network is "tcp" or "udp".
	Network string
	// Rule is the rule that classified the destination, empty when the routing
	// failed before a rule matched.
	Rule string
	// Policy and Outbound are the target the rule named and the leaf that
	// finally carried the connection.
	Policy   string
	Outbound string
	// Started and Duration describe when the connection was opened and how long
	// it was served.
	Started  time.Time
	Duration time.Duration
	// Up and Down are the bytes the connection carried, as counted on the
	// upstream side.
	Up, Down int64
}

// Observer receives the events the inbound layer produces. It is the seam the
// persistent history plugs into: the layer keeps its own bounded records and
// tells an observer about them, so a store that cannot write never becomes part
// of the data path.
//
// The methods are called from the goroutine that serves a connection, so an
// implementation must not block: appending to a bounded in-memory table is the
// expected amount of work.
type Observer interface {
	// Connection is called once per connection that was carried, after it
	// ended.
	Connection(ConnectionRecord)
	// Failure is called once per request that was not carried, after the record
	// was added to the ring.
	Failure(Failure)
}

// Metrics is the runtime observation of the inbound layer: connection counters
// per listener, the bytes the connections carried, and the recent failure record
// the local API serves.
//
// A nil *Metrics is valid and records nothing, so a listener built without one
// behaves exactly as it did before this type existed; every method tolerates the
// nil receiver, and so does the zero value.
type Metrics struct {
	http   protocolCounters
	socks5 protocolCounters
	tun    protocolCounters

	failures atomic.Uint64
	rejected atomic.Uint64
	// nameAddressFailures counts the TUN DNS questions answered with SERVFAIL
	// because the name address pool had nothing reclaimable.
	nameAddressFailures atomic.Uint64

	// up and down are the bytes every connection carried since startup. They
	// only ever grow, which is what lets a sampler take a difference without
	// missing a record that arrives between two reads.
	up   atomic.Int64
	down atomic.Int64

	ring     *failureRing
	observer Observer
}

// NewMetrics returns a Metrics that keeps at most capacity recent failures. An
// observer is optional; the first one wins, because one history is one history.
func NewMetrics(capacity int, observers ...Observer) *Metrics {
	if capacity <= 0 {
		capacity = DefaultFailureCapacity
	}
	m := &Metrics{ring: newFailureRing(capacity)}
	if len(observers) > 0 {
		m.observer = observers[0]
	}
	return m
}

// counters returns the counter set of a protocol, or nil for a protocol this
// package does not listen on.
func (m *Metrics) counters(protocol string) *protocolCounters {
	if m == nil {
		return nil
	}
	switch protocol {
	case protocolHTTP:
		return &m.http
	case protocolSOCKS5:
		return &m.socks5
	case protocolTUN:
		return &m.tun
	}
	return nil
}

// listen notes that a listener of this protocol is bound.
func (m *Metrics) listen(protocol string) {
	if c := m.counters(protocol); c != nil {
		c.enabled.Store(true)
	}
}

// connectionOpened counts one accepted connection.
func (m *Metrics) connectionOpened(protocol string) {
	if c := m.counters(protocol); c != nil {
		c.open.Add(1)
		c.accepted.Add(1)
	}
}

// connectionClosed counts one connection whose handler has returned. It is
// called from a deferred statement, so an error return and a panicking handler
// both bring the count back down.
func (m *Metrics) connectionClosed(protocol string) {
	if c := m.counters(protocol); c != nil {
		c.open.Add(-1)
	}
}

// datagramOpened counts one UDP association of the SOCKS5 listener.
func (m *Metrics) datagramOpened() {
	if m == nil {
		return
	}
	m.socks5.datagrams.Add(1)
	m.socks5.datagramTotal.Add(1)
}

// datagramClosed counts one UDP association that has ended.
func (m *Metrics) datagramClosed() {
	if m == nil {
		return
	}
	m.socks5.datagrams.Add(-1)
}

// tunDatagramOpened and tunDatagramClosed count the UDP sessions a TUN device
// keeps. They are separate from the SOCKS5 counters because an association and
// a TUN session are different lifetimes: one TUN association can carry several
// sessions, and a session can end while the association stays open.
func (m *Metrics) tunDatagramOpened() {
	if m == nil {
		return
	}
	m.tun.datagrams.Add(1)
	m.tun.datagramTotal.Add(1)
}

func (m *Metrics) tunDatagramClosed() {
	if m == nil {
		return
	}
	m.tun.datagrams.Add(-1)
}

// nameAddressExhausted counts one TUN DNS question the pool could not serve.
// It is the only record of a device whose clients are being told SERVFAIL
// because every name address is leased or still in use.
func (m *Metrics) nameAddressExhausted() {
	if m == nil {
		return
	}
	m.nameAddressFailures.Add(1)
}

// Record notes one request that was not carried.
//
// The category decides which counter moves; the record itself goes into the
// ring either way, because an operator debugging a client has to be able to see
// that a rule blocked the destination rather than a proxy being down, and the
// category is what tells the two apart.
func (m *Metrics) Record(f Failure) {
	if m == nil {
		return
	}
	if f.Category == CategoryRejected {
		m.rejected.Add(1)
	} else {
		m.failures.Add(1)
	}
	m.ring.add(f)
	if m.observer != nil {
		m.observer.Failure(f)
	}
}

// observeConnection notes what one connection carried and reports it.
//
// The counters move even without an observer: the totals are what a traffic
// sample is taken from, and a daemon configured without a history still reports
// how much it moved.
func (m *Metrics) observeConnection(rec ConnectionRecord) {
	if m == nil {
		return
	}
	m.up.Add(rec.Up)
	m.down.Add(rec.Down)
	if m.observer != nil {
		m.observer.Connection(rec)
	}
}

// Traffic returns the bytes every connection carried since startup.
func (m *Metrics) Traffic() (up, down int64) {
	if m == nil {
		return 0, 0
	}
	return m.up.Load(), m.down.Load()
}

// Recent returns the retained failures, oldest first, at most limit of the
// newest ones. A limit of zero or less returns all of them.
func (m *Metrics) Recent(limit int) []Failure {
	if m == nil {
		return nil
	}
	return m.ring.snapshot(limit)
}

// Snapshot returns the counters and the size of the failure record.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	snap := Snapshot{
		Protocols:            make([]ProtocolStats, 0, 3),
		Failures:             m.failures.Load(),
		Rejected:             m.rejected.Load(),
		NameAddressExhausted: m.nameAddressFailures.Load(),
		FailureCapacity:      m.ring.capacity(),
		FailureCount:         m.ring.len(),
	}
	// HTTP first, always: a snapshot that reorders itself is a snapshot a
	// client cannot diff.
	for _, entry := range [...]struct {
		name string
		c    *protocolCounters
	}{
		{protocolHTTP, &m.http},
		{protocolSOCKS5, &m.socks5},
		{protocolTUN, &m.tun},
	} {
		if !entry.c.enabled.Load() {
			continue
		}
		snap.Protocols = append(snap.Protocols, ProtocolStats{
			Protocol:      entry.name,
			Open:          entry.c.open.Load(),
			Accepted:      entry.c.accepted.Load(),
			Datagrams:     entry.c.datagrams.Load(),
			DatagramTotal: entry.c.datagramTotal.Load(),
		})
	}
	return snap
}

// failureRing is a fixed-size ring of the most recent failures. Writing past the
// end overwrites the oldest record, which is the eviction rule: there is no
// timestamps comparison to get wrong and no slice to grow.
type failureRing struct {
	mu    sync.Mutex
	buf   []Failure
	next  int
	count int
}

// newFailureRing returns a ring of the given capacity, which must be positive.
func newFailureRing(capacity int) *failureRing {
	return &failureRing{buf: make([]Failure, capacity)}
}

// add appends a record, dropping the oldest one when the ring is full.
func (r *failureRing) add(f Failure) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = f
	r.next = (r.next + 1) % len(r.buf)
	if r.count < len(r.buf) {
		r.count++
	}
}

// snapshot copies the retained records, oldest first, keeping at most limit of
// the newest ones.
func (r *failureRing) snapshot(limit int) []Failure {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Failure, 0, r.count)
	start := r.next - r.count
	if start < 0 {
		start += len(r.buf)
	}
	for i := 0; i < r.count; i++ {
		out = append(out, r.buf[(start+i)%len(r.buf)])
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// len returns how many records are retained.
func (r *failureRing) len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// capacity returns how many records fit.
func (r *failureRing) capacity() int {
	if r == nil {
		return 0
	}
	return len(r.buf)
}
