package inbound

import (
	"sync"
	"sync/atomic"
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
	// FailureCapacity and FailureCount describe the failure record: how many
	// entries it holds and how many it can hold.
	FailureCapacity int
	FailureCount    int
}

// Metrics is the runtime observation of the inbound layer: connection counters
// per listener plus the recent failure record the local API serves.
//
// A nil *Metrics is valid and records nothing, so a listener built without one
// behaves exactly as it did before this type existed; every method tolerates the
// nil receiver, and so does the zero value.
type Metrics struct {
	http   protocolCounters
	socks5 protocolCounters

	failures atomic.Uint64
	rejected atomic.Uint64

	ring *failureRing
}

// NewMetrics returns a Metrics that keeps at most capacity recent failures.
// Capacity zero or less means DefaultFailureCapacity.
func NewMetrics(capacity int) *Metrics {
	if capacity <= 0 {
		capacity = DefaultFailureCapacity
	}
	return &Metrics{ring: newFailureRing(capacity)}
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
		Protocols:       make([]ProtocolStats, 0, 2),
		Failures:        m.failures.Load(),
		Rejected:        m.rejected.Load(),
		FailureCapacity: m.ring.capacity(),
		FailureCount:    m.ring.len(),
	}
	// HTTP first, always: a snapshot that reorders itself is a snapshot a
	// client cannot diff.
	for _, entry := range [...]struct {
		name string
		c    *protocolCounters
	}{
		{protocolHTTP, &m.http},
		{protocolSOCKS5, &m.socks5},
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
