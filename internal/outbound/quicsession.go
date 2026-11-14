package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// QUIC transports are connections, not sockets: a client that opens one stream
// per proxied connection pays a handshake plus an authentication round trip for
// every connection it carries. This file keeps one connection per outbound and
// hands it out with a reference count, so the connection lives exactly as long
// as something is using it.
//
// A QUIC connection is also a datagram endpoint, and only one goroutine may
// read its datagrams. datagramMux owns that goroutine and fans the payloads out
// to the associations that asked for them.

// DefaultQUICIdleTimeout is how long an unused connection is kept. It is long
// enough that a burst of connections reuses one handshake and short enough that
// a replaced outbound does not hold a socket for the life of the process.
const DefaultQUICIdleTimeout = 60 * time.Second

// quicSession is a lazily created QUIC connection shared by every dial of one
// outbound.
type quicSession struct {
	dialFn func(context.Context) (*quic.Conn, error)
	idle   time.Duration
	mux    *datagramMux

	mu      sync.Mutex
	conn    *quic.Conn
	refs    int
	timer   *time.Timer
	closed  bool
	retired bool
}

// NewQUICSession builds a session around a dial function. The mux may be nil
// when the protocol does not use datagrams.
func newQUICSession(dialFn func(context.Context) (*quic.Conn, error), mux *datagramMux, idle time.Duration) *quicSession {
	if idle <= 0 {
		idle = DefaultQUICIdleTimeout
	}
	return &quicSession{dialFn: dialFn, idle: idle, mux: mux}
}

// acquire returns a live connection and a release function. Every acquire must
// be paired with exactly one release call.
func (s *quicSession) acquire(ctx context.Context) (*quic.Conn, func(), error) {
	s.mu.Lock()
	if s.closed || s.retired {
		s.mu.Unlock()
		return nil, nil, errors.New("outbound: the quic session is closed")
	}
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if conn := s.conn; conn != nil && conn.Context().Err() == nil {
		s.refs++
		s.mu.Unlock()
		return conn, s.release, nil
	}
	s.conn = nil
	s.mu.Unlock()

	conn, err := s.dialFn(ctx)
	if err != nil {
		return nil, nil, err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.CloseWithError(0, "closed")
		return nil, nil, errors.New("outbound: the quic session is closed")
	}
	if s.retired {
		// The configuration that named this outbound is gone. A dial that
		// started before the swap may still arrive here, and answering it
		// would give the replaced connection a new user.
		s.mu.Unlock()
		_ = conn.CloseWithError(0, "retired")
		return nil, nil, errors.New("outbound: the quic session is closed")
	}
	if existing := s.conn; existing != nil && existing.Context().Err() == nil {
		// Another caller won the race; use its connection and drop this one.
		s.refs++
		s.mu.Unlock()
		_ = conn.CloseWithError(0, "duplicate")
		return existing, s.release, nil
	}
	s.conn = conn
	s.refs++
	s.mu.Unlock()

	if s.mux != nil {
		go s.mux.run(conn)
	}
	return conn, s.release, nil
}

// release drops one reference and starts the idle timer when the last one goes
// away, or closes the connection right away if the session has been retired.
func (s *quicSession) release() {
	s.mu.Lock()
	if s.refs > 0 {
		s.refs--
	}
	if s.refs != 0 || s.closed {
		s.mu.Unlock()
		return
	}
	if s.retired {
		conn := s.conn
		s.conn = nil
		s.mu.Unlock()
		if conn != nil {
			_ = conn.CloseWithError(0, "retired")
		}
		return
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(s.idle, s.expire)
	s.mu.Unlock()
}

// expire closes a connection that nobody is using.
func (s *quicSession) expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refs != 0 || s.closed || s.conn == nil {
		return
	}
	_ = s.conn.CloseWithError(0, "idle")
	s.conn = nil
	s.timer = nil
}

// Close closes the connection and every datagram subscription.
func (s *quicSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.CloseWithError(0, "closed")
}

// Disown retires the session: it is not used again, and its connection goes
// away as soon as the last connection it carries is done. Unlike Close it never
// cuts anything in flight, which is what a reload needs.
func (s *quicSession) Disown() {
	s.mu.Lock()
	if s.retired || s.closed {
		s.mu.Unlock()
		return
	}
	s.retired = true
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	conn := s.conn
	idle := s.refs == 0
	if idle {
		s.conn = nil
	}
	s.mu.Unlock()
	if idle && conn != nil {
		_ = conn.CloseWithError(0, "retired")
	}
}

// datagramMux reads the datagrams of one connection and hands each payload to
// the association that registered its key.
type datagramMux struct {
	// key extracts the association key from a datagram payload. A payload it
	// rejects is dropped: an unknown key belongs to no association, and
	// inventing one would leak traffic between them.
	key func(payload []byte) (uint32, bool)

	mu   sync.Mutex
	subs map[uint32]chan []byte
	done bool
}

func newDatagramMux(key func([]byte) (uint32, bool)) *datagramMux {
	return &datagramMux{key: key, subs: make(map[uint32]chan []byte)}
}

// subscribe registers a key. The channel is closed when the connection ends,
// and is already closed when the connection ended before the subscription.
func (m *datagramMux) subscribe(key uint32) (<-chan []byte, func()) {
	ch := make(chan []byte, 64)
	m.mu.Lock()
	if m.done {
		close(ch)
		m.mu.Unlock()
		return ch, func() {}
	}
	m.subs[key] = ch
	m.mu.Unlock()
	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			m.mu.Lock()
			if current, ok := m.subs[key]; ok && current == ch {
				delete(m.subs, key)
				close(ch)
			}
			m.mu.Unlock()
		})
	}
	return ch, unsubscribe
}

// run reads datagrams until the connection ends.
func (m *datagramMux) run(conn *quic.Conn) {
	for {
		payload, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			break
		}
		key, ok := m.key(payload)
		if !ok {
			continue
		}
		m.mu.Lock()
		ch, ok := m.subs[key]
		if ok {
			select {
			case ch <- payload:
			default:
				// A full queue means the reader is not keeping up. Dropping is
				// what a datagram transport does; blocking here would stall
				// every other association on the same connection.
			}
		}
		m.mu.Unlock()
	}
	m.mu.Lock()
	m.done = true
	for key, ch := range m.subs {
		delete(m.subs, key)
		close(ch)
	}
	m.mu.Unlock()
}

// datagramReassembler collects the fragments of a datagram that arrived in
// pieces. Both QUIC protocols frame fragments as an id, an index and a count,
// so the bookkeeping lives in one place instead of one place per protocol.
type datagramReassembler struct {
	mu      sync.Mutex
	pending map[uint16]*pendingDatagram
	// limit bounds the map so a stream of never-completing datagrams cannot
	// grow it without bound.
	limit int
}

type pendingDatagram struct {
	parts  [][]byte
	filled int
	at     time.Time
}

func newDatagramReassembler() *datagramReassembler {
	return &datagramReassembler{pending: make(map[uint16]*pendingDatagram), limit: 64}
}

// add records one fragment and returns the whole payload once every fragment
// of that id has arrived. A nil result with a nil error means "still waiting".
func (r *datagramReassembler) add(id uint16, index, count int, payload []byte) ([]byte, error) {
	if index < 0 || index >= count || count == 0 {
		return nil, errors.New("outbound: inconsistent fragment numbers")
	}
	if count == 1 {
		return payload, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.pending[id]
	if entry == nil {
		entry = &pendingDatagram{parts: make([][]byte, count), at: time.Now()}
		r.pending[id] = entry
		r.dropOldest()
	}
	if len(entry.parts) != count {
		return nil, errors.New("outbound: fragments of one datagram disagree on their count")
	}
	if entry.parts[index] == nil {
		entry.parts[index] = append([]byte(nil), payload...)
		entry.filled++
	}
	if entry.filled != count {
		return nil, nil
	}
	delete(r.pending, id)
	out := make([]byte, 0, count*len(payload))
	for _, part := range entry.parts {
		out = append(out, part...)
	}
	return out, nil
}

// dropOldest forgets the oldest incomplete datagram when the map is full. The
// caller holds the lock.
func (r *datagramReassembler) dropOldest() {
	if len(r.pending) <= r.limit {
		return
	}
	oldestID, oldest := uint16(0), time.Time{}
	for id, entry := range r.pending {
		if oldest.IsZero() || entry.at.Before(oldest) {
			oldestID, oldest = id, entry.at
		}
	}
	delete(r.pending, oldestID)
}

// datagramDeadline is the deadline of a datagram association that owns no
// socket: there is nothing to call SetDeadline on, so the read and write paths
// check the value themselves. Both QUIC protocols use it, which is what makes
// a deadline mean the same thing for both.
type datagramDeadline struct {
	mu   sync.Mutex
	when time.Time
}

// set stores a deadline.
func (d *datagramDeadline) set(t time.Time) error {
	d.mu.Lock()
	d.when = t
	d.mu.Unlock()
	return nil
}

// expired reports whether the deadline has passed.
func (d *datagramDeadline) expired() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.when.IsZero() && time.Now().After(d.when)
}

// channel fires when the deadline passes, which lets a blocked read wake up. A
// zero deadline means "wait forever", which a nil channel expresses.
func (d *datagramDeadline) channel() <-chan time.Time {
	d.mu.Lock()
	when := d.when
	d.mu.Unlock()
	if when.IsZero() {
		return nil
	}
	wait := time.Until(when)
	if wait <= 0 {
		expired := make(chan time.Time)
		close(expired)
		return expired
	}
	return time.After(wait)
}

// quicDialConfig builds the QUIC configuration of an outbound.
func quicDialConfig(tlsOpts TLSOptions, host string, datagrams bool) (*tls.Config, *quic.Config, error) {
	if len(tlsOpts.ALPN) == 0 {
		return nil, nil, errors.New("outbound: a QUIC transport needs an ALPN protocol")
	}
	tlsConfig := tlsOpts.For(host)
	// QUIC is TLS 1.3 only; a lower floor would only turn a clear protocol
	// error into a handshake failure.
	tlsConfig.MinVersion = tls.VersionTLS13
	conf := &quic.Config{
		HandshakeIdleTimeout: DefaultTimeout,
		MaxIdleTimeout:       2 * DefaultQUICIdleTimeout,
		KeepAlivePeriod:      15 * time.Second,
		EnableDatagrams:      datagrams,
	}
	return tlsConfig, conf, nil
}

// dialQUICAddr opens a QUIC connection to a server address. It is a variable
// because the socket a default dial creates cannot be used everywhere: a
// sandbox that blocks sendto on unconnected sockets needs the dial to go
// through a connected one. Production always uses the default.
var dialQUICAddr = func(ctx context.Context, server string, tlsConfig *tls.Config, conf *quic.Config) (*quic.Conn, error) {
	return quic.DialAddr(ctx, server, tlsConfig, conf)
}

// dialQUIC opens one QUIC connection, optionally through an obfuscated packet
// connection.
func dialQUIC(ctx context.Context, server string, tlsConfig *tls.Config, conf *quic.Config, wrap func(net.PacketConn) (net.PacketConn, error)) (*quic.Conn, error) {
	if wrap == nil {
		conn, err := dialQUICAddr(ctx, server, tlsConfig, conf)
		if err != nil {
			return nil, fmt.Errorf("quic dial %s: %w", server, err)
		}
		return conn, nil
	}
	addr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", server, err)
	}
	raw, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("open a datagram socket: %w", err)
	}
	wrapped, err := wrap(raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	conn, err := quic.Dial(ctx, wrapped, addr, tlsConfig, conf)
	if err != nil {
		// The transport only closes the socket once a connection exists.
		_ = wrapped.Close()
		return nil, fmt.Errorf("quic dial %s: %w", server, err)
	}
	return conn, nil
}
