package inbound

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// Limits of one UDP association.
const (
	// maxDatagramDestinations bounds the destination sockets one association
	// keeps open. A client that talks to many destinations would otherwise
	// accumulate a socket per destination for as long as the association lives.
	maxDatagramDestinations = 128
	// maxSkippedDatagrams bounds how many unusable datagrams in a row an
	// association drops before it stops, so a broken client cannot make it spin.
	maxSkippedDatagrams = 32
	// maxDatagramPayload is the largest payload a single datagram can carry.
	maxDatagramPayload = 65535
)

// datagramSocket is the client facing socket of an association. It is an
// interface so the association can be driven from a test without bending the
// production path: the real implementation is a *net.UDPConn that stays
// unconnected, because a server must answer whoever wrote to it.
type datagramSocket interface {
	ReadFrom(p []byte) (int, net.Addr, error)
	WriteTo(p []byte, addr net.Addr) (int, error)
	Close() error
}

// associationOptions configures a datagram association.
type associationOptions struct {
	// ctx bounds the dials the association makes.
	ctx context.Context
	// handler routes each destination and opens its socket.
	handler *Handler
	// logger receives the failure lines.
	logger *slog.Logger
	// socket is the bound, unconnected socket the client writes to.
	socket datagramSocket
	// expect is the endpoint the client said it would send from, nil when it
	// did not say.
	expect net.Addr
}

// association relays SOCKS5 datagrams between one client and the outbound that
// each destination is routed to.
//
// The client side uses the framing of the protocol, which internal/outbound
// owns: this type decodes what the client sent and encodes what it sends back
// with the same functions the outbound client uses, so the two halves cannot
// disagree about the format. The relay itself is per destination, because each
// destination may be routed to a different outbound.
type association struct {
	ctx     context.Context
	handler *Handler
	logger  *slog.Logger
	socket  datagramSocket
	expect  net.Addr

	mu      sync.Mutex
	client  net.Addr
	entries map[string]*datagramEntry
	closed  bool

	// wmu serialises the framing buffer and the writes to the socket: reply
	// goroutines of different destinations share both.
	wmu  sync.Mutex
	wbuf []byte

	closeOnce sync.Once
	closeErr  error
}

// datagramEntry is the open socket for one destination.
type datagramEntry struct {
	conn     outbound.PacketConn
	dest     outbound.Target
	lastUsed time.Time
}

// newAssociation starts relaying datagrams on an already bound socket.
func newAssociation(opts associationOptions) *association {
	a := &association{
		ctx:     opts.ctx,
		handler: opts.handler,
		logger:  loggerOrDiscard(opts.logger),
		socket:  opts.socket,
		expect:  opts.expect,
		entries: make(map[string]*datagramEntry),
	}
	go a.read()
	return a
}

// read takes datagrams from the client until the socket fails.
func (a *association) read() {
	buf := make([]byte, maxDatagramPayload+outbound.MaxUDPHeaderLen)
	skipped := 0
	for {
		n, from, err := a.socket.ReadFrom(buf)
		if err != nil {
			a.Close()
			return
		}
		payload, dest, frag, err := outbound.DecodeUDPDatagram(buf[:n])
		if err != nil || frag != 0 {
			// A fragment is not a whole payload and a malformed header has no
			// destination; both are dropped rather than guessed at.
			skipped++
			if skipped >= maxSkippedDatagrams {
				a.logger.Warn("socks5 udp association gave up on unusable datagrams", "error", err)
				a.Close()
				return
			}
			continue
		}
		skipped = 0
		if !a.accepted(from) {
			continue
		}
		if err := a.forward(dest, payload); err != nil {
			a.logger.Debug("socks5 udp datagram dropped", "destination", dest.String(), "error", err)
		}
	}
}

// forward sends one payload to its destination, opening the route on first use.
func (a *association) forward(dest outbound.Target, payload []byte) error {
	entry, err := a.entry(dest)
	if err != nil {
		return err
	}
	_, err = entry.conn.Write(payload)
	return err
}

// entry returns the socket for a destination, dialing it when it is new.
//
// The dial runs on the read loop, so a destination that is slow to open delays
// the next new destination of this association; a route that is already open is
// unaffected, because its replies are read on their own goroutine.
func (a *association) entry(dest outbound.Target) (*datagramEntry, error) {
	key := dest.String()
	a.mu.Lock()
	if entry, ok := a.entries[key]; ok {
		entry.lastUsed = time.Now()
		a.mu.Unlock()
		return entry, nil
	}
	a.mu.Unlock()

	conn, _, err := a.handler.Packet(a.ctx, Request{Target: dest, Network: networkUDP, Protocol: protocolSOCKS5})
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	if len(a.entries) >= maxDatagramDestinations {
		a.evictLocked()
	}
	entry := &datagramEntry{conn: conn, dest: dest, lastUsed: time.Now()}
	a.entries[key] = entry
	a.mu.Unlock()

	go a.replies(key, entry)
	return entry, nil
}

// evictLocked makes room by closing the destination that has been idle longest.
// The caller holds a.mu.
func (a *association) evictLocked() {
	var oldest string
	var when time.Time
	for key, entry := range a.entries {
		if oldest == "" || entry.lastUsed.Before(when) {
			oldest, when = key, entry.lastUsed
		}
	}
	if oldest == "" {
		return
	}
	entry := a.entries[oldest]
	delete(a.entries, oldest)
	_ = entry.conn.Close()
}

// replies carries the answers of one destination back to the client until the
// socket fails or the association ends.
func (a *association) replies(key string, entry *datagramEntry) {
	buf := make([]byte, maxDatagramPayload)
	for {
		n, err := entry.conn.Read(buf)
		if err != nil {
			a.forget(key, entry)
			return
		}
		if err := a.send(entry.dest, buf[:n]); err != nil {
			a.forget(key, entry)
			return
		}
	}
}

// send frames one payload for the client. The source address it carries is the
// destination the payload came from, which is what the client matches its
// request against.
func (a *association) send(from outbound.Target, payload []byte) error {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	client, err := a.currentClient()
	if err != nil {
		return err
	}
	a.wbuf = outbound.AppendUDPDatagram(a.wbuf[:0], from, payload)
	_, err = a.socket.WriteTo(a.wbuf, client)
	return err
}

// currentClient returns the endpoint datagrams go back to.
func (a *association) currentClient() (net.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, net.ErrClosed
	}
	if a.client == nil {
		return nil, errors.New("inbound: the client has not sent a datagram yet")
	}
	return a.client, nil
}

// accepted reports whether a datagram may be relayed and, the first time one
// arrives, remembers the endpoint it came from. An association belongs to one
// client: without that check the socket would relay for anything that found
// its port.
func (a *association) accepted(from net.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return false
	}
	if a.client == nil {
		if a.expect != nil {
			a.client = a.expect
		} else {
			a.client = from
		}
	}
	return a.client != nil && from != nil && a.client.String() == from.String()
}

// forget drops a destination whose socket has failed, unless it was already
// replaced.
func (a *association) forget(key string, entry *datagramEntry) {
	a.mu.Lock()
	if current, ok := a.entries[key]; ok && current == entry {
		delete(a.entries, key)
	}
	a.mu.Unlock()
	_ = entry.conn.Close()
}

// Close stops the association and every destination socket it opened. A second
// call returns the result of the first.
func (a *association) Close() error {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		entries := make([]*datagramEntry, 0, len(a.entries))
		for _, entry := range a.entries {
			entries = append(entries, entry)
		}
		a.entries = make(map[string]*datagramEntry)
		a.mu.Unlock()

		a.closeErr = a.socket.Close()
		for _, entry := range entries {
			_ = entry.conn.Close()
		}
	})
	return a.closeErr
}
