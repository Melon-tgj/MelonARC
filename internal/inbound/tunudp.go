package inbound

import (
	"strconv"
	"sync"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// udpFlow is the four-tuple of one UDP session as it appeared on the wire. The
// source is part of the key: two applications talking to the same server must
// get their replies back separately.
type udpFlow struct {
	src   ip4
	dst   ip4
	sport uint16
	dport uint16
}

// udpSession is one (source, destination) pair carried over a shared
// association. lastUsed is refreshed by packets in both directions.
type udpSession struct {
	flow     udpFlow
	target   outbound.Target
	assoc    *DatagramAssociation
	lastUsed time.Time
}

// relayState is the TUN side of one shared association. One reader goroutine
// serves all its sessions, because a shared connection has a single stream of
// replies and concurrent readers would split it arbitrarily.
type relayState struct {
	sessions map[udpFlow]*udpSession
}

// udpDispatcher keeps the UDP session table, routes new destinations through
// Handler.Datagrams and writes replies back into the device as IP packets.
type udpDispatcher struct {
	svc     *TUNService
	timeout time.Duration

	mu       sync.Mutex
	sessions map[udpFlow]*udpSession
	relays   map[*DatagramAssociation]*relayState
	closed   bool
	wg       sync.WaitGroup
}

func newUDPDispatcher(svc *TUNService, timeout time.Duration) *udpDispatcher {
	return &udpDispatcher{
		svc:      svc,
		timeout:  timeout,
		sessions: make(map[udpFlow]*udpSession),
		relays:   make(map[*DatagramAssociation]*relayState),
	}
}

// handle forwards one datagram, opening a session on the first packet of a flow.
func (d *udpDispatcher) handle(pkt ipv4Packet, seg udpSegment) {
	flow := udpFlow{src: pkt.Src, dst: pkt.Dst, sport: seg.SrcPort, dport: seg.DstPort}
	target, ok := d.svc.destination(pkt, seg.DstPort)
	if !ok {
		return
	}
	payload := append([]byte(nil), seg.Data...)

	d.mu.Lock()
	if session := d.sessions[flow]; session != nil {
		session.lastUsed = d.svc.now()
		assoc, dest := session.assoc, session.target
		d.mu.Unlock()
		if _, err := assoc.Conn.WriteTo(payload, dest); err != nil {
			d.svc.logger.Debug("tun udp session failed on write", "destination", dest.String(), "error", err)
			d.remove(flow, session)
		}
		return
	}
	d.mu.Unlock()

	source := flow.src.String() + ":" + strconv.Itoa(int(flow.sport))
	assoc, err := d.svc.handler.Datagrams(d.svc.ctx,
		Request{Target: target, Network: networkUDP, Protocol: protocolTUN}, source)
	if err != nil {
		d.svc.logger.Debug("tun udp destination could not be routed", "destination", target.String(), "error", err)
		return
	}

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		assoc.Release()
		return
	}
	// A second packet of the same flow may have opened the session while the
	// route was being resolved: release the extra reference and use the winner.
	if existing := d.sessions[flow]; existing != nil {
		existing.lastUsed = d.svc.now()
		winner, dest := existing.assoc, existing.target
		d.mu.Unlock()
		assoc.Release()
		if _, err := winner.Conn.WriteTo(payload, dest); err != nil {
			d.remove(flow, existing)
		}
		return
	}
	if len(d.sessions) >= maxUDPSessions {
		d.evictOldestLocked()
	}
	session := &udpSession{
		flow:     flow,
		target:   target,
		assoc:    assoc,
		lastUsed: d.svc.now(),
	}
	d.sessions[flow] = session
	state := d.relays[assoc]
	if state == nil {
		state = &relayState{sessions: make(map[udpFlow]*udpSession)}
		d.relays[assoc] = state
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.readReplies(assoc, state)
		}()
	}
	state.sessions[flow] = session
	d.mu.Unlock()
	d.svc.metrics.tunDatagramOpened()

	if _, err := assoc.Conn.WriteTo(payload, target); err != nil {
		d.svc.logger.Debug("tun udp session failed on first write", "destination", target.String(), "error", err)
		d.remove(flow, session)
	}
}

// readReplies carries every answer of one shared association back to the source
// that asked for it, wrapped in an IP/UDP packet whose addresses are the mirror
// of the original request.
func (d *udpDispatcher) readReplies(assoc *DatagramAssociation, state *relayState) {
	buf := make([]byte, maxDatagramPayload)
	for {
		n, from, err := assoc.Conn.ReadFrom(buf)
		if err != nil {
			d.dropRelay(assoc, state)
			return
		}
		payload := append([]byte(nil), buf[:n]...)
		d.mu.Lock()
		session := findReplyLocked(state, from)
		var flow udpFlow
		if session != nil {
			flow = session.flow
			session.lastUsed = d.svc.now()
		}
		d.mu.Unlock()
		if session == nil {
			continue
		}
		reply := appendUDPPacket(nil, flow.dst, flow.src, flow.dport, flow.sport, payload)
		if err := d.svc.writePacket(reply); err != nil {
			d.svc.logger.Debug("tun udp reply not written", "destination", flow.dst.String(), "error", err)
		}
	}
}

// findReplyLocked matches a reply's reported source to a session. An exact
// destination match is preferred; a proxy that answers with a resolved IP
// rather than the name it was given still matches when that port has only one
// candidate session on this association.
func findReplyLocked(state *relayState, from outbound.Target) *udpSession {
	key := from.String()
	for _, session := range state.sessions {
		if session.target.String() == key {
			return session
		}
	}
	var candidate *udpSession
	for _, session := range state.sessions {
		if session.flow.dport != from.Port {
			continue
		}
		if candidate != nil {
			return nil // ambiguous: dropping is safer than guessing
		}
		candidate = session
	}
	return candidate
}

// expire removes every session idle for at least the configured timeout, and
// with the last session of an association releases that association as well.
func (d *udpDispatcher) expire(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for flow, session := range d.sessions {
		if now.Sub(session.lastUsed) >= d.timeout {
			d.removeLocked(flow, session)
		}
	}
}

// evictOldestLocked makes room for a new session. The caller holds d.mu.
func (d *udpDispatcher) evictOldestLocked() {
	var oldestFlow udpFlow
	var oldest *udpSession
	for flow, session := range d.sessions {
		if oldest == nil || session.lastUsed.Before(oldest.lastUsed) {
			oldestFlow, oldest = flow, session
		}
	}
	if oldest != nil {
		d.removeLocked(oldestFlow, oldest)
	}
}

// remove drops one session if it is still the one registered for its flow.
func (d *udpDispatcher) remove(flow udpFlow, session *udpSession) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.removeLocked(flow, session)
}

// removeLocked releases a session and its reference. The caller holds d.mu.
func (d *udpDispatcher) removeLocked(flow udpFlow, session *udpSession) {
	if d.sessions[flow] != session {
		return
	}
	delete(d.sessions, flow)
	if state := d.relays[session.assoc]; state != nil {
		delete(state.sessions, flow)
		if len(state.sessions) == 0 {
			delete(d.relays, session.assoc)
		}
	}
	session.assoc.Release()
	d.svc.metrics.tunDatagramClosed()
}

// dropRelay ends every session whose association stopped producing replies.
func (d *udpDispatcher) dropRelay(assoc *DatagramAssociation, state *relayState) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.relays[assoc] == state {
		delete(d.relays, assoc)
	}
	for flow, session := range state.sessions {
		if d.sessions[flow] == session {
			delete(d.sessions, flow)
			session.assoc.Release()
			d.svc.metrics.tunDatagramClosed()
		}
	}
}

// close drops every session and waits for the reply readers to return. The
// associations are closed by the references being released, which is what
// unblocks their readers.
func (d *udpDispatcher) close() {
	d.mu.Lock()
	d.closed = true
	sessions := make([]*udpSession, 0, len(d.sessions))
	for _, session := range d.sessions {
		sessions = append(sessions, session)
	}
	d.sessions = make(map[udpFlow]*udpSession)
	d.relays = make(map[*DatagramAssociation]*relayState)
	d.mu.Unlock()

	for _, session := range sessions {
		session.assoc.Release()
		d.svc.metrics.tunDatagramClosed()
	}
	d.wg.Wait()
}
