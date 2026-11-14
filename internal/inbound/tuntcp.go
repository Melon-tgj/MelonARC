package inbound

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// Limits of the userspace TCP endpoint.
const (
	// tcpWindow is the receive window advertised in every packet. It is fixed
	// and large enough for the traffic this stage carries; scaling it would need
	// a window-scale negotiation and a buffer that can actually hold it.
	tcpWindow = 65535
	// minMSS and maxMSS bound the segment size derived from the device MTU and
	// the peer's advertised MSS.
	minMSS = 536
	maxMSS = 1460
	// tcpRTO starts at this value and doubles on every retransmission. A TUN
	// peer is on this host, so a short first retry is enough.
	tcpRTO      = 200 * time.Millisecond
	maxTCPRTO   = 2 * time.Second
	maxTCPRetry = 8
	// tcpTimeWait keeps a finished flow long enough to answer a retransmitted
	// FIN/ACK from the kernel instead of resetting the peer's socket.
	tcpTimeWait = 5 * time.Second
	// tcpCloseWait bounds how long closing the stack waits for handlers.
	tcpCloseWait = 5 * time.Second
)

type tcpState uint8

const (
	tcpSynReceived tcpState = iota
	tcpEstablished
	tcpClosed
)

// tcpFlow is the four-tuple of one TCP connection. A flow is the identity of a
// connection on a TUN device in the same way a socket pair is in the kernel.
type tcpFlow struct {
	src   ip4
	dst   ip4
	sport uint16
	dport uint16
}

// tcpStack owns the TCP flows of one TUN device. It is deliberately small: a
// userspace TCP implementation that only has to carry one client's streams over
// a local device does not need a congestion controller, SACK or window scaling.
// What it must get right is the sequence space, the checksums and half closes,
// because those are what a real kernel peer checks.
type tcpStack struct {
	svc *TUNService

	mu     sync.Mutex
	flows  map[tcpFlow]*tunTCPConn
	closed bool
	wg     sync.WaitGroup
}

func newTCPStack(svc *TUNService) *tcpStack {
	return &tcpStack{svc: svc, flows: make(map[tcpFlow]*tunTCPConn)}
}

// handle dispatches one TCP packet. A SYN opens a flow; a packet for an unknown
// flow is reset so the kernel does not keep retransmitting into a dead endpoint.
func (s *tcpStack) handle(pkt ipv4Packet) {
	seg, err := decodeTCP(pkt.Payload)
	if err != nil {
		s.svc.logger.Debug("tun tcp packet dropped", "error", err)
		return
	}
	flow := tcpFlow{src: pkt.Src, dst: pkt.Dst, sport: seg.SrcPort, dport: seg.DstPort}
	if seg.Flags&tcpFlagSYN != 0 && seg.Flags&tcpFlagACK == 0 {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		if conn := s.flows[flow]; conn != nil {
			s.mu.Unlock()
			conn.sendSynAck() // a retransmitted SYN
			return
		}
		target, ok := s.svc.destination(pkt, seg.DstPort)
		if !ok {
			s.mu.Unlock()
			return
		}
		conn := newTunTCPConn(s, flow, target, seg)
		s.flows[flow] = conn
		s.mu.Unlock()
		s.svc.logger.Debug("tun tcp opening", "source", flow.src.String(), "destination", target.String())
		conn.sendSynAck()
		return
	}
	s.mu.Lock()
	conn := s.flows[flow]
	s.mu.Unlock()
	if conn == nil {
		s.sendReset(pkt, seg)
		return
	}
	conn.handle(seg)
}

// writeTCP sends one segment from the server side of a flow back to the client.
func (s *tcpStack) writeTCP(flow tcpFlow, seq, ack uint32, flags uint8, mss uint16, payload []byte) {
	packet := appendTCPPacket(nil, flow.dst, flow.src, flow.dport, flow.sport, seq, ack, flags, mss, payload)
	if err := s.svc.writePacket(packet); err != nil {
		s.svc.logger.Debug("tun tcp packet not written", "error", err)
	}
}

// sendReset answers a packet for a flow that no longer exists.
func (s *tcpStack) sendReset(pkt ipv4Packet, seg tcpSegment) {
	ack := seg.Seq + uint32(len(seg.Data))
	if seg.Flags&tcpFlagSYN != 0 {
		ack++
	}
	if seg.Flags&tcpFlagFIN != 0 {
		ack++
	}
	seq := uint32(0)
	if seg.Flags&tcpFlagACK != 0 {
		seq = seg.Ack
	}
	packet := appendTCPPacket(nil, pkt.Dst, pkt.Src, seg.DstPort, seg.SrcPort,
		seq, ack, tcpFlagRST|tcpFlagACK, 0, nil)
	_ = s.svc.writePacket(packet)
}

// forget removes a flow if it is still the connection the caller closed.
func (s *tcpStack) forget(flow tcpFlow, conn *tunTCPConn) {
	s.mu.Lock()
	if s.flows[flow] == conn {
		delete(s.flows, flow)
	}
	s.mu.Unlock()
}

// spawn runs one connection's handler under the stack's wait group.
func (s *tcpStack) spawn(conn *tunTCPConn) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		conn.serve()
	}()
}

// close aborts every flow and waits a bounded time for the handlers to drain.
func (s *tcpStack) close() {
	s.mu.Lock()
	s.closed = true
	conns := make([]*tunTCPConn, 0, len(s.flows))
	for _, conn := range s.flows {
		conns = append(conns, conn)
	}
	s.flows = make(map[tcpFlow]*tunTCPConn)
	s.mu.Unlock()
	for _, conn := range conns {
		conn.abort()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(tcpCloseWait):
	}
}

// tunTCPConn is the TUN side of one TCP connection. It implements net.Conn, so
// the existing relay (with its single CloseWrite half-close implementation) can
// carry the connection without knowing where the bytes came from.
type tunTCPConn struct {
	stack  *tcpStack
	flow   tcpFlow
	target outbound.Target
	logger *slog.Logger

	mu         sync.Mutex
	iss        uint32
	rcvNxt     uint32
	sndNxt     uint32
	sndUna     uint32
	mss        uint16
	advertise  uint16
	state      tcpState
	finSent    bool
	started    bool
	closed     bool
	readUntil  time.Time
	writeUntil time.Time

	dataCh chan []byte
	eofCh  chan struct{}
	done   chan struct{}
	ackCh  chan struct{}

	eofOnce   sync.Once
	doneOnce  sync.Once
	closeOnce sync.Once

	readMu  sync.Mutex
	pending []byte
}

func newTunTCPConn(s *tcpStack, flow tcpFlow, target outbound.Target, seg tcpSegment) *tunTCPConn {
	var random [4]byte
	_, _ = rand.Read(random[:])
	iss := binary.BigEndian.Uint32(random[:])

	ours := uint16(maxMSS)
	if mtu := s.svc.mtu; mtu > 40 {
		if candidate := uint16(mtu - 40); candidate < ours {
			ours = candidate
		}
	}
	if ours < minMSS {
		ours = minMSS
	}
	peer := seg.MSS
	if peer == 0 || peer > ours {
		peer = ours
	}
	if peer < minMSS {
		peer = minMSS
	}
	return &tunTCPConn{
		stack:     s,
		flow:      flow,
		target:    target,
		logger:    s.svc.logger,
		iss:       iss,
		rcvNxt:    seg.Seq + 1,
		sndNxt:    iss + 1,
		sndUna:    iss,
		mss:       peer,
		advertise: ours,
		state:     tcpSynReceived,
		dataCh:    make(chan []byte, 256),
		eofCh:     make(chan struct{}),
		done:      make(chan struct{}),
		ackCh:     make(chan struct{}, 1),
	}
}

// sendSynAck completes the first half of the handshake. Retransmitted SYNs get
// the same sequence number, which is what makes the peer accept the retry.
func (c *tunTCPConn) sendSynAck() {
	c.mu.Lock()
	seq, ack, mss := c.iss, c.rcvNxt, c.advertise
	c.mu.Unlock()
	c.stack.writeTCP(c.flow, seq, ack, tcpFlagSYN|tcpFlagACK, mss, nil)
}

func (c *tunTCPConn) sendAck() {
	c.mu.Lock()
	seq, ack := c.sndNxt, c.rcvNxt
	c.mu.Unlock()
	c.stack.writeTCP(c.flow, seq, ack, tcpFlagACK, 0, nil)
}

// handle applies one segment to the connection's state. Everything that has to
// be kept past the device read (payloads) is copied here.
func (c *tunTCPConn) handle(seg tcpSegment) {
	if seg.Flags&tcpFlagRST != 0 {
		c.abort()
		return
	}
	if seg.Flags&tcpFlagACK != 0 {
		c.mu.Lock()
		if seqAfter(seg.Ack, c.sndUna) && !seqAfter(seg.Ack, c.sndNxt) {
			c.sndUna = seg.Ack
		}
		c.mu.Unlock()
		select {
		case c.ackCh <- struct{}{}:
		default:
		}
	}

	c.mu.Lock()
	synReceived := c.state == tcpSynReceived
	if synReceived && seg.Flags&tcpFlagACK != 0 && seg.Ack == c.iss+1 {
		c.state = tcpEstablished
		c.started = true
		c.mu.Unlock()
		c.stack.spawn(c)
	} else {
		c.mu.Unlock()
		if synReceived {
			return // the third handshake packet has not arrived yet
		}
	}

	if seg.Flags&tcpFlagSYN != 0 && seg.Flags&tcpFlagACK == 0 {
		c.sendSynAck()
		return
	}

	seq := seg.Seq
	if len(seg.Data) > 0 {
		c.mu.Lock()
		expected := c.rcvNxt
		c.mu.Unlock()
		if seq != expected {
			// A retransmission of bytes already acknowledged, or a gap. This
			// stack does not reassemble out-of-order data, so it acknowledges
			// what it has and lets the peer retransmit the rest.
			c.sendAck()
			return
		}
		payload := append([]byte(nil), seg.Data...)
		c.mu.Lock()
		c.rcvNxt += uint32(len(payload))
		c.mu.Unlock()
		select {
		case c.dataCh <- payload:
		case <-c.done:
			return
		}
		seq += uint32(len(payload))
		c.sendAck()
	}
	if seg.Flags&tcpFlagFIN != 0 {
		c.mu.Lock()
		expected, already := c.rcvNxt, c.peerEOF()
		if seq == expected && !already {
			c.rcvNxt++
			c.mu.Unlock()
			c.eofOnce.Do(func() { close(c.eofCh) })
			c.sendAck()
		} else {
			c.mu.Unlock()
			c.sendAck()
		}
	}
}

// peerEOF reports whether the EOF channel is already closed. It is called with
// c.mu held, so it must not take the lock again.
func (c *tunTCPConn) peerEOF() bool {
	select {
	case <-c.eofCh:
		return true
	default:
		return false
	}
}

// serve bridges the established connection to the rule pipeline.
func (c *tunTCPConn) serve() {
	metrics := c.stack.svc.metrics
	c.logger.Debug("tun tcp routing", "destination", c.target.String())
	upstream, _, err := c.stack.svc.handler.Stream(c.stack.svc.ctx,
		Request{Target: c.target, Network: networkTCP})
	if err != nil {
		c.logger.Debug("tun tcp destination could not be routed", "destination", c.target.String(), "error", err)
		c.reset()
		c.abort()
		return
	}
	c.logger.Debug("tun tcp routed", "destination", c.target.String())
	defer upstream.Close()
	defer c.Close()
	metrics.connectionOpened(protocolTUN)
	defer metrics.connectionClosed(protocolTUN)
	relay(c, upstream)
	c.logger.Debug("tun tcp relay finished", "destination", c.target.String())
}

// reset tells a peer whose dial failed that the connection is gone. Without it
// the kernel would keep retransmitting its request until its own timeout.
func (c *tunTCPConn) reset() {
	c.mu.Lock()
	seq, ack := c.sndNxt, c.rcvNxt
	c.mu.Unlock()
	c.stack.writeTCP(c.flow, seq, ack, tcpFlagRST|tcpFlagACK, 0, nil)
}

// Read implements net.Conn. It returns one in-order segment at a time; a
// segment larger than p keeps its remainder for the next call.
func (c *tunTCPConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	c.mu.Lock()
	deadline := c.readUntil
	c.mu.Unlock()
	timer, timeout := deadlineTimer(deadline)
	if timer != nil {
		defer timer.Stop()
	}
	for {
		select {
		case b := <-c.dataCh:
			n := copy(p, b)
			if n < len(b) {
				c.pending = append(c.pending[:0], b[n:]...)
			}
			return n, nil
		case <-c.eofCh:
			select {
			case b := <-c.dataCh:
				n := copy(p, b)
				if n < len(b) {
					c.pending = append(c.pending[:0], b[n:]...)
				}
				return n, nil
			default:
				return 0, io.EOF
			}
		case <-c.done:
			return 0, net.ErrClosed
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// Write implements net.Conn. Payload is split into MSS-sized segments, which
// are sent together (the advertised window is 65535) and retransmitted until a
// cumulative ACK covers them. A write larger than the window is sent in rounds.
func (c *tunTCPConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	c.mu.Lock()
	mss, deadline := int(c.mss), c.writeUntil
	c.mu.Unlock()
	if mss <= 0 {
		mss = minMSS
	}
	for offset := 0; offset < len(p); {
		end := offset + tcpWindow
		if end > len(p) {
			end = len(p)
		}
		if err := c.writeRound(p[offset:end], mss, deadline); err != nil {
			return offset, err
		}
		offset = end
	}
	return len(p), nil
}

type pendingSegment struct {
	seq  uint32
	data []byte
}

func (c *tunTCPConn) writeRound(p []byte, mss int, deadline time.Time) error {
	c.mu.Lock()
	ack := c.rcvNxt
	segments := make([]pendingSegment, 0, (len(p)+mss-1)/mss)
	for offset := 0; offset < len(p); {
		end := offset + mss
		if end > len(p) {
			end = len(p)
		}
		data := append([]byte(nil), p[offset:end]...)
		segments = append(segments, pendingSegment{seq: c.sndNxt, data: data})
		c.sndNxt += uint32(len(data))
		offset = end
	}
	target := c.sndNxt
	state := c.state
	c.mu.Unlock()
	if state != tcpEstablished {
		return net.ErrClosed
	}
	c.sendSegments(segments, ack)

	timer, timeout := deadlineTimer(deadline)
	if timer != nil {
		defer timer.Stop()
	}
	rto := tcpRTO
	retries := 0
	for {
		c.mu.Lock()
		unacknowledged := c.sndUna
		c.mu.Unlock()
		if seqAtLeast(unacknowledged, target) {
			return nil
		}
		retry := time.NewTimer(rto)
		select {
		case <-c.ackCh:
			retry.Stop()
		case <-retry.C:
			retries++
			if retries > maxTCPRetry {
				return errors.New("inbound: TUN peer stopped acknowledging")
			}
			c.sendSegments(segments, ack)
			if rto < maxTCPRTO {
				rto *= 2
				if rto > maxTCPRTO {
					rto = maxTCPRTO
				}
			}
		case <-c.done:
			retry.Stop()
			return net.ErrClosed
		case <-timeout:
			retry.Stop()
			return os.ErrDeadlineExceeded
		}
	}
}

func (c *tunTCPConn) sendSegments(segments []pendingSegment, ack uint32) {
	for _, seg := range segments {
		c.stack.writeTCP(c.flow, seg.seq, ack, tcpFlagACK|tcpFlagPSH, 0, seg.data)
	}
}

// deadlineTimer returns a stopped-safe timer channel. A zero deadline means
// no deadline, represented by a nil channel that no select case ever receives.
func deadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	wait := time.Until(deadline)
	if wait < 0 {
		wait = 0
	}
	timer := time.NewTimer(wait)
	return timer, timer.C
}

// CloseWrite implements the half close the shared relay calls. It sends a FIN
// once and leaves reads open so the peer's remaining bytes still arrive.
func (c *tunTCPConn) CloseWrite() error {
	c.mu.Lock()
	if c.finSent || c.state == tcpClosed {
		c.mu.Unlock()
		return nil
	}
	c.finSent = true
	seq, ack := c.sndNxt, c.rcvNxt
	c.sndNxt++
	c.mu.Unlock()
	c.stack.writeTCP(c.flow, seq, ack, tcpFlagFIN|tcpFlagACK, 0, nil)
	return nil
}

// Close implements net.Conn. A connection that never completed its handshake is
// reset; a finished one sends a FIN if the relay did not already, and the flow is
// kept briefly to answer the peer's final ACK.
func (c *tunTCPConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		established := c.state == tcpEstablished
		finSent := c.finSent
		c.finSent = true
		seq, ack := c.sndNxt, c.rcvNxt
		c.sndNxt++
		c.state = tcpClosed
		c.closed = true
		c.mu.Unlock()
		c.doneOnce.Do(func() { close(c.done) })
		if !established {
			c.reset()
			c.stack.forget(c.flow, c)
			return
		}
		if !finSent {
			c.stack.writeTCP(c.flow, seq, ack, tcpFlagFIN|tcpFlagACK, 0, nil)
		}
		time.AfterFunc(tcpTimeWait, func() { c.stack.forget(c.flow, c) })
	})
	return nil
}

// abort stops a connection immediately (a peer reset or a device shutdown).
func (c *tunTCPConn) abort() {
	_ = c.Close()
	c.stack.forget(c.flow, c)
}

func (c *tunTCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: c.flow.dst.IP(), Port: int(c.flow.dport)}
}

func (c *tunTCPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: c.flow.src.IP(), Port: int(c.flow.sport)}
}

func (c *tunTCPConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readUntil, c.writeUntil = t, t
	c.mu.Unlock()
	return nil
}

func (c *tunTCPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readUntil = t
	c.mu.Unlock()
	return nil
}

func (c *tunTCPConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeUntil = t
	c.mu.Unlock()
	return nil
}
