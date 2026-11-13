package dns

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// testRecord is one resource record a fake server puts in an answer.
type testRecord struct {
	typ uint16
	ip  net.IP
	ttl uint32
}

// testSOA is the authority record that gives a negative answer its lifetime.
type testSOA struct {
	name    string
	rname   string
	ttl     uint32
	minimum uint32
}

// zoneEntry is what a fake server knows about one name.
type zoneEntry struct {
	v4    []net.IP
	v6    []net.IP
	ttl   uint32
	rcode int
	soa   *testSOA
	// silent makes the server read the question and answer nothing, which is
	// how a dead upstream looks to a client.
	silent bool
}

// fakeDNS is a DNS server the tests run in process. It answers A and AAAA
// questions from a zone table and records every question it was asked.
//
// The stream listener always runs. The datagram socket is optional, because the
// development sandbox forbids a datagram socket from sending to an address it is
// not connected to: without it the client's datagram attempt fails at once and
// the tests that need a datagram reply are skipped.
type fakeDNS struct {
	t   *testing.T
	tcp net.Listener
	udp *net.UDPConn

	mu       sync.Mutex
	zone     map[string]zoneEntry
	asked    []string
	truncate map[string]bool
	closed   bool
	wg       sync.WaitGroup
}

// newFakeDNS starts a server that only listens on TCP.
func newFakeDNS(t *testing.T, zone map[string]zoneEntry) *fakeDNS {
	t.Helper()
	s := &fakeDNS{t: t, zone: zone, truncate: map[string]bool{}}
	if s.zone == nil {
		s.zone = map[string]zoneEntry{}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	s.tcp = listener
	s.wg.Add(1)
	go s.serveTCP()
	t.Cleanup(s.close)
	return s
}

// newFakeDNSUDP starts a server on both transports, on the same port.
func newFakeDNSUDP(t *testing.T, zone map[string]zoneEntry) *fakeDNS {
	t.Helper()
	s := newFakeDNS(t, zone)
	addr := s.addr()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("listen udp on %s: %v", addr, err)
	}
	s.udp = conn
	s.wg.Add(1)
	go s.serveUDP()
	return s
}

// addr is the address a client should be given.
func (s *fakeDNS) addr() string { return s.tcp.Addr().String() }

// truncateOver answers a UDP question for name with the truncated bit set, so
// the client has to retry over TCP.
func (s *fakeDNS) truncateOver(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.truncate[name] = true
}

// questions returns the names asked, in order.
func (s *fakeDNS) questions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...)
}

// close stops both loops.
func (s *fakeDNS) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	_ = s.tcp.Close()
	if s.udp != nil {
		_ = s.udp.Close()
	}
	s.wg.Wait()
}

func (s *fakeDNS) serveTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			var length uint16
			if err := binary.Read(io.LimitReader(conn, 2), binary.BigEndian, &length); err != nil {
				return
			}
			query := make([]byte, length)
			if _, err := io.ReadFull(conn, query); err != nil {
				return
			}
			answer, ok := s.answer(query, false)
			if !ok {
				return
			}
			header := make([]byte, 2, 2+len(answer))
			binary.BigEndian.PutUint16(header, uint16(len(answer)))
			_, _ = conn.Write(append(header, answer...))
		}()
	}
}

func (s *fakeDNS) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, maxUDPMessage)
	for {
		n, from, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		answer, ok := s.answer(buf[:n], true)
		if !ok {
			continue
		}
		_, _ = s.udp.WriteToUDP(answer, from)
	}
}

// answer builds the reply to one query. The transport decides whether a name is
// truncated: a UDP answer is cut short, the same question over TCP is answered
// in full.
func (s *fakeDNS) answer(query []byte, datagram bool) ([]byte, bool) {
	question, name, qtype, ok := parseTestQuestion(s.t, query)
	if !ok {
		return nil, false
	}
	s.mu.Lock()
	s.asked = append(s.asked, name)
	entry, known := s.zone[name]
	cut := s.truncate[name] && datagram
	s.mu.Unlock()

	if !known {
		entry = zoneEntry{rcode: rcodeNXDomain, soa: &testSOA{name: "test", rname: "ns.test", ttl: 60, minimum: 60}}
	}
	if entry.silent {
		return nil, false
	}
	if cut {
		return buildTestResponse(s.t, query, question, nil, rcodeNoError, true, nil), true
	}
	if entry.rcode != rcodeNoError {
		return buildTestResponse(s.t, query, question, nil, entry.rcode, false, entry.soa), true
	}
	var recs []testRecord
	switch qtype {
	case typeA:
		for _, ip := range entry.v4 {
			recs = append(recs, testRecord{typ: typeA, ip: ip, ttl: entry.ttl})
		}
	case typeAAAA:
		for _, ip := range entry.v6 {
			recs = append(recs, testRecord{typ: typeAAAA, ip: ip, ttl: entry.ttl})
		}
	}
	return buildTestResponse(s.t, query, question, recs, rcodeNoError, false, entry.soa), true
}

// parseTestQuestion reads the identifier and the single question of a query and
// returns the question bytes so the reply can echo them.
func parseTestQuestion(t *testing.T, query []byte) (question []byte, name string, qtype uint16, ok bool) {
	t.Helper()
	if len(query) < headerLen {
		return nil, "", 0, false
	}
	if binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, "", 0, false
	}
	name, off, err := readName(query, headerLen)
	if err != nil {
		t.Logf("fake server: %v", err)
		return nil, "", 0, false
	}
	if off+4 > len(query) {
		return nil, "", 0, false
	}
	return query[headerLen : off+4], name, binary.BigEndian.Uint16(query[off : off+2]), true
}

// buildTestResponse encodes a reply with one question and zero or more answers.
func buildTestResponse(t *testing.T, query, question []byte, recs []testRecord, rcode int, truncated bool, soa *testSOA) []byte {
	t.Helper()
	out := make([]byte, headerLen, headerLen+len(question)+128)
	copy(out[0:2], query[0:2])
	flags := uint16(0x8180) // response, recursion desired and available
	if truncated {
		flags |= flagTruncated
	}
	flags |= uint16(rcode)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], uint16(len(recs)))
	if soa != nil {
		binary.BigEndian.PutUint16(out[8:10], 1)
	}
	out = append(out, question...)
	for _, rec := range recs {
		out = append(out, 0xc0, 0x0c) // the name of the question
		out = binary.BigEndian.AppendUint16(out, rec.typ)
		out = binary.BigEndian.AppendUint16(out, classINET)
		out = binary.BigEndian.AppendUint32(out, rec.ttl)
		rdata := rec.ip.To4()
		if rec.typ == typeAAAA {
			rdata = rec.ip.To16()
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
		out = append(out, rdata...)
	}
	if soa != nil {
		out = append(out, 0xc0, 0x0c)
		out = binary.BigEndian.AppendUint16(out, typeSOA)
		out = binary.BigEndian.AppendUint16(out, classINET)
		out = binary.BigEndian.AppendUint32(out, soa.ttl)
		rdata := append([]byte(nil), encodeTestName(soa.name)...)
		rdata = append(rdata, encodeTestName(soa.rname)...)
		rdata = binary.BigEndian.AppendUint32(rdata, 1)           // serial
		rdata = binary.BigEndian.AppendUint32(rdata, 3600)        // refresh
		rdata = binary.BigEndian.AppendUint32(rdata, 600)         // retry
		rdata = binary.BigEndian.AppendUint32(rdata, 86400)       // expire
		rdata = binary.BigEndian.AppendUint32(rdata, soa.minimum) // minimum
		out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
		out = append(out, rdata...)
	}
	return out
}

// encodeTestName writes a name as labels.
func encodeTestName(name string) []byte {
	out := make([]byte, 0, len(name)+2)
	label := make([]byte, 0, 8)
	flush := func() {
		if len(label) == 0 {
			return
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
		label = label[:0]
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			flush()
			continue
		}
		label = append(label, name[i])
	}
	flush()
	return append(out, 0)
}

// datagramSendAllowed reports whether this environment lets a datagram socket
// send to an address it is not connected to, which is what a UDP DNS server has
// to do. Some sandboxes deny sendto outright; there the datagram tests skip
// instead of failing for a reason unrelated to the code. The outbound package
// carries the same guard for the same reason.
func datagramSendAllowed(t *testing.T) bool {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Logf("skipping datagram test: cannot bind a udp socket: %v", err)
		return false
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Logf("skipping datagram test: cannot dial a udp socket: %v", err)
		return false
	}
	defer client.Close()
	if _, err := server.WriteToUDP([]byte("probe"), client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Logf("skipping datagram test: this environment denies sendto to an unconnected peer: %v", err)
		return false
	}
	return true
}
