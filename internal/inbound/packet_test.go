package inbound

import (
	"encoding/binary"
	"errors"
	"testing"
)

func testIPs() (ip4, ip4) {
	return ip4{198, 18, 0, 2}, ip4{198, 18, 0, 9}
}

// verifyTransportChecksum recomputes a TCP/UDP checksum the way a receiver
// does, from the wire pseudo header and the segment including its checksum
// field. It deliberately does not call transportChecksum: using the generator
// to check itself would hide a wrong pseudo header. A valid packet folds to
// zero (all ones in one's complement).
func verifyTransportChecksum(t *testing.T, packet []byte) {
	t.Helper()
	pkt, err := decodeIPv4(packet)
	if err != nil {
		t.Fatalf("decodeIPv4: %v", err)
	}
	pseudo := make([]byte, 0, 12)
	pseudo = append(pseudo, pkt.Src[:]...)
	pseudo = append(pseudo, pkt.Dst[:]...)
	pseudo = append(pseudo, 0, pkt.Protocol)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(pkt.Payload)))
	pseudo = append(pseudo, length[:]...)
	sum := sumBytes(pseudo, 0)
	sum = sumBytes(pkt.Payload, sum)
	if got := foldSum(sum); got != 0 {
		t.Fatalf("%s checksum does not verify against a receiver-side pseudo header: %#x",
			map[uint8]string{protoTCP: "TCP", protoUDP: "UDP"}[pkt.Protocol], got)
	}
}

func TestDecodeIPv4RejectsMalformedPackets(t *testing.T) {
	cases := []struct {
		name string
		make func() []byte
		want error
	}{
		{"short", func() []byte { return make([]byte, 19) }, errShortIPv4},
		{"not ipv4", func() []byte { b := make([]byte, 20); b[0] = 0x65; return b }, errNotIPv4},
		{"short ihl", func() []byte { b := make([]byte, 20); b[0] = 0x44; return b }, errBadIPv4Len},
		{"total too large", func() []byte {
			b := make([]byte, 20)
			b[0] = 0x45
			binary.BigEndian.PutUint16(b[2:4], 40)
			return b
		}, errBadIPv4Len},
		{"fragment", func() []byte {
			b := make([]byte, 20)
			b[0] = 0x45
			binary.BigEndian.PutUint16(b[2:4], 20)
			binary.BigEndian.PutUint16(b[6:8], 0x2000)
			return b
		}, errFragment},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeIPv4(tc.make()); !errors.Is(err, tc.want) {
				t.Fatalf("decodeIPv4 error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestIPv4UDPTCPRoundTrip(t *testing.T) {
	src, dst := testIPs()
	packet := appendUDPPacket(nil, src, dst, 41000, 9999, []byte("melonarc udp"))
	pkt, err := decodeIPv4(packet)
	if err != nil {
		t.Fatalf("decodeIPv4: %v", err)
	}
	if pkt.Src != src || pkt.Dst != dst || pkt.Protocol != protoUDP {
		t.Fatalf("header = %+v", pkt)
	}
	if checksum(packet[:20], 0) != 0 {
		t.Fatal("the IPv4 header checksum does not verify")
	}
	seg, err := decodeUDP(pkt.Payload)
	if err != nil {
		t.Fatalf("decodeUDP: %v", err)
	}
	if seg.SrcPort != 41000 || seg.DstPort != 9999 || string(seg.Data) != "melonarc udp" {
		t.Fatalf("udp segment = %+v payload %q", seg, seg.Data)
	}
	verifyTransportChecksum(t, packet)

	packet = appendTCPPacket(nil, src, dst, 41000, 80, 1000, 2000,
		tcpFlagSYN|tcpFlagACK, 1460, []byte("tcp payload"))
	pkt, err = decodeIPv4(packet)
	if err != nil {
		t.Fatalf("decodeIPv4 tcp: %v", err)
	}
	if pkt.Protocol != protoTCP {
		t.Fatalf("protocol = %d", pkt.Protocol)
	}
	if checksum(packet[:20], 0) != 0 {
		t.Fatal("the IPv4 header checksum does not verify (tcp)")
	}
	tcp, err := decodeTCP(pkt.Payload)
	if err != nil {
		t.Fatalf("decodeTCP: %v", err)
	}
	if tcp.SrcPort != 41000 || tcp.DstPort != 80 || tcp.Seq != 1000 || tcp.Ack != 2000 {
		t.Fatalf("tcp segment = %+v", tcp)
	}
	if tcp.Flags != tcpFlagSYN|tcpFlagACK || tcp.MSS != 1460 || string(tcp.Data) != "tcp payload" {
		t.Fatalf("tcp flags/mss/data = %#x/%d/%q", tcp.Flags, tcp.MSS, tcp.Data)
	}
	verifyTransportChecksum(t, packet)
}

func TestTransportChecksumPseudoHeader(t *testing.T) {
	src, dst := testIPs()
	// The protocol byte is the low half of the pseudo header word. A shift here
	// makes every emitted checksum wrong even though the generator's own check
	// still agrees with itself.
	cases := []struct {
		name     string
		protocol uint8
		make     func() []byte
	}{
		{"udp", protoUDP, func() []byte {
			return appendUDPPacket(nil, src, dst, 41000, 53, []byte("query"))
		}},
		{"tcp", protoTCP, func() []byte {
			return appendTCPPacket(nil, src, dst, 41000, 80, 1, 2, tcpFlagSYN|tcpFlagACK, 1460, nil)
		}},
		{"tcp with data", protoTCP, func() []byte {
			return appendTCPPacket(nil, src, dst, 41000, 80, 1, 2, tcpFlagACK|tcpFlagPSH, 0, []byte("odd"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			packet := tc.make()
			verifyTransportChecksum(t, packet)
			pkt, err := decodeIPv4(packet)
			if err != nil {
				t.Fatalf("decodeIPv4: %v", err)
			}
			if pkt.Protocol != tc.protocol {
				t.Fatalf("protocol = %d, want %d", pkt.Protocol, tc.protocol)
			}
		})
	}
}

func TestDecodeTransportRejectsTruncatedSegments(t *testing.T) {
	if _, err := decodeTCP(make([]byte, 19)); !errors.Is(err, errShortTCP) {
		t.Fatalf("decodeTCP short = %v", err)
	}
	bad := make([]byte, 20)
	bad[12] = 0xf0 // data offset 15 means 60 bytes of header
	if _, err := decodeTCP(bad); !errors.Is(err, errBadTCPLen) {
		t.Fatalf("decodeTCP bad offset = %v", err)
	}
	if _, err := decodeUDP(make([]byte, 7)); !errors.Is(err, errShortUDP) {
		t.Fatalf("decodeUDP short = %v", err)
	}
	badUDP := make([]byte, 8)
	binary.BigEndian.PutUint16(badUDP[4:6], 40)
	if _, err := decodeUDP(badUDP); !errors.Is(err, errBadUDPLen) {
		t.Fatalf("decodeUDP bad length = %v", err)
	}
}

func TestDecodeTCPSkipsUnknownOptions(t *testing.T) {
	// A SYN with a NOP, a timestamp option and an MSS option. The parser must
	// skip the unknown ones and still find the MSS at the end.
	options := []byte{
		1,                             // padding
		8, 10, 0, 0, 0, 0, 0, 0, 0, 0, // timestamp
		2, 4, 0x04, 0xb0, // MSS = 1200
		0, // end of options
	}
	seg := make([]byte, 20+len(options))
	binary.BigEndian.PutUint16(seg[0:2], 41000)
	binary.BigEndian.PutUint16(seg[2:4], 80)
	seg[12] = byte(len(seg)/4) << 4
	seg[13] = tcpFlagSYN
	copy(seg[20:], options)
	got, err := decodeTCP(seg)
	if err != nil {
		t.Fatalf("decodeTCP: %v", err)
	}
	if got.MSS != 1200 {
		t.Fatalf("MSS = %d, want 1200 from the option after the unknown ones", got.MSS)
	}
	if string(got.Data) != "" {
		t.Fatalf("data = %q, want only the header", got.Data)
	}
}

func TestICMPEchoReply(t *testing.T) {
	src, dst := testIPs()
	request := []byte{8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, 'p', 'i', 'n', 'g'}
	// Recompute the request checksum first, so the reply's checksum can be
	// verified against a well-formed request.
	binary.BigEndian.PutUint16(request[2:4], checksum(request, 0))
	packet, err := appendICMPEchoReply(nil, dst, src, request)
	if err != nil {
		t.Fatalf("appendICMPEchoReply: %v", err)
	}
	pkt, err := decodeIPv4(packet)
	if err != nil {
		t.Fatalf("decodeIPv4: %v", err)
	}
	if pkt.Src != dst || pkt.Dst != src || pkt.Protocol != protoICMP {
		t.Fatalf("icmp header = %+v", pkt)
	}
	if pkt.Payload[0] != 0 || string(pkt.Payload[8:]) != "ping" {
		t.Fatalf("icmp payload = %v", pkt.Payload)
	}
	if got := checksum(pkt.Payload, 0); got != 0 {
		t.Fatalf("icmp checksum does not verify: %#x", got)
	}
	if _, err := appendICMPEchoReply(nil, dst, src, []byte{3, 0, 0, 0}); err == nil {
		t.Fatal("a non-echo ICMP type was answered")
	}
}

func TestSequenceComparisonWraps(t *testing.T) {
	if !seqAfter(10, 9) || seqAfter(9, 10) {
		t.Fatal("plain sequence comparison is wrong")
	}
	if !seqAfter(1, ^uint32(0)) {
		t.Fatal("a wrapped sequence number was not recognised")
	}
	if !seqAtLeast(5, 5) || seqAtLeast(4, 5) {
		t.Fatal("seqAtLeast is wrong")
	}
}
