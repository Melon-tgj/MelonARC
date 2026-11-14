package inbound

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
)

// The IP protocols a TUN device carries in this stage. Anything else is dropped
// rather than guessed at: the packet parser is deliberately a closed set.
const (
	protoICMP uint8 = 1
	protoTCP  uint8 = 6
	protoUDP  uint8 = 17

	ipv4MinHeader = 20
	udpHeaderLen  = 8
	tcpMinHeader  = 20

	// tcpFlag* are the control bits of byte 13 of a TCP header.
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10
)

// Errors the packet decoder reports. They are all "drop this packet" outcomes:
// a malformed or fragmented packet cannot be routed, and silently treating it as
// something else would be worse than losing it.
var (
	errShortIPv4  = errors.New("inbound: packet is shorter than an IPv4 header")
	errNotIPv4    = errors.New("inbound: packet is not IPv4")
	errBadIPv4Len = errors.New("inbound: IPv4 header or total length is invalid")
	errFragment   = errors.New("inbound: fragmented IPv4 packets are not supported")
	errShortTCP   = errors.New("inbound: packet is shorter than a TCP header")
	errBadTCPLen  = errors.New("inbound: TCP data offset is invalid")
	errShortUDP   = errors.New("inbound: packet is shorter than a UDP header")
	errBadUDPLen  = errors.New("inbound: UDP length does not match the packet")
	errShortICMP  = errors.New("inbound: packet is shorter than an ICMP echo header")
)

// ip4 is an IPv4 address in its wire form. It is comparable, so it can be a
// session key without allocating or normalising a net.IP first.
type ip4 [4]byte

func toIP4(ip net.IP) ip4 {
	v4 := ip.To4()
	if v4 == nil {
		return ip4{}
	}
	return ip4(v4)
}

func (a ip4) IP() net.IP { return net.IP(a[:]) }

func (a ip4) String() string { return net.IP(a[:]).String() }

// ipv4Packet is one decoded packet. Payload is the transport header plus its
// data and aliases the buffer the device read into, so a caller that keeps it
// past the read has to copy it.
type ipv4Packet struct {
	Src      ip4
	Dst      ip4
	Protocol uint8
	Payload  []byte
}

// decodeIPv4 reads one raw IPv4 packet. IP options are skipped by the header
// length, and fragments are rejected: this stage has no reassembly, and routing
// only the first fragment of a datagram would be a silent misroute.
func decodeIPv4(b []byte) (ipv4Packet, error) {
	if len(b) < ipv4MinHeader {
		return ipv4Packet{}, errShortIPv4
	}
	if b[0]>>4 != 4 {
		return ipv4Packet{}, errNotIPv4
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < ipv4MinHeader || len(b) < ihl {
		return ipv4Packet{}, errBadIPv4Len
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl || total > len(b) {
		return ipv4Packet{}, errBadIPv4Len
	}
	frag := binary.BigEndian.Uint16(b[6:8])
	if frag&0x2000 != 0 || frag&0x1fff != 0 {
		return ipv4Packet{}, errFragment
	}
	return ipv4Packet{
		Src:      ip4(b[12:16]),
		Dst:      ip4(b[16:20]),
		Protocol: b[9],
		Payload:  b[ihl:total],
	}, nil
}

// tcpSegment is the part of a TCP header this stack uses. Options are reduced to
// the MSS the peer advertised; everything else is skipped by its declared size.
type tcpSegment struct {
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   uint8
	Window  uint16
	MSS     uint16
	Data    []byte
}

func decodeTCP(b []byte) (tcpSegment, error) {
	if len(b) < tcpMinHeader {
		return tcpSegment{}, errShortTCP
	}
	doff := int(b[12]>>4) * 4
	if doff < tcpMinHeader || len(b) < doff {
		return tcpSegment{}, errBadTCPLen
	}
	seg := tcpSegment{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		Seq:     binary.BigEndian.Uint32(b[4:8]),
		Ack:     binary.BigEndian.Uint32(b[8:12]),
		Flags:   b[13],
		Window:  binary.BigEndian.Uint16(b[14:16]),
		Data:    b[doff:],
	}
	for off := tcpMinHeader; off < doff; {
		kind := b[off]
		if kind == 0 || kind == 1 { // end of options, or a one-byte padding
			if kind == 0 {
				break
			}
			off++
			continue
		}
		if off+2 > doff {
			break
		}
		length := int(b[off+1])
		if length < 2 || off+length > doff {
			break
		}
		if kind == 2 && length == 4 {
			seg.MSS = binary.BigEndian.Uint16(b[off+2 : off+4])
		}
		off += length
	}
	return seg, nil
}

// udpSegment is one UDP datagram as it appeared on the wire.
type udpSegment struct {
	SrcPort uint16
	DstPort uint16
	Data    []byte
}

func decodeUDP(b []byte) (udpSegment, error) {
	if len(b) < udpHeaderLen {
		return udpSegment{}, errShortUDP
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if length < udpHeaderLen || length > len(b) {
		return udpSegment{}, errBadUDPLen
	}
	return udpSegment{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		Data:    b[udpHeaderLen:length],
	}, nil
}

// ipID is shared by every packet the process writes. An identifier does not
// have to be secret, only different enough that a receiver can match fragments;
// fragments are not produced here, so a counter is enough.
var ipID atomic.Uint32

// appendIPv4Packet appends a complete IPv4 packet to buf. The transport payload
// must already carry its own checksum; the IP header checksum is computed here.
func appendIPv4Packet(buf []byte, src, dst ip4, protocol uint8, payload []byte) []byte {
	start := len(buf)
	total := ipv4MinHeader + len(payload)
	buf = append(buf, make([]byte, total)...)
	h := buf[start:]
	h[0] = 0x45 // version 4, no IP options
	binary.BigEndian.PutUint16(h[2:4], uint16(total))
	binary.BigEndian.PutUint16(h[4:6], uint16(ipID.Add(1)))
	binary.BigEndian.PutUint16(h[6:8], 0x4000) // do not fragment
	h[8] = 64                                  // a normal host TTL
	h[9] = protocol
	copy(h[12:16], src[:])
	copy(h[16:20], dst[:])
	binary.BigEndian.PutUint16(h[10:12], checksum(h[:ipv4MinHeader], 0))
	copy(h[ipv4MinHeader:], payload)
	return buf
}

// appendTCPPacket appends one TCP segment inside an IPv4 packet. A non-zero mss
// adds the MSS option and is only used on the SYN-ACK, which is where a receiver
// learns how large our segments may be.
func appendTCPPacket(buf []byte, src, dst ip4, srcPort, dstPort uint16, seq, ack uint32, flags uint8, mss uint16, payload []byte) []byte {
	headerLen := tcpMinHeader
	if mss > 0 {
		headerLen += 4
	}
	seg := make([]byte, headerLen+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], ack)
	seg[12] = byte(headerLen/4) << 4
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535) // a fixed receive window
	if mss > 0 {
		seg[20] = 2 // MSS kind
		seg[21] = 4 // MSS length
		binary.BigEndian.PutUint16(seg[22:24], mss)
	}
	copy(seg[headerLen:], payload)
	binary.BigEndian.PutUint16(seg[16:18], transportChecksum(src, dst, protoTCP, seg))
	return appendIPv4Packet(buf, src, dst, protoTCP, seg)
}

// appendUDPPacket appends one UDP datagram inside an IPv4 packet.
func appendUDPPacket(buf []byte, src, dst ip4, srcPort, dstPort uint16, payload []byte) []byte {
	seg := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))
	copy(seg[udpHeaderLen:], payload)
	csum := transportChecksum(src, dst, protoUDP, seg)
	if csum == 0 {
		csum = 0xffff // zero means "no checksum" on the wire
	}
	binary.BigEndian.PutUint16(seg[6:8], csum)
	return appendIPv4Packet(buf, src, dst, protoUDP, seg)
}

// appendICMPEchoReply turns an echo request into an echo reply. TUN devices are
// point-to-point, so answering ping is both cheap and the quickest way for an
// operator to see that the device is alive.
func appendICMPEchoReply(buf []byte, src, dst ip4, request []byte) ([]byte, error) {
	if len(request) < udpHeaderLen {
		return nil, errShortICMP
	}
	if request[0] != 8 { // only echo requests are answered
		return nil, fmt.Errorf("inbound: ICMP type %d is not an echo request", request[0])
	}
	reply := append([]byte(nil), request...)
	reply[0] = 0
	// Zero the copied checksum before recomputing it, or the old one is added
	// twice and the kernel drops the reply.
	binary.BigEndian.PutUint16(reply[2:4], 0)
	binary.BigEndian.PutUint16(reply[2:4], checksum(reply, 0))
	return appendIPv4Packet(buf, src, dst, protoICMP, reply), nil
}

// transportChecksum computes a TCP or UDP checksum over the pseudo header and
// the segment. The checksum field of the segment is zero when this is called.
func transportChecksum(src, dst ip4, protocol uint8, segment []byte) uint16 {
	sum := sumBytes(src[:], 0)
	sum = sumBytes(dst[:], sum)
	// The pseudo header's zero/protocol byte pair is one big-endian word whose
	// value is the protocol number itself, not the protocol shifted into the
	// high byte. Getting this wrong produces a checksum a real kernel rejects.
	sum += uint32(protocol)
	sum += uint32(len(segment))
	sum = sumBytes(segment, sum)
	return foldSum(sum)
}

// checksum computes the internet checksum of a header (used for IPv4 and ICMP).
func checksum(b []byte, initial uint32) uint16 { return foldSum(sumBytes(b, initial)) }

// sumBytes adds 16-bit big endian words to a one's complement sum, treating an
// odd trailing byte as the high half of a word.
func sumBytes(b []byte, sum uint32) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func foldSum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// seqAfter reports whether a is strictly after b in TCP's wrapping sequence
// space. It is used instead of a plain comparison so a window that wraps past
// 2^32 still behaves.
func seqAfter(a, b uint32) bool { return int32(a-b) > 0 }

func seqAtLeast(a, b uint32) bool { return a == b || seqAfter(a, b) }
