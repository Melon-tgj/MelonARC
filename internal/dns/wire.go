package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// The DNS wire constants this client needs. A stub resolver only asks two
// question types and only reads addresses, the authority section's SOA (for the
// lifetime of a negative answer) and the truncation bit, so the table is short
// on purpose: everything else is skipped by its record length.
const (
	typeA     uint16 = 1
	typeCNAME uint16 = 5
	typeSOA   uint16 = 6
	typeAAAA  uint16 = 28

	classINET uint16 = 1

	// rcodes the client reports. The rest are folded into "the server answered
	// with rcode N", because a stub resolver cannot do anything about them.
	rcodeNoError  = 0
	rcodeNXDomain = 3

	headerLen = 12
	// flagRecursionDesired asks the server to resolve the name for us; without
	// it a caching resolver would answer from its own data only.
	flagRecursionDesired = 0x0100
	// flagTruncated marks an answer the server cut short because it did not fit
	// the transport. The client retries such a question over TCP.
	flagTruncated = 0x0200

	// maxUDPMessage is the largest reply the client accepts over UDP. Without
	// EDNS0 a server may only send 512 bytes, but reading a larger buffer costs
	// nothing and survives servers that ignore the limit.
	maxUDPMessage = 4096
	// maxWireNameLen is the longest name a message can carry.
	maxWireNameLen = 255
	// maxLabelLen is the longest single label.
	maxLabelLen = 63
	// maxCompressionJumps bounds how many pointers a name may follow, so a
	// malicious message cannot send the parser in circles.
	maxCompressionJumps = 32
)

// Errors a malformed message produces.
var (
	errMalformedMessage = errors.New("dns: malformed message")
	errNameLoop         = errors.New("dns: compression pointer loop")
)

// answerRecord is one address record with the lifetime the server gave it.
type answerRecord struct {
	ip  net.IP
	ttl uint32
}

// response is the part of a message this client understands.
type response struct {
	id        uint16
	truncated bool
	rcode     int
	// records are the address records of the answer section, in the order the
	// server listed them. A CNAME chain is followed implicitly: every address
	// in the answer belongs to the name that was asked for.
	records []answerRecord
	// soaTTL is the lifetime a negative answer asked for, from the authority
	// section's SOA record. hasSOA says whether one was present.
	soaTTL uint32
	hasSOA bool
}

// buildQuery encodes one question. The identifier is chosen by the caller, which
// keeps this function pure and testable.
func buildQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	msg := make([]byte, headerLen, headerLen+len(name)+6)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], flagRecursionDesired)
	binary.BigEndian.PutUint16(msg[4:6], 1) // QDCOUNT
	msg, err := appendName(msg, name)
	if err != nil {
		return nil, err
	}
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, classINET)
	return msg, nil
}

// appendName writes a name as length-prefixed labels followed by a root label.
func appendName(buf []byte, name string) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: empty name", ErrInvalidName)
	}
	start := len(buf)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return nil, fmt.Errorf("%w: %q has an empty label", ErrInvalidName, name)
		}
		if len(label) > maxLabelLen {
			return nil, fmt.Errorf("%w: %q has a label longer than %d bytes", ErrInvalidName, name, maxLabelLen)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	if len(buf)-start > maxWireNameLen {
		return nil, fmt.Errorf("%w: %q is longer than %d bytes on the wire", ErrInvalidName, name, maxWireNameLen)
	}
	return buf, nil
}

// parseResponse decodes a message. Every offset is checked against the buffer,
// so a truncated or hostile answer becomes an error rather than a panic.
func parseResponse(msg []byte) (*response, error) {
	if len(msg) < headerLen {
		return nil, fmt.Errorf("%w: %d bytes is shorter than a header", errMalformedMessage, len(msg))
	}
	r := &response{
		id:        binary.BigEndian.Uint16(msg[0:2]),
		truncated: binary.BigEndian.Uint16(msg[2:4])&flagTruncated != 0,
		rcode:     int(msg[3] & 0x0f),
	}
	questions := int(binary.BigEndian.Uint16(msg[4:6]))
	answers := int(binary.BigEndian.Uint16(msg[6:8]))
	authority := int(binary.BigEndian.Uint16(msg[8:10]))

	off := headerLen
	var err error
	for i := 0; i < questions; i++ {
		// The question is echoed back; only its length matters here.
		if _, off, err = readName(msg, off); err != nil {
			return nil, err
		}
		if off+4 > len(msg) {
			return nil, fmt.Errorf("%w: the question runs past the message", errMalformedMessage)
		}
		off += 4
	}
	for i := 0; i < answers; i++ {
		if off, err = r.readRecord(msg, off, false); err != nil {
			return nil, err
		}
	}
	for i := 0; i < authority; i++ {
		if off, err = r.readRecord(msg, off, true); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// readRecord consumes one resource record and returns the offset of the next
// one. Records other than addresses and the SOA are skipped by their declared
// length.
func (r *response) readRecord(msg []byte, off int, authority bool) (int, error) {
	var err error
	if _, off, err = readName(msg, off); err != nil {
		return 0, err
	}
	if off+10 > len(msg) {
		return 0, fmt.Errorf("%w: a record header runs past the message", errMalformedMessage)
	}
	typ := binary.BigEndian.Uint16(msg[off : off+2])
	class := binary.BigEndian.Uint16(msg[off+2 : off+4])
	ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
	rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
	rdata := off + 10
	next := rdata + rdlen
	if next > len(msg) {
		return 0, fmt.Errorf("%w: a record runs past the message", errMalformedMessage)
	}
	if class != classINET {
		return next, nil
	}
	switch typ {
	case typeA:
		if rdlen == net.IPv4len {
			r.records = append(r.records, answerRecord{ip: net.IP(append([]byte(nil), msg[rdata:next]...)), ttl: ttl})
		}
	case typeAAAA:
		if rdlen == net.IPv6len {
			r.records = append(r.records, answerRecord{ip: net.IP(append([]byte(nil), msg[rdata:next]...)), ttl: ttl})
		}
	case typeSOA:
		// RFC 2308: a negative answer is cached for the smaller of the SOA
		// record's own TTL and its MINIMUM field. Only the first SOA is used;
		// a message with several is already unusual.
		if authority && !r.hasSOA {
			minimum, err := soaMinimum(msg, rdata, rdlen)
			if err != nil {
				return 0, err
			}
			r.soaTTL, r.hasSOA = ttl, true
			if minimum < ttl {
				r.soaTTL = minimum
			}
		}
	}
	return next, nil
}

// soaMinimum reads the MINIMUM field of an SOA record: two names, then five
// 32-bit numbers, the last of which is the negative caching lifetime.
func soaMinimum(msg []byte, off, rdlen int) (uint32, error) {
	end := off + rdlen
	var err error
	if _, off, err = readName(msg, off); err != nil {
		return 0, err
	}
	if _, off, err = readName(msg, off); err != nil {
		return 0, err
	}
	if off+20 > end {
		return 0, fmt.Errorf("%w: the SOA record is too short", errMalformedMessage)
	}
	return binary.BigEndian.Uint32(msg[off+16 : off+20]), nil
}

// readName reads a possibly compressed name and returns the offset just past it
// in the original message, which is what the caller needs to keep walking.
//
// Compression pointers must point backwards; accepting a forward pointer would
// let a message describe a loop that the jump counter alone cannot stop in
// bounded time on a hostile input.
func readName(msg []byte, off int) (string, int, error) {
	var (
		name     strings.Builder
		next     = -1
		jumps    int
		nameLen  int
		firstOff = off
	)
	for {
		if off < 0 || off >= len(msg) {
			return "", 0, fmt.Errorf("%w: a name runs past the message", errMalformedMessage)
		}
		length := int(msg[off])
		switch {
		case length == 0:
			off++
			if next < 0 {
				next = off
			}
			return name.String(), next, nil
		case length&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return "", 0, fmt.Errorf("%w: a compression pointer is cut short", errMalformedMessage)
			}
			pointer := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			if next < 0 {
				next = off + 2
			}
			// Every jump must move backwards, which is what makes a loop
			// impossible: the offsets strictly decrease.
			if pointer >= off {
				return "", 0, fmt.Errorf("%w at offset %d", errNameLoop, off)
			}
			jumps++
			if jumps > maxCompressionJumps {
				return "", 0, fmt.Errorf("%w at offset %d", errNameLoop, firstOff)
			}
			off = pointer
		case length&0xc0 != 0:
			return "", 0, fmt.Errorf("%w: label type 0x%02x is reserved", errMalformedMessage, length&0xc0)
		default:
			if off+1+length > len(msg) {
				return "", 0, fmt.Errorf("%w: a label runs past the message", errMalformedMessage)
			}
			if name.Len() > 0 {
				name.WriteByte('.')
			}
			name.Write(msg[off+1 : off+1+length])
			nameLen += length + 1
			if nameLen > maxWireNameLen {
				return "", 0, fmt.Errorf("%w: a name is longer than %d bytes", errMalformedMessage, maxWireNameLen)
			}
			off += 1 + length
		}
	}
}
