package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Response codes a local DNS responder can give. They are the only three the
// TUN path needs: an answer, a name that does not exist and a lookup that could
// not be completed.
const (
	RcodeOK       = 0
	RcodeServFail = 2
	RcodeNXDomain = 3
)

// Question is one question taken from a standard DNS query. Raw is the exact
// wire bytes of the question, which an answer echoes back unchanged.
type Question struct {
	ID    uint16
	Name  string
	Type  uint16
	Class uint16
	Raw   []byte
}

// QueryTypeA is the A record type, exported so a responder can tell an address
// question from one it should answer with no records.
const QueryTypeA = typeA

var errNotAQuery = errors.New("dns: message is not a single-question query")

// ParseQuestion reads the one question of a standard query. It is the mirror of
// parseResponse: this package owns the wire format, so a second parser must not
// grow inside another package. Compression pointers are handled by readName,
// which rejects loops and forward jumps.
func ParseQuestion(msg []byte) (Question, error) {
	if len(msg) < headerLen {
		return Question{}, fmt.Errorf("%w: %d bytes is shorter than a header", errMalformedMessage, len(msg))
	}
	if msg[2]&0x80 != 0 {
		return Question{}, fmt.Errorf("%w: the QR bit is set", errNotAQuery)
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return Question{}, fmt.Errorf("%w: QDCOUNT is not one", errNotAQuery)
	}
	name, off, err := readName(msg, headerLen)
	if err != nil {
		return Question{}, err
	}
	if off+4 > len(msg) {
		return Question{}, fmt.Errorf("%w: the question runs past the message", errMalformedMessage)
	}
	q := Question{
		ID:    binary.BigEndian.Uint16(msg[0:2]),
		Name:  name,
		Type:  binary.BigEndian.Uint16(msg[off : off+2]),
		Class: binary.BigEndian.Uint16(msg[off+2 : off+4]),
		Raw:   append([]byte(nil), msg[headerLen:off+4]...),
	}
	if q.Class != classINET {
		return Question{}, fmt.Errorf("%w: question class %d is not IN", errNotAQuery, q.Class)
	}
	// The name has to be one this resolver could have asked for: labels are
	// length-prefixed on the wire and cannot be empty in the middle.
	if _, err := appendName(nil, q.Name); err != nil {
		return Question{}, err
	}
	return q, nil
}

// AnswerQuestion builds a response to q. An A question receives one A record per
// IPv4 address in ips; any other question type receives no answer section, which
// is a normal negative answer for a type the responder does not carry. rcode is
// one of RcodeOK, RcodeNXDomain or RcodeServFail.
func AnswerQuestion(q Question, rcode int, ttl uint32, ips []net.IP) []byte {
	var records []net.IP
	if q.Type == typeA && rcode == RcodeOK {
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				records = append(records, v4)
			}
		}
	}
	msg := make([]byte, headerLen, headerLen+len(q.Raw)+len(records)*16)
	binary.BigEndian.PutUint16(msg[0:2], q.ID)
	// QR | RD | RA, with the response code in the low nibble.
	binary.BigEndian.PutUint16(msg[2:4], uint16(0x8180|rcode&0x0f))
	binary.BigEndian.PutUint16(msg[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(records)))
	msg = append(msg, q.Raw...)
	for _, ip := range records {
		msg = append(msg, 0xc0, 0x0c) // a pointer to the question's name
		msg = binary.BigEndian.AppendUint16(msg, typeA)
		msg = binary.BigEndian.AppendUint16(msg, classINET)
		msg = binary.BigEndian.AppendUint32(msg, ttl)
		msg = binary.BigEndian.AppendUint16(msg, net.IPv4len)
		msg = append(msg, ip...)
	}
	return msg
}
