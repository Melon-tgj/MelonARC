package outbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/http2/hpack"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

// A minimal HTTP/3 client, enough for one request: a request stream carrying a
// HEADERS frame, and the status code of the reply.
//
// The auth handshake of the QUIC protocols is an HTTP/3 request so that a
// server without credentials looks like a web server. Only the pieces that
// requires are here: one stream, a static-table QPACK encoder (no dynamic
// table, so no encoder/decoder streams), and a decoder that reads a header
// block down to its field lines. SETTINGS is sent with no settings at all,
// which is a valid HTTP/3 client that supports neither pushes nor the dynamic
// table.
//
// Every header block, on either side, starts with the encoded field section
// prefix of RFC 9204, Section 4.5.1. Leaving it out makes a conforming peer
// read the first field line as the Required Insert Count and fail the whole
// section with QPACK_DECOMPRESSION_FAILED.
const (
	h3FrameData     = 0x00
	h3FrameHeaders  = 0x01
	h3FrameSettings = 0x04

	h3StreamControl  = 0x00
	h3StreamPush     = 0x01
	h3StreamQpackEnc = 0x02
	h3StreamQpackDec = 0x03
)

// h3StaticEntry is one row of the QPACK static table of RFC 9204, Appendix A.
// All 99 rows are present: a peer may reference any of them, and a decoder
// that keeps only the rows it expects would silently drop field lines.
type h3StaticEntry struct{ name, value string }

var h3StaticTable = [...]h3StaticEntry{
	{":authority", ""},                       // 0
	{":path", "/"},                           // 1
	{"age", "0"},                             // 2
	{"content-disposition", ""},              // 3
	{"content-length", "0"},                  // 4
	{"cookie", ""},                           // 5
	{"date", ""},                             // 6
	{"etag", ""},                             // 7
	{"if-modified-since", ""},                // 8
	{"if-none-match", ""},                    // 9
	{"last-modified", ""},                    // 10
	{"link", ""},                             // 11
	{"location", ""},                         // 12
	{"referer", ""},                          // 13
	{"set-cookie", ""},                       // 14
	{":method", "CONNECT"},                   // 15
	{":method", "DELETE"},                    // 16
	{":method", "GET"},                       // 17
	{":method", "HEAD"},                      // 18
	{":method", "OPTIONS"},                   // 19
	{":method", "POST"},                      // 20
	{":method", "PUT"},                       // 21
	{":scheme", "http"},                      // 22
	{":scheme", "https"},                     // 23
	{":status", "103"},                       // 24
	{":status", "200"},                       // 25
	{":status", "304"},                       // 26
	{":status", "404"},                       // 27
	{":status", "503"},                       // 28
	{"accept", "*/*"},                        // 29
	{"accept", "application/dns-message"},    // 30
	{"accept-encoding", "gzip, deflate, br"}, // 31
	{"accept-ranges", "bytes"},               // 32
	{"access-control-allow-headers", "cache-control"},                             // 33
	{"access-control-allow-headers", "content-type"},                              // 34
	{"access-control-allow-origin", "*"},                                          // 35
	{"cache-control", "max-age=0"},                                                // 36
	{"cache-control", "max-age=2592000"},                                          // 37
	{"cache-control", "max-age=604800"},                                           // 38
	{"cache-control", "no-cache"},                                                 // 39
	{"cache-control", "no-store"},                                                 // 40
	{"cache-control", "public, max-age=31536000"},                                 // 41
	{"content-encoding", "br"},                                                    // 42
	{"content-encoding", "gzip"},                                                  // 43
	{"content-type", "application/dns-message"},                                   // 44
	{"content-type", "application/javascript"},                                    // 45
	{"content-type", "application/json"},                                          // 46
	{"content-type", "application/x-www-form-urlencoded"},                         // 47
	{"content-type", "image/gif"},                                                 // 48
	{"content-type", "image/jpeg"},                                                // 49
	{"content-type", "image/png"},                                                 // 50
	{"content-type", "text/css"},                                                  // 51
	{"content-type", "text/html; charset=utf-8"},                                  // 52
	{"content-type", "text/plain"},                                                // 53
	{"content-type", "text/plain;charset=utf-8"},                                  // 54
	{"range", "bytes=0-"},                                                         // 55
	{"strict-transport-security", "max-age=31536000"},                             // 56
	{"strict-transport-security", "max-age=31536000; includesubdomains"},          // 57
	{"strict-transport-security", "max-age=31536000; includesubdomains; preload"}, // 58
	{"vary", "accept-encoding"},                                                   // 59
	{"vary", "origin"},                                                            // 60
	{"x-content-type-options", "nosniff"},                                         // 61
	{"x-xss-protection", "1; mode=block"},                                         // 62
	{":status", "100"},                                                            // 63
	{":status", "204"},                                                            // 64
	{":status", "206"},                                                            // 65
	{":status", "302"},                                                            // 66
	{":status", "400"},                                                            // 67
	{":status", "403"},                                                            // 68
	{":status", "421"},                                                            // 69
	{":status", "425"},                                                            // 70
	{":status", "500"},                                                            // 71
	{"accept-language", ""},                                                       // 72
	{"access-control-allow-credentials", "FALSE"},                                 // 73
	{"access-control-allow-credentials", "TRUE"},                                  // 74
	{"access-control-allow-headers", "*"},                                         // 75
	{"access-control-allow-methods", "get"},                                       // 76
	{"access-control-allow-methods", "get, post, options"},                        // 77
	{"access-control-allow-methods", "options"},                                   // 78
	{"access-control-expose-headers", "content-length"},                           // 79
	{"access-control-request-headers", "content-type"},                            // 80
	{"access-control-request-method", "get"},                                      // 81
	{"access-control-request-method", "post"},                                     // 82
	{"alt-svc", "clear"},                                                          // 83
	{"authorization", ""},                                                         // 84
	{"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"}, // 85
	{"early-data", "1"},                // 86
	{"expect-ct", ""},                  // 87
	{"forwarded", ""},                  // 88
	{"if-range", ""},                   // 89
	{"origin", ""},                     // 90
	{"purpose", "prefetch"},            // 91
	{"server", ""},                     // 92
	{"timing-allow-origin", "*"},       // 93
	{"upgrade-insecure-requests", "1"}, // 94
	{"user-agent", ""},                 // 95
	{"x-forwarded-for", ""},            // 96
	{"x-frame-options", "deny"},        // 97
	{"x-frame-options", "sameorigin"},  // 98
}

// h3Client sends requests on one QUIC connection.
type h3Client struct {
	conn *quic.Conn
}

// newH3Client sends the settings frame that opens the control stream.
func newH3Client(ctx context.Context, conn *quic.Conn) (*h3Client, error) {
	control, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("http3: open the control stream: %w", err)
	}
	frame := quicvarint.Append(nil, h3StreamControl)
	frame = appendH3Frame(frame, h3FrameSettings, nil)
	if _, err := control.Write(frame); err != nil {
		return nil, fmt.Errorf("http3: write settings: %w", err)
	}
	return &h3Client{conn: conn}, nil
}

// do sends one request and returns the status code. The request has no body, so
// the send side is closed right after the headers.
func (c *h3Client) do(ctx context.Context, authority, path string, headers [][2]string) (int, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, fmt.Errorf("http3: open a request stream: %w", err)
	}
	block := h3EncodeRequestHeaders(authority, path, headers)
	if _, err := stream.Write(appendH3Frame(nil, h3FrameHeaders, block)); err != nil {
		_ = stream.Close()
		return 0, fmt.Errorf("http3: write request headers: %w", err)
	}
	// A request without a body ends with the headers.
	if err := stream.Close(); err != nil {
		return 0, fmt.Errorf("http3: finish the request: %w", err)
	}
	status, err := h3ReadStatus(stream)
	if err != nil {
		return 0, err
	}
	// Nothing else is read from this request, so the stream is abandoned
	// instead of drained.
	stream.CancelRead(0)
	return status, nil
}

// h3ReadStatus reads frames until the response headers arrive.
func h3ReadStatus(r io.Reader) (int, error) {
	reader := bufio.NewReader(r)
	for {
		typ, payload, err := readH3Frame(reader)
		if err != nil {
			return 0, err
		}
		switch typ {
		case h3FrameHeaders:
			fields, err := h3DecodeHeaderBlock(payload)
			if err != nil {
				return 0, err
			}
			for _, field := range fields {
				if field[0] != ":status" {
					continue
				}
				status, err := parseHTTPStatus(field[1])
				if err != nil {
					return 0, err
				}
				return status, nil
			}
			return 0, errors.New("http3: the response has no status")
		case h3FrameData:
			continue
		default:
			return 0, fmt.Errorf("http3: unexpected frame type %#x in a response", typ)
		}
	}
}

func parseHTTPStatus(value string) (int, error) {
	if len(value) != 3 {
		return 0, fmt.Errorf("http3: status %q is not three digits", value)
	}
	status := 0
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, fmt.Errorf("http3: status %q is not a number", value)
		}
		status = status*10 + int(value[i]-'0')
	}
	return status, nil
}

// appendH3Frame writes a frame type, its length and its payload.
func appendH3Frame(dst []byte, typ uint64, payload []byte) []byte {
	dst = quicvarint.Append(dst, typ)
	dst = quicvarint.Append(dst, uint64(len(payload)))
	return append(dst, payload...)
}

// readH3Frame reads one frame.
func readH3Frame(r *bufio.Reader) (uint64, []byte, error) {
	typ, err := quicvarint.Read(r)
	if err != nil {
		return 0, nil, fmt.Errorf("http3: read frame type: %w", err)
	}
	length, err := quicvarint.Read(r)
	if err != nil {
		return 0, nil, fmt.Errorf("http3: read frame length: %w", err)
	}
	if length > 1<<20 {
		return 0, nil, fmt.Errorf("http3: frame of %d bytes is too large", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("http3: read frame payload: %w", err)
	}
	return typ, payload, nil
}

// h3AppendFieldSectionPrefix writes the prefix of RFC 9204, Section 4.5.1:
// a Required Insert Count of zero (8-bit prefix) and a Base of zero (Sign bit
// clear, Delta Base zero with a 7-bit prefix). This client advertises no
// dynamic table, so no other value is possible.
func h3AppendFieldSectionPrefix(dst []byte) []byte {
	return append(dst, 0x00, 0x00)
}

// h3ReadFieldSectionPrefix consumes the prefix and returns the encoded field
// lines. A nonzero Required Insert Count would need dynamic table inserts this
// client never receives; a Sign bit with a zero Required Insert Count would
// make the Base negative, which Section 4.5.1.2 forbids. Both are refused
// explicitly so a peer's dynamic-table section cannot be misread.
func h3ReadFieldSectionPrefix(block []byte) ([]byte, error) {
	if len(block) < 2 {
		return nil, errors.New("http3: truncated encoded field section prefix")
	}
	encInsertCount, rest, err := h3ReadPrefixedInt(block, 8)
	if err != nil {
		return nil, fmt.Errorf("http3: read the required insert count: %w", err)
	}
	if encInsertCount != 0 {
		return nil, fmt.Errorf("http3: the field section needs %d dynamic table inserts, but this client has none", encInsertCount)
	}
	if len(rest) == 0 {
		return nil, errors.New("http3: truncated encoded field section prefix")
	}
	sign := rest[0]&0x80 != 0
	_, rest, err = h3ReadPrefixedInt(rest, 7)
	if err != nil {
		return nil, fmt.Errorf("http3: read the delta base: %w", err)
	}
	if sign {
		return nil, errors.New("http3: a zero required insert count cannot have a negative base")
	}
	return rest, nil
}

// h3EncodeRequestHeaders writes the request header block, prefix included.
// Every field is a literal with a literal name: the encoder is then
// independent of the static table's numbering, and a field the table happens
// to contain costs a few bytes more rather than being wrong.
func h3EncodeRequestHeaders(authority, path string, headers [][2]string) []byte {
	block := h3AppendFieldSectionPrefix(nil)
	block = h3AppendField(block, ":method", "POST")
	block = h3AppendField(block, ":scheme", "https")
	block = h3AppendField(block, ":authority", authority)
	block = h3AppendField(block, ":path", path)
	for _, header := range headers {
		block = h3AppendField(block, strings.ToLower(header[0]), header[1])
	}
	return block
}

// h3AppendField writes one literal field line with a literal name: the pattern
// 001, the never-indexed bit clear, the huffman bit clear, a three-bit name
// length, the name bytes and then the value.
func h3AppendField(dst []byte, name, value string) []byte {
	dst = h3AppendPrefixedInt(dst, uint64(len(name)), 3, 0x20)
	dst = append(dst, name...)
	dst = h3AppendPrefixedInt(dst, uint64(len(value)), 7, 0x00)
	return append(dst, value...)
}

// h3AppendPrefixedInt writes an integer with a prefix of the given width.
func h3AppendPrefixedInt(dst []byte, value uint64, prefix uint, first byte) []byte {
	max := uint64(1)<<prefix - 1
	if value < max {
		return append(dst, first|byte(value))
	}
	dst = append(dst, first|byte(max))
	value -= max
	for value >= 128 {
		dst = append(dst, byte(value&0x7f)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}

// h3ReadPrefixedInt reads an integer with a prefix of the given width.
func h3ReadPrefixedInt(b []byte, prefix uint) (value uint64, rest []byte, err error) {
	if len(b) == 0 {
		return 0, nil, errors.New("http3: truncated integer")
	}
	max := uint64(1)<<prefix - 1
	value = uint64(b[0]) & max
	b = b[1:]
	if value < max {
		return value, b, nil
	}
	shift := uint(0)
	for {
		if len(b) == 0 {
			return 0, nil, errors.New("http3: truncated integer")
		}
		next := b[0]
		b = b[1:]
		value += uint64(next&0x7f) << shift
		if next&0x80 == 0 {
			return value, b, nil
		}
		shift += 7
		if shift > 28 {
			return 0, nil, errors.New("http3: integer is too long")
		}
	}
}

// h3DecodeHeaderBlock returns the field lines of a header block, in order.
// Field names that refer to a static table row are resolved from it; a
// reference to the dynamic table is an error, because this client advertises no
// capacity for one and a peer that uses it anyway cannot be answered.
func h3DecodeHeaderBlock(block []byte) ([][2]string, error) {
	block, err := h3ReadFieldSectionPrefix(block)
	if err != nil {
		return nil, err
	}
	var fields [][2]string
	for len(block) > 0 {
		first := block[0]
		switch {
		case first&0x80 != 0: // indexed field line
			index, rest, err := h3ReadPrefixedInt(block, 6)
			if err != nil {
				return nil, err
			}
			block = rest
			if first&0x40 == 0 {
				return nil, errors.New("http3: a response referred to the dynamic table")
			}
			if index >= uint64(len(h3StaticTable)) {
				return nil, fmt.Errorf("http3: static table index %d is out of range", index)
			}
			fields = append(fields, [2]string{h3StaticTable[index].name, h3StaticTable[index].value})
		case first&0xc0 == 0x40: // literal with a name reference
			// 01NTxxxx: the index has four bits, not the six an indexed
			// field line uses; the N and T bits sit above it.
			index, rest, err := h3ReadPrefixedInt(block, 4)
			if err != nil {
				return nil, err
			}
			name := ""
			if first&0x10 != 0 {
				if index >= uint64(len(h3StaticTable)) {
					return nil, fmt.Errorf("http3: static table index %d is not known", index)
				}
				name = h3StaticTable[index].name
			} else {
				return nil, errors.New("http3: a response referred to the dynamic table")
			}
			value, rest, err := h3ReadString(rest, 7)
			if err != nil {
				return nil, err
			}
			block = rest
			fields = append(fields, [2]string{name, value})
		case first&0xe0 == 0x20: // literal with a literal name
			name, rest, err := h3ReadString(block, 3)
			if err != nil {
				return nil, err
			}
			value, rest, err := h3ReadString(rest, 7)
			if err != nil {
				return nil, err
			}
			block = rest
			fields = append(fields, [2]string{name, value})
		default:
			return nil, errors.New("http3: the response used a post-base table reference")
		}
	}
	return fields, nil
}

// h3ReadString reads a string whose length has the given prefix width, which is
// seven bits for a value and three for the name of a literal field line.
// Huffman-coded strings use the HPACK code table of RFC 7541, Appendix B,
// which QPACK inherits; an encoder is free to choose it for any string.
func h3ReadString(b []byte, prefix uint) (string, []byte, error) {
	if len(b) == 0 {
		return "", nil, errors.New("http3: truncated string")
	}
	huffman := b[0]&(1<<prefix) != 0
	length, rest, err := h3ReadPrefixedInt(b, prefix)
	if err != nil {
		return "", nil, err
	}
	if length > uint64(len(rest)) {
		return "", nil, errors.New("http3: truncated string")
	}
	value := rest[:length]
	remain := rest[length:]
	if huffman {
		decoded, err := hpack.HuffmanDecodeToString(value)
		if err != nil {
			return "", nil, fmt.Errorf("http3: decode a huffman-coded header string: %w", err)
		}
		return decoded, remain, nil
	}
	return string(value), remain, nil
}
