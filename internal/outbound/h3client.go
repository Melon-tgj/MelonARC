package outbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

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
const (
	h3FrameData     = 0x00
	h3FrameHeaders  = 0x01
	h3FrameSettings = 0x04

	h3StreamControl  = 0x00
	h3StreamPush     = 0x01
	h3StreamQpackEnc = 0x02
	h3StreamQpackDec = 0x03
)

// h3StaticEntry is one row of the QPACK static table. Only the rows this client
// can meet are listed: the request encoder writes literal names, so it needs no
// row at all, and the response decoder only has to recognise a status, whether
// it arrives as an indexed line or as a literal that refers to the table.
type h3StaticEntry struct{ name, value string }

var h3StaticTable = [...]h3StaticEntry{
	0:  {":authority", ""},
	1:  {":path", "/"},
	2:  {"age", "0"},
	3:  {"content-disposition", ""},
	4:  {"content-length", "0"},
	5:  {"cookie", ""},
	6:  {"date", ""},
	7:  {"etag", ""},
	8:  {"if-modified-since", ""},
	9:  {"if-none-match", ""},
	10: {"last-modified", ""},
	11: {"link", ""},
	12: {"location", ""},
	13: {"referer", ""},
	14: {"set-cookie", ""},
	15: {":method", "CONNECT"},
	16: {":method", "DELETE"},
	17: {":method", "GET"},
	18: {":method", "HEAD"},
	19: {":method", "OPTIONS"},
	20: {":method", "POST"},
	21: {":method", "PUT"},
	22: {":scheme", "http"},
	23: {":scheme", "https"},
	24: {":status", "103"},
	25: {":status", "200"},
	26: {":status", "304"},
	27: {":status", "404"},
	28: {":status", "503"},
	63: {":status", "100"},
	64: {":status", "204"},
	65: {":status", "206"},
	66: {":status", "302"},
	67: {":status", "400"},
	68: {":status", "403"},
	69: {":status", "421"},
	70: {":status", "425"},
	71: {":status", "500"},
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

// h3EncodeRequestHeaders writes the request header block. Every field is a
// literal with a literal name: the encoder is then independent of the static
// table's numbering, and a field the table happens to contain costs a few bytes
// more rather than being wrong.
func h3EncodeRequestHeaders(authority, path string, headers [][2]string) []byte {
	var block []byte
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
			if index < uint64(len(h3StaticTable)) {
				fields = append(fields, [2]string{h3StaticTable[index].name, h3StaticTable[index].value})
			}
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
// Huffman coding is not implemented: nothing in these exchanges is short enough
// for an encoder to choose it, and decoding it wrong is worse than refusing.
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
	if huffman {
		return "", nil, errors.New("http3: huffman-coded header strings are not supported")
	}
	return string(rest[:length]), rest[length:], nil
}
