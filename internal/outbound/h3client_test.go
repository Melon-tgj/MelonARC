package outbound

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// The request encoder and the response decoder are two halves of the same
// format, so they are checked against each other: a block the encoder writes
// must decode back to the same field lines.
func TestH3HeaderBlockRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		author  string
		path    string
		headers [][2]string
	}{
		{name: "auth request", author: "hysteria", path: "/auth", headers: [][2]string{
			{"hysteria-auth", "correct horse battery staple"},
			{"hysteria-cc-rx", "0"},
		}},
		{name: "no extra headers", author: "example.test", path: "/"},
		{name: "long value", path: "/auth", headers: [][2]string{
			{"hysteria-padding", strings.Repeat("x", 200)},
		}},
		{name: "long name", path: "/auth", headers: [][2]string{
			{"x-a-header-name-that-does-not-fit-in-three-bits", "v"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block := h3EncodeRequestHeaders(test.author, test.path, test.headers)
			fields, err := h3DecodeHeaderBlock(block)
			if err != nil {
				t.Fatalf("decode: %v (block %x)", err, block)
			}
			want := [][2]string{
				{":method", "POST"},
				{":scheme", "https"},
				{":authority", test.author},
				{":path", test.path},
			}
			want = append(want, test.headers...)
			if len(fields) != len(want) {
				t.Fatalf("decoded %d fields, want %d: %v", len(fields), len(want), fields)
			}
			for i := range want {
				if fields[i] != want[i] {
					t.Fatalf("field %d = %v, want %v", i, fields[i], want[i])
				}
			}
		})
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex %q: %v", value, err)
	}
	return decoded
}

// TestH3EncodeRequestHeadersKnownAnswer pins the request block to the byte
// sequence RFC 9204 prescribes: the encoded field section prefix of 4.5.1
// (Required Insert Count 0, Sign 0 / Delta Base 0), then one Literal Field
// Line With Literal Name (4.5.6) per field. Name lengths use a 3-bit prefix
// and values a 7-bit prefix, so a 7-byte name is 0x27 0x00 and a 10-byte name
// is 0x27 0x03. This is the block a peer's QPACK decoder reads first.
func TestH3EncodeRequestHeadersKnownAnswer(t *testing.T) {
	got := h3EncodeRequestHeaders("example.test", "/", nil)
	want := []byte{
		0x00, 0x00, // encoded field section prefix
		0x27, 0x00, ':', 'm', 'e', 't', 'h', 'o', 'd', 0x04, 'P', 'O', 'S', 'T',
		0x27, 0x00, ':', 's', 'c', 'h', 'e', 'm', 'e', 0x05, 'h', 't', 't', 'p', 's',
		0x27, 0x03, ':', 'a', 'u', 't', 'h', 'o', 'r', 'i', 't', 'y',
		0x0c, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 't', 'e', 's', 't',
		0x25, ':', 'p', 'a', 't', 'h', 0x01, '/',
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("request block = %x, want the RFC 9204 sequence %x", got, want)
	}
	// The prefix is exactly two bytes: without it a peer reads 0x27 as the
	// Required Insert Count and fails the whole field section.
	if got[0] != 0x00 || got[1] != 0x00 {
		t.Fatalf("field section prefix = %x, want 0000", got[:2])
	}
}

// TestH3DecodeRFC9204Vectors feeds Appendix B field sections to the decoder.
// B.1 is a literal with a name reference and decodes to :path=/index.html;
// B.2 and B.4 require dynamic table inserts this client never receives and
// must be refused rather than misread.
func TestH3DecodeRFC9204Vectors(t *testing.T) {
	tests := []struct {
		name    string
		block   string
		want    [][2]string
		wantErr bool
	}{
		{
			name:  "B.1 literal with name reference",
			block: "0000510b2f696e6465782e68746d6c",
			want:  [][2]string{{":path", "/index.html"}},
		},
		{
			name:  "indexed static field line",
			block: "0000d9",
			want:  [][2]string{{":status", "200"}},
		},
		{
			// Static index 25 with a 4-bit name reference prefix: 0x5f 0x0a.
			name:  "literal name reference with prefix extension",
			block: "00005f0a03323333",
			want:  [][2]string{{":status", "233"}},
		},
		{
			name:  "literal with literal name",
			block: "000027003a73746174757303343034",
			want:  [][2]string{{":status", "404"}},
		},
		{
			name:    "B.2 required insert count 2",
			block:   "03811011",
			wantErr: true,
		},
		{
			name:    "B.4 required insert count 4",
			block:   "050080c181",
			wantErr: true,
		},
		{
			name:    "negative base with zero insert count",
			block:   "0080",
			wantErr: true,
		},
		{
			name:    "truncated field section prefix",
			block:   "00",
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields, err := h3DecodeHeaderBlock(mustHex(t, test.block))
			if test.wantErr {
				if err == nil {
					t.Fatalf("decode %s accepted a block it cannot process: %v", test.block, fields)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode %s: %v", test.block, err)
			}
			if len(fields) != len(test.want) {
				t.Fatalf("decode %s = %v, want %v", test.block, fields, test.want)
			}
			for i := range test.want {
				if fields[i] != test.want[i] {
					t.Fatalf("decode %s field %d = %v, want %v", test.block, i, fields[i], test.want[i])
				}
			}
		})
	}
}

// TestH3StaticTableIsComplete guards against the sparse table that used to
// make every index above 71 an empty field line.
func TestH3StaticTableIsComplete(t *testing.T) {
	if len(h3StaticTable) != 99 {
		t.Fatalf("static table has %d rows, want 99", len(h3StaticTable))
	}
	known := map[int][2]string{
		0:  {":authority", ""},
		25: {":status", "200"},
		52: {"content-type", "text/html; charset=utf-8"},
		71: {":status", "500"},
		85: {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
		98: {"x-frame-options", "sameorigin"},
	}
	for index, want := range known {
		got := [2]string{h3StaticTable[index].name, h3StaticTable[index].value}
		if got != want {
			t.Fatalf("static row %d = %v, want %v", index, got, want)
		}
	}
}

// h3StatusLiteral writes a status field the way the peers under test do: a
// literal field line whose name is written out. It must survive the decoder.
func TestH3DecodeStatus(t *testing.T) {
	tests := []struct {
		block string
		want  int
	}{
		{block: "\x00\x00\x27\x00:status\x03233", want: 233},
		{block: "\x00\x00\x27\x00:status\x03404", want: 404},
		// A static indexed line: index 25 is ":status 200".
		{block: "\x00\x00\xd9", want: 200},
		// Index 71 needs the 6-bit prefix extension: 0xff 0x08.
		{block: "\x00\x00\xff\x08", want: 500},
	}
	for _, test := range tests {
		fields, err := h3DecodeHeaderBlock([]byte(test.block))
		if err != nil {
			t.Fatalf("decode %x: %v", test.block, err)
		}
		if len(fields) != 1 {
			t.Fatalf("decode %x = %v, want one field", test.block, fields)
		}
		got, err := parseHTTPStatus(fields[0][1])
		if err != nil || got != test.want {
			t.Fatalf("status of %x = %d, %v, want %d", test.block, got, err, test.want)
		}
	}
}

func TestH3DecodeRejectsUnknownForms(t *testing.T) {
	// A dynamic table reference: an indexed field line with the static bit
	// clear, and a literal that refers to a dynamic name.
	for _, block := range [][]byte{
		{0x00, 0x00, 0xc0, 0x00},
		{0x00, 0x00, 0x40, 0x00, 0x00},
		{0x00, 0x00, 0xff, 0x40}, // static index 127 is out of range
		{0x00, 0x00, 0x10, 0x00}, // post-base index needs a dynamic table
		{0x00, 0x00, 0x27, 0x00, ':', 's', 't', 'a', 't', 'u', 's', 0x82, 0xff, 0xff}, // invalid huffman value
	} {
		if _, err := h3DecodeHeaderBlock(block); err == nil {
			t.Fatalf("decode %x accepted an invalid field section", block)
		}
	}
}

// TestH3DecodeHuffmanStrings checks the header decoder against a mature HPACK
// Huffman encoder: QPACK inherits the RFC 7541 code table, so a peer that
// chooses Huffman for a name or a value must still decode to the same field.
func TestH3DecodeHuffmanStrings(t *testing.T) {
	t.Run("value", func(t *testing.T) {
		encoded := hpack.AppendHuffmanString(nil, "200")
		if len(encoded) >= 127 {
			t.Fatal("the vector is too long for a one-byte length")
		}
		block := []byte{0x00, 0x00, 0x27, 0x00, ':', 's', 't', 'a', 't', 'u', 's'}
		block = append(block, 0x80|byte(len(encoded)))
		block = append(block, encoded...)
		fields, err := h3DecodeHeaderBlock(block)
		if err != nil {
			t.Fatalf("decode a huffman value: %v", err)
		}
		if len(fields) != 1 || fields[0] != [2]string{":status", "200"} {
			t.Fatalf("fields = %v, want :status 200", fields)
		}
	})
	t.Run("name", func(t *testing.T) {
		encoded := hpack.AppendHuffmanString(nil, ":status")
		block := h3AppendFieldSectionPrefix(nil)
		// 0x28 sets the Huffman bit of a literal-name field line.
		block = h3AppendPrefixedInt(block, uint64(len(encoded)), 3, 0x28)
		block = append(block, encoded...)
		block = h3AppendPrefixedInt(block, uint64(len("200")), 7, 0x00)
		block = append(block, "200"...)
		fields, err := h3DecodeHeaderBlock(block)
		if err != nil {
			t.Fatalf("decode a huffman name: %v", err)
		}
		if len(fields) != 1 || fields[0] != [2]string{":status", "200"} {
			t.Fatalf("fields = %v, want :status 200", fields)
		}
	})
}

func TestH3PrefixedInt(t *testing.T) {
	for _, value := range []uint64{0, 1, 6, 7, 8, 15, 16, 126, 127, 128, 254, 255, 256, 1000, 1 << 20} {
		for _, prefix := range []uint{3, 4, 6, 7, 8} {
			encoded := h3AppendPrefixedInt(nil, value, prefix, 0)
			got, rest, err := h3ReadPrefixedInt(encoded, prefix)
			if err != nil || got != value || len(rest) != 0 {
				t.Fatalf("prefix %d value %d: got %d, rest %d, err %v", prefix, value, got, len(rest), err)
			}
		}
	}
}
