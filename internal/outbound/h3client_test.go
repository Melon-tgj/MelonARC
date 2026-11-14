package outbound

import (
	"strings"
	"testing"
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

// h3StatusLiteral writes a status field the way the peers under test do: a
// literal field line whose name is written out. It must survive the decoder.
func TestH3DecodeStatus(t *testing.T) {
	tests := []struct {
		block string
		want  int
	}{
		{block: "\x27\x00:status\x03233", want: 233},
		{block: "\x27\x00:status\x03404", want: 404},
		// A static indexed line: index 25 is ":status 200".
		{block: "\xd9", want: 200},
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
	for _, block := range [][]byte{{0xc0, 0x00}, {0x40, 0x00, 0x00}} {
		if _, err := h3DecodeHeaderBlock(block); err == nil {
			t.Fatalf("decode %x accepted a dynamic table reference", block)
		}
	}
	// Huffman strings are refused rather than guessed at.
	if _, err := h3DecodeHeaderBlock([]byte{0x2f, 0x00, 0x00}); err == nil {
		t.Fatal("decode accepted a huffman-coded name")
	}
}

func TestH3PrefixedInt(t *testing.T) {
	for _, value := range []uint64{0, 1, 6, 7, 8, 126, 127, 128, 1000, 1 << 20} {
		for _, prefix := range []uint{3, 6, 7} {
			encoded := h3AppendPrefixedInt(nil, value, prefix, 0)
			got, rest, err := h3ReadPrefixedInt(encoded, prefix)
			if err != nil || got != value || len(rest) != 0 {
				t.Fatalf("prefix %d value %d: got %d, rest %d, err %v", prefix, value, got, len(rest), err)
			}
		}
	}
}
