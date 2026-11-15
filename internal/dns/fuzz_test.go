package dns

import (
	"encoding/binary"
	"testing"
)

// FuzzParseResponse feeds hostile DNS messages to the answer parser.
//
// parseResponse runs on bytes that arrived over the network, and it walks them by
// offsets the message itself supplies: a question count, an answer count, a
// length per record, and names made of labels or of pointers into the buffer.
// Every one of those is attacker-controlled. The parser documents that each
// offset is checked against the buffer and that a truncated or hostile answer
// becomes an error, so the invariant here is exactly that: an error or a
// response, never a panic.
//
// The seeds are the reply shapes the fake server in testserver_test.go writes,
// including the one that matters most for coverage — an answer whose name is a
// two-byte compression pointer back to the question, which is how every real
// resolver replies and the only thing that exercises the pointer path of
// readName. TestFuzzParseResponseSeedsReachTheParser checks that each seed still
// lands where it is meant to, so the corpus cannot quietly decay into a pile of
// early errors.
const (
	// A reply to "example.com" with one A record. The answer's name is the
	// pointer 0xc0 0x0c: compression, offset 12, the question's name.
	seedAnswerA = "\x00\x07\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + // header: id 7, response, 1 question, 1 answer
		"\x07example\x03com\x00\x00\x01\x00\x01" + // question: example.com A IN
		"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x78\x00\x04\xcb\x00\x71\x05" // answer: pointer, A, IN, ttl 120, 203.0.113.5

	// The same shape with an AAAA record, so the second address branch has a
	// seed of its own.
	seedAnswerAAAA = "\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" +
		"\x07example\x03com\x00\x00\x1c\x00\x01" +
		"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x01\x2c\x00\x10\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

	// A negative answer: NXDOMAIN with one SOA record in the authority section,
	// which is the path that decides how long a "no such host" is cached.
	seedNegative = "\xab\xcd\x81\x83\x00\x01\x00\x00\x00\x01\x00\x00" + // header: rcode 3, no answers, 1 authority
		"\x07example\x03com\x00\x00\x01\x00\x01" +
		"\xc0\x0c\x00\x06\x00\x01\x00\x00\x01\x2c\x00\x1e" + // SOA, IN, ttl 300, 30 bytes
		"\x02ns\x00" + "\x04host\x00" + // mname, rname
		"\x00\x00\x00\x01" + "\x00\x00\x0e\x10" + "\x00\x00\x02\x58" + "\x00\x01\x51\x80" + "\x00\x00\x00\x3c" // serial, refresh, retry, expire, minimum

	// A header with every count zero: the smallest message that parses.
	seedHeaderOnly = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

	// A question, not a reply, which is what a resolver sees if it parses its own
	// query by mistake.
	seedQuery = "\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
		"\x07example\x03com\x00\x00\x01\x00\x01"

	// A name that points at itself. The parser refuses forward and sideways
	// pointers, which is what makes a loop impossible.
	seedSelfPointer = "\x00\x02\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" +
		"\xc0\x0c\x00\x01\x00\x01"
)

// FuzzParseResponse is the target itself.
func FuzzParseResponse(f *testing.F) {
	for _, seed := range []string{
		seedAnswerA,
		seedAnswerAAAA,
		seedNegative,
		seedHeaderOnly,
		seedQuery,
		seedSelfPointer,
		// A reply cut in the middle of the question, and one cut inside the
		// answer's fixed fields.
		seedAnswerA[:20],
		seedAnswerA[:38],
		// A record that claims more data than the message holds.
		seedAnswerA[:len(seedAnswerA)-2],
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, msg []byte) {
		resp, err := parseResponse(msg)
		if err != nil {
			return
		}
		if resp == nil {
			t.Fatal("parseResponse returned no response and no error")
		}
		if got, want := resp.id, binary.BigEndian.Uint16(msg[0:2]); got != want {
			t.Fatalf("identifier = %#x, want the first two bytes %#x", got, want)
		}
		if resp.rcode < 0 || resp.rcode > 15 {
			t.Fatalf("rcode = %d, want a four bit value", resp.rcode)
		}
		for _, rec := range resp.records {
			switch len(rec.ip) {
			case 4, 16:
			default:
				t.Fatalf("a record carries %d address bytes, want 4 or 16", len(rec.ip))
			}
		}
	})
}

// TestFuzzParseResponseSeedsReachTheParser checks that every seed lands where the
// comment above it says, so a corpus that has drifted into failing on its first
// byte is caught here rather than by a silently lower coverage number.
func TestFuzzParseResponseSeedsReachTheParser(t *testing.T) {
	tests := []struct {
		name       string
		msg        string
		wantErr    bool
		wantRecord int
		wantSOA    bool
	}{
		{name: "a record", msg: seedAnswerA, wantRecord: 1},
		{name: "aaaa record", msg: seedAnswerAAAA, wantRecord: 1},
		{name: "negative answer", msg: seedNegative, wantSOA: true},
		{name: "header only", msg: seedHeaderOnly},
		{name: "a query", msg: seedQuery},
		{name: "a name that points at itself", msg: seedSelfPointer, wantErr: true},
		{name: "cut inside the question", msg: seedAnswerA[:20], wantErr: true},
		{name: "cut inside the answer header", msg: seedAnswerA[:38], wantErr: true},
		{name: "more rdata than the message holds", msg: seedAnswerA[:len(seedAnswerA)-2], wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := parseResponse([]byte(tc.msg))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseResponse accepted %q", tc.msg)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseResponse: %v", err)
			}
			if len(resp.records) != tc.wantRecord {
				t.Fatalf("records = %d, want %d", len(resp.records), tc.wantRecord)
			}
			if resp.hasSOA != tc.wantSOA {
				t.Fatalf("hasSOA = %v, want %v", resp.hasSOA, tc.wantSOA)
			}
		})
	}
}
