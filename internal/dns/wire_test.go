package dns

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

// TestBuildQueryEncodesTheQuestion checks the bytes a query puts on the wire.
func TestBuildQueryEncodesTheQuestion(t *testing.T) {
	msg, err := buildQuery(0xbeef, "example.com", typeA)
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	if got := binary.BigEndian.Uint16(msg[0:2]); got != 0xbeef {
		t.Fatalf("identifier = %#x, want 0xbeef", got)
	}
	if got := binary.BigEndian.Uint16(msg[2:4]); got&flagRecursionDesired == 0 {
		t.Fatalf("flags = %#x, want the recursion desired bit set", got)
	}
	if got := binary.BigEndian.Uint16(msg[4:6]); got != 1 {
		t.Fatalf("question count = %d, want 1", got)
	}
	want := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if got := msg[headerLen:]; string(got) != string(want) {
		t.Fatalf("question = %v, want %v", got, want)
	}
}

// TestBuildQueryRejectsUnencodableNames covers the shapes a name can take that
// cannot be written as labels.
func TestBuildQueryRejectsUnencodableNames(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{"empty", ""},
		{"empty label", "a..b"},
		{"leading dot", ".a"},
		{"label too long", string(make([]byte, 64))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildQuery(1, tc.host, typeA); err == nil {
				t.Fatalf("buildQuery(%q) succeeded, want an error", tc.host)
			}
		})
	}
}

// TestParseResponseReadsAddressesAndTheCompressedName checks the common answer:
// one A record behind a compression pointer.
func TestParseResponseReadsAddressesAndTheCompressedName(t *testing.T) {
	query, err := buildQuery(7, "example.com", typeA)
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	question, _, _, ok := parseTestQuestion(t, query)
	if !ok {
		t.Fatal("cannot read the question back")
	}
	msg := buildTestResponse(t, query, question, []testRecord{
		{typ: typeA, ip: net.IPv4(203, 0, 113, 5), ttl: 120},
		{typ: typeA, ip: net.IPv4(203, 0, 113, 6), ttl: 60},
	}, rcodeNoError, false, nil)

	resp, err := parseResponse(msg)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.id != 7 || resp.truncated || resp.rcode != rcodeNoError {
		t.Fatalf("header = %+v, want id 7, no truncation, no error", resp)
	}
	if len(resp.records) != 2 {
		t.Fatalf("records = %d, want 2", len(resp.records))
	}
	if got := resp.records[0].ip.String(); got != "203.0.113.5" {
		t.Fatalf("first address = %s, want 203.0.113.5", got)
	}
	if got := resp.records[1].ttl; got != 60 {
		t.Fatalf("second ttl = %d, want 60", got)
	}
}

// TestParseResponseReadsTheTruncationBit keeps the one flag the client acts on.
func TestParseResponseReadsTheTruncationBit(t *testing.T) {
	query, err := buildQuery(9, "example.com", typeA)
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	question, _, _, ok := parseTestQuestion(t, query)
	if !ok {
		t.Fatal("cannot read the question back")
	}
	msg := buildTestResponse(t, query, question, nil, rcodeNoError, true, nil)
	resp, err := parseResponse(msg)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if !resp.truncated {
		t.Fatal("the truncation bit was not read")
	}
}

// TestParseResponseReadsTheSOALifetime checks both halves of RFC 2308: the
// negative lifetime is the smaller of the record's TTL and its MINIMUM field.
func TestParseResponseReadsTheSOALifetime(t *testing.T) {
	tests := []struct {
		name string
		soa  testSOA
		want uint32
	}{
		{"minimum wins", testSOA{name: "test", rname: "ns.test", ttl: 3600, minimum: 300}, 300},
		{"record ttl wins", testSOA{name: "test", rname: "ns.test", ttl: 120, minimum: 900}, 120},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			query, err := buildQuery(11, "missing.test", typeA)
			if err != nil {
				t.Fatalf("build query: %v", err)
			}
			question, _, _, ok := parseTestQuestion(t, query)
			if !ok {
				t.Fatal("cannot read the question back")
			}
			soa := tc.soa
			msg := buildTestResponse(t, query, question, nil, rcodeNXDomain, false, &soa)
			resp, err := parseResponse(msg)
			if err != nil {
				t.Fatalf("parse response: %v", err)
			}
			if resp.rcode != rcodeNXDomain {
				t.Fatalf("rcode = %d, want %d", resp.rcode, rcodeNXDomain)
			}
			if !resp.hasSOA {
				t.Fatal("the SOA record was not read")
			}
			if resp.soaTTL != tc.want {
				t.Fatalf("soa lifetime = %d, want %d", resp.soaTTL, tc.want)
			}
		})
	}
}

// TestParseResponseRejectsMalformedMessages covers the shapes a hostile or
// broken server can send. None of them may panic.
func TestParseResponseRejectsMalformedMessages(t *testing.T) {
	query, err := buildQuery(13, "example.com", typeA)
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	question, _, _, ok := parseTestQuestion(t, query)
	if !ok {
		t.Fatal("cannot read the question back")
	}
	good := buildTestResponse(t, query, question, []testRecord{
		{typ: typeA, ip: net.IPv4(192, 0, 2, 1), ttl: 60},
	}, rcodeNoError, false, nil)

	// A pointer that points at itself: the name never terminates.
	loop := append([]byte(nil), good...)
	loop[headerLen] = 0xc0
	loop[headerLen+1] = 0x0c

	tests := []struct {
		name string
		msg  []byte
	}{
		{"empty", nil},
		{"short header", []byte{0, 1, 2}},
		{"header only", good[:headerLen]},
		{"cut mid record", good[:len(good)-2]},
		{"self pointer", loop},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseResponse(tc.msg); err == nil {
				t.Fatal("parseResponse accepted a malformed message")
			}
		})
	}
}

// TestReadNameRejectsAForwardPointer checks the property that makes parsing
// terminate: every compression pointer has to move backwards.
func TestReadNameRejectsAForwardPointer(t *testing.T) {
	msg := []byte{0xc0, 0x04, 0x00, 1, 'a', 0}
	if _, _, err := readName(msg, 0); !errors.Is(err, errNameLoop) {
		t.Fatalf("error = %v, want %v", err, errNameLoop)
	}
}

// TestReadNameFollowsAPointerChain checks a legal chain: the name at the front is
// a pointer to a name further back, which itself ends at the root label.
func TestReadNameFollowsAPointerChain(t *testing.T) {
	msg := []byte{
		0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
	}
	// Append a name at the end that points back at offset 0.
	start := len(msg)
	msg = append(msg, 0x03, 'a', 'p', 'i', 0xc0, 0x00)
	name, next, err := readName(msg, start)
	if err != nil {
		t.Fatalf("read name: %v", err)
	}
	if name != "api.www.example.com" {
		t.Fatalf("name = %q, want api.www.example.com", name)
	}
	if next != len(msg) {
		t.Fatalf("next = %d, want %d", next, len(msg))
	}
}
