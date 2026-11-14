package dns

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseQuestionReadsAStandardQuery(t *testing.T) {
	msg, err := buildQuery(0xabcd, "service.test", typeA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	q, err := ParseQuestion(msg)
	if err != nil {
		t.Fatalf("ParseQuestion: %v", err)
	}
	if q.ID != 0xabcd || q.Name != "service.test" || q.Type != typeA || q.Class != classINET {
		t.Fatalf("question = %+v", q)
	}
	if string(q.Raw) != string(msg[headerLen:]) {
		t.Fatal("the question bytes were not echoed verbatim")
	}
}

func TestParseQuestionRejectsNonQueries(t *testing.T) {
	msg, err := buildQuery(1, "service.test", typeA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"truncated", func(b []byte) []byte { return b[:8] }},
		{"response bit", func(b []byte) []byte { b[2] |= 0x80; return b }},
		{"two questions", func(b []byte) []byte { b[5] = 2; return b }},
		{"cut question", func(b []byte) []byte { return b[:len(b)-2] }},
		{"non-IN class", func(b []byte) []byte { b[len(b)-1] = 3; return b }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseQuestion(tc.mutate(append([]byte(nil), msg...))); err == nil {
				t.Fatal("a malformed or non-query message was accepted")
			}
		})
	}
}

func TestAnswerQuestionCarriesOneAddressAndEchoesTheQuestion(t *testing.T) {
	msg, err := buildQuery(0x1357, "service.test", typeA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	q, err := ParseQuestion(msg)
	if err != nil {
		t.Fatalf("ParseQuestion: %v", err)
	}
	answer := AnswerQuestion(q, RcodeOK, 60, []net.IP{net.IPv4(198, 18, 1, 7)})
	if len(answer) < headerLen {
		t.Fatalf("answer is %d bytes", len(answer))
	}
	if binary.BigEndian.Uint16(answer[0:2]) != q.ID || answer[2]&0x80 == 0 {
		t.Fatalf("answer header = %v", answer[:4])
	}
	if binary.BigEndian.Uint16(answer[6:8]) != 1 || answer[3]&0x0f != 0 {
		t.Fatal("answer should carry one record and rcode 0")
	}
	if string(answer[headerLen:headerLen+len(q.Raw)]) != string(q.Raw) {
		t.Fatal("the question was not echoed")
	}
	// The last four bytes of an A answer are the address.
	if got := net.IP(answer[len(answer)-4:]).String(); got != "198.18.1.7" {
		t.Fatalf("answer address = %s", got)
	}
	// The parser of this package must be able to read the answer back.
	parsed, err := parseResponse(answer)
	if err != nil {
		t.Fatalf("parseResponse: %v", err)
	}
	if len(parsed.records) != 1 || parsed.records[0].ttl != 60 || !parsed.records[0].ip.Equal(net.IPv4(198, 18, 1, 7)) {
		t.Fatalf("records = %+v", parsed.records)
	}
}

func TestAnswerQuestionHandlesNegativeAndNonATypes(t *testing.T) {
	msg, err := buildQuery(0x2468, "missing.test", typeA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	q, err := ParseQuestion(msg)
	if err != nil {
		t.Fatalf("ParseQuestion: %v", err)
	}
	answer := AnswerQuestion(q, RcodeNXDomain, 30, []net.IP{net.IPv4(198, 18, 1, 7)})
	if answer[3]&0x0f != RcodeNXDomain || binary.BigEndian.Uint16(answer[6:8]) != 0 {
		t.Fatalf("NXDOMAIN answer = %v", answer[:12])
	}

	msg, err = buildQuery(0x2468, "service.test", typeAAAA)
	if err != nil {
		t.Fatalf("buildQuery AAAA: %v", err)
	}
	q, err = ParseQuestion(msg)
	if err != nil {
		t.Fatalf("ParseQuestion AAAA: %v", err)
	}
	answer = AnswerQuestion(q, RcodeOK, 30, []net.IP{net.IPv4(198, 18, 1, 7)})
	if q.Type == QueryTypeA {
		t.Fatal("the second question should not be an A question")
	}
	if binary.BigEndian.Uint16(answer[6:8]) != 0 || answer[3]&0x0f != 0 {
		t.Fatalf("AAAA answer = %v", answer[:12])
	}
}
