package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// TestParseNameServer checks the two accepted shapes and the rejected ones.
func TestParseNameServer(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "1.1.1.1", want: "1.1.1.1:53"},
		{in: " 9.9.9.9 ", want: "9.9.9.9:53"},
		{in: "8.8.8.8:5353", want: "8.8.8.8:5353"},
		{in: "2001:db8::1", want: "[2001:db8::1]:53"},
		{in: "[2001:db8::1]:5353", want: "[2001:db8::1]:5353"},
		{in: "dns.example", wantErr: true},
		{in: "dns.example:53", wantErr: true},
		{in: "1.1.1.1:0", wantErr: true},
		{in: "1.1.1.1:70000", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseNameServer(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseNameServer(%q) = %q, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseNameServer(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseNameServer(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNewUpstreamDeduplicates keeps one address from being asked twice, which
// would only double the latency of a failing lookup.
func TestNewUpstreamDeduplicates(t *testing.T) {
	up, err := NewUpstream([]string{"1.1.1.1", "1.1.1.1:53", "9.9.9.9"}, 0)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	got := up.Servers()
	want := []string{"1.1.1.1:53", "9.9.9.9:53"}
	if len(got) != len(want) {
		t.Fatalf("servers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("servers = %v, want %v", got, want)
		}
	}
	if up.timeout != DefaultUpstreamTimeout {
		t.Fatalf("timeout = %v, want %v", up.timeout, DefaultUpstreamTimeout)
	}
}

// TestUpstreamAnswersOverTCP covers the transport fallback that works in every
// environment: the server publishes no datagram socket, so the datagram attempt
// is refused at once and the client retries over the stream.
func TestUpstreamAnswersOverTCP(t *testing.T) {
	server := newFakeDNS(t, map[string]zoneEntry{
		"example.test": {
			v4:  []net.IP{net.IPv4(203, 0, 113, 5), net.IPv4(203, 0, 113, 6)},
			v6:  []net.IP{net.ParseIP("2001:db8::5")},
			ttl: 120,
		},
	})
	up, err := NewUpstream([]string{server.addr()}, 2*time.Second)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	answer, err := up.Exchange(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	want := []string{"203.0.113.5", "203.0.113.6", "2001:db8::5"}
	if len(answer.IPs) != len(want) {
		t.Fatalf("addresses = %v, want %v", answer.IPs, want)
	}
	for i, ip := range wantedStrings(want) {
		if !answer.IPs[i].Equal(ip) {
			t.Fatalf("address %d = %s, want %s", i, answer.IPs[i], want[i])
		}
	}
	if answer.TTL != 120*time.Second {
		t.Fatalf("ttl = %v, want 2m", answer.TTL)
	}
	names := server.questions()
	if len(names) != 2 {
		t.Fatalf("questions = %v, want one per address family", names)
	}
	for _, name := range names {
		if name != "example.test" {
			t.Fatalf("question = %q, want example.test", name)
		}
	}
}

// TestUpstreamTakesTheSmallestTTL checks the rule the cache depends on: the
// answer is only reusable for as long as its shortest lived record.
func TestUpstreamTakesTheSmallestTTL(t *testing.T) {
	server := newFakeDNS(t, map[string]zoneEntry{
		"short.test": {v4: []net.IP{net.IPv4(192, 0, 2, 1)}, ttl: 30},
	})
	up, err := NewUpstream([]string{server.addr()}, 2*time.Second)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	answer, err := up.Exchange(context.Background(), "short.test")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if answer.TTL != 30*time.Second {
		t.Fatalf("ttl = %v, want 30s", answer.TTL)
	}
}

// TestUpstreamReportsANegativeAnswer checks that an NXDOMAIN carries both the
// "no such name" meaning and the lifetime the authority asked for.
func TestUpstreamReportsANegativeAnswer(t *testing.T) {
	server := newFakeDNS(t, map[string]zoneEntry{
		"gone.test": {
			rcode: rcodeNXDomain,
			soa:   &testSOA{name: "test", rname: "ns.test", ttl: 3600, minimum: 240},
		},
	})
	up, err := NewUpstream([]string{server.addr()}, 2*time.Second)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	_, err = up.Exchange(context.Background(), "gone.test")
	if err == nil {
		t.Fatal("exchange succeeded, want a negative answer")
	}
	if !isNotFound(err) {
		t.Fatalf("error = %v, want a not-found error", err)
	}
	var negative *NegativeError
	if !errors.As(err, &negative) {
		t.Fatalf("error = %T, want a *NegativeError", err)
	}
	if negative.Kind != NegativeNXDomain {
		t.Fatalf("kind = %q, want %q", negative.Kind, NegativeNXDomain)
	}
	if negative.Lifetime != 240*time.Second {
		t.Fatalf("lifetime = %v, want 4m", negative.Lifetime)
	}
}

// TestUpstreamReportsNoData covers the other negative answer: the name exists,
// it just carries no address of the family that was asked for.
func TestUpstreamReportsNoData(t *testing.T) {
	server := newFakeDNS(t, map[string]zoneEntry{
		"empty.test": {soa: &testSOA{name: "test", rname: "ns.test", ttl: 60, minimum: 60}},
	})
	up, err := NewUpstream([]string{server.addr()}, 2*time.Second)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	_, err = up.Exchange(context.Background(), "empty.test")
	var negative *NegativeError
	if !errors.As(err, &negative) {
		t.Fatalf("error = %v, want a *NegativeError", err)
	}
	if negative.Kind != NegativeNoData {
		t.Fatalf("kind = %q, want %q", negative.Kind, NegativeNoData)
	}
	if negative.Lifetime != 60*time.Second {
		t.Fatalf("lifetime = %v, want 1m", negative.Lifetime)
	}
}

// TestUpstreamMovesToTheNextServer keeps the configured order meaningful: the
// first server may be down without failing the lookup.
func TestUpstreamMovesToTheNextServer(t *testing.T) {
	server := newFakeDNS(t, map[string]zoneEntry{
		"example.test": {v4: []net.IP{net.IPv4(203, 0, 113, 9)}, ttl: 60},
	})
	up, err := NewUpstream([]string{"127.0.0.1:1", server.addr()}, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	answer, err := up.Exchange(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(answer.IPs) != 1 || !answer.IPs[0].Equal(net.IPv4(203, 0, 113, 9)) {
		t.Fatalf("addresses = %v, want 203.0.113.9", answer.IPs)
	}
}

// TestUpstreamTimesOutOnASilentServer checks that a server which accepts the
// question and never answers cannot hold the lookup past the budget.
func TestUpstreamTimesOutOnASilentServer(t *testing.T) {
	server := newFakeDNS(t, map[string]zoneEntry{"quiet.test": {silent: true}})
	up, err := NewUpstream([]string{server.addr()}, 150*time.Millisecond)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	start := time.Now()
	_, err = up.Exchange(context.Background(), "quiet.test")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("exchange succeeded, want a transport failure")
	}
	if isNotFound(err) {
		t.Fatalf("error = %v, want a transport failure rather than a negative answer", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("exchange took %v, want it bounded by the per attempt timeout", elapsed)
	}
}

// TestUpstreamHonoursAContextDeadline checks that the caller's budget wins over
// the configured timeout.
func TestUpstreamHonoursAContextDeadline(t *testing.T) {
	server := newFakeDNS(t, map[string]zoneEntry{"quiet.test": {silent: true}})
	up, err := NewUpstream([]string{server.addr()}, 5*time.Second)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := up.Exchange(ctx, "quiet.test"); err == nil {
		t.Fatal("exchange succeeded, want a failure")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("exchange took %v, want it bounded by the context", elapsed)
	}
}

// TestUpstreamRetriesOverTCPWhenTruncated needs a datagram socket that can send
// back, which the development sandbox forbids.
func TestUpstreamRetriesOverTCPWhenTruncated(t *testing.T) {
	if !datagramSendAllowed(t) {
		t.Skip("this environment cannot send datagrams to an unconnected peer")
	}
	server := newFakeDNSUDP(t, map[string]zoneEntry{
		"big.test": {v4: []net.IP{net.IPv4(198, 51, 100, 7)}, ttl: 90},
	})
	server.truncateOver("big.test")
	up, err := NewUpstream([]string{server.addr()}, 2*time.Second)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	answer, err := up.Exchange(context.Background(), "big.test")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(answer.IPs) != 1 || !answer.IPs[0].Equal(net.IPv4(198, 51, 100, 7)) {
		t.Fatalf("addresses = %v, want 198.51.100.7", answer.IPs)
	}
	// The question is asked twice: once over UDP, once over TCP.
	if names := server.questions(); len(names) != 4 {
		t.Fatalf("questions = %v, want four (two families over each transport)", names)
	}
}

// TestUpstreamAnswersOverUDP is the same lookup over a datagram socket.
func TestUpstreamAnswersOverUDP(t *testing.T) {
	if !datagramSendAllowed(t) {
		t.Skip("this environment cannot send datagrams to an unconnected peer")
	}
	server := newFakeDNSUDP(t, map[string]zoneEntry{
		"example.test": {v4: []net.IP{net.IPv4(192, 0, 2, 44)}, ttl: 45},
	})
	up, err := NewUpstream([]string{server.addr()}, 2*time.Second)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	answer, err := up.Exchange(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(answer.IPs) != 1 || !answer.IPs[0].Equal(net.IPv4(192, 0, 2, 44)) {
		t.Fatalf("addresses = %v, want 192.0.2.44", answer.IPs)
	}
}

// TestUpstreamErrorNamesTheServer keeps a multi server failure diagnosable.
func TestUpstreamErrorNamesTheServer(t *testing.T) {
	up, err := NewUpstream([]string{"127.0.0.1:1"}, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	_, err = up.Exchange(context.Background(), "example.test")
	if err == nil {
		t.Fatal("exchange succeeded, want a failure")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("error = %v, want the server address in it", err)
	}
}

// wantedStrings parses the addresses a test expects.
func wantedStrings(addrs []string) []net.IP {
	out := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, net.ParseIP(addr))
	}
	return out
}

// TestAnswerNeedsStream covers the decision that sends the client back over the
// stream. It reads the header only, so a truncated message whose body ends in the
// middle of a record still has to be asked again rather than reported as a broken
// answer.
func TestAnswerNeedsStream(t *testing.T) {
	header := func(id uint16, flags uint16) []byte {
		msg := make([]byte, headerLen)
		binary.BigEndian.PutUint16(msg[0:2], id)
		binary.BigEndian.PutUint16(msg[2:4], flags)
		return msg
	}
	tests := []struct {
		name string
		msg  []byte
		want bool
		fail bool
	}{
		{name: "complete answer", msg: header(7, 0x8180)},
		{name: "truncated answer", msg: header(7, 0x8180|flagTruncated), want: true},
		{name: "truncated with a cut body", msg: append(header(7, 0x8180|flagTruncated), 0xc0, 0x0c, 0x00), want: true},
		{name: "short answer", msg: header(7, 0x8180)[:6], fail: true},
		{name: "different identifier", msg: header(8, 0x8180), fail: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := answerNeedsStream(tc.msg, 7)
			if tc.fail {
				if err == nil {
					t.Fatal("answerNeedsStream accepted the message")
				}
				return
			}
			if err != nil {
				t.Fatalf("answerNeedsStream: %v", err)
			}
			if got != tc.want {
				t.Fatalf("needs stream = %v, want %v", got, tc.want)
			}
		})
	}
}
