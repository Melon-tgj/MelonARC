package outbound

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    Target
		wantErr bool
	}{
		{name: "name and port", address: "example.com:443", want: Target{Host: "example.com", Port: 443}},
		{name: "ipv4", address: "192.0.2.10:80", want: Target{Host: "192.0.2.10", Port: 80}},
		{name: "ipv6", address: "[2001:db8::1]:8443", want: Target{Host: "2001:db8::1", Port: 8443}},
		{name: "missing port", address: "example.com", wantErr: true},
		{name: "missing host", address: ":80", wantErr: true},
		{name: "empty port", address: "example.com:", wantErr: true},
		{name: "port zero", address: "example.com:0", wantErr: true},
		{name: "port too large", address: "example.com:70000", wantErr: true},
		{name: "port not a number", address: "example.com:http", wantErr: true},
		{name: "unbracketed ipv6", address: "2001:db8::1:80", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTarget(tc.address)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q) = %+v, want an error", tc.address, got)
				}
				if !errors.Is(err, ErrInvalidAddress) {
					t.Fatalf("ParseTarget(%q) error = %v, want ErrInvalidAddress", tc.address, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q): %v", tc.address, err)
			}
			if got != tc.want {
				t.Fatalf("ParseTarget(%q) = %+v, want %+v", tc.address, got, tc.want)
			}
		})
	}
}

func TestTargetStringAndIP(t *testing.T) {
	tests := []struct {
		target Target
		want   string
		wantIP bool
	}{
		{target: Target{Host: "example.com", Port: 80}, want: "example.com:80"},
		{target: Target{Host: "192.0.2.1", Port: 443}, want: "192.0.2.1:443", wantIP: true},
		{target: Target{Host: "2001:db8::1", Port: 53}, want: "[2001:db8::1]:53", wantIP: true},
	}
	for _, tc := range tests {
		if got := tc.target.String(); got != tc.want {
			t.Errorf("Target%+v.String() = %q, want %q", tc.target, got, tc.want)
		}
		if got := tc.target.IsIP(); got != tc.wantIP {
			t.Errorf("Target%+v.IsIP() = %v, want %v", tc.target, got, tc.wantIP)
		}
		if tc.target.Network() != "melonarc" {
			t.Errorf("Target%+v.Network() = %q", tc.target, tc.target.Network())
		}
	}
}

func TestSetAddAndLookup(t *testing.T) {
	set := NewSet()
	if err := set.Add("a", NewDirect()); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := set.Dialer("a"); err != nil {
		t.Fatalf("Dialer(a): %v", err)
	}
	if _, err := set.Dialer("b"); !errors.Is(err, ErrUnknownDialer) {
		t.Fatalf("Dialer(b) error = %v, want ErrUnknownDialer", err)
	}
	if err := set.Add("a", NewDirect()); err == nil {
		t.Fatal("Add of a duplicate name succeeded")
	}
	if err := set.Add("", NewDirect()); err == nil {
		t.Fatal("Add of an empty name succeeded")
	}
	if err := set.Add("c", nil); err == nil {
		t.Fatal("Add of a nil dialer succeeded")
	}
	if got := set.Names(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("Names() = %v, want [a]", got)
	}
}

func TestDirectDialContext(t *testing.T) {
	echo := startTCPEcho(t)
	conn := dialThrough(t, NewDirect(), echo)
	payload := []byte("hello over tcp")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestDirectDialPacket(t *testing.T) {
	if !datagramSendAllowed(t) {
		t.Skip("the environment does not allow the echo server to answer")
	}
	echo := startUDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	packet, err := NewDirect().DialPacket(ctx, echo)
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer packet.Close()
	if _, err := packet.Write([]byte("datagram")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := packet.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, err := packet.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "datagram" {
		t.Fatalf("echo = %q, want %q", buf[:n], "datagram")
	}
	if packet.RemoteAddr().String() != echo {
		t.Fatalf("RemoteAddr = %s, want %s", packet.RemoteAddr(), echo)
	}
}

func TestDirectHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewDirect().DialContext(ctx, "192.0.2.1:9"); err == nil {
		t.Fatal("dial with a cancelled context succeeded")
	}
}

func TestDirectRejectsInvalidAddress(t *testing.T) {
	if _, err := NewDirect().DialContext(context.Background(), "not-an-address"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("DialContext error = %v, want ErrInvalidAddress", err)
	}
	if _, err := NewDirect().DialPacket(context.Background(), "not-an-address"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("DialPacket error = %v, want ErrInvalidAddress", err)
	}
}

func TestRejectAndUnsupported(t *testing.T) {
	if _, err := NewReject().DialContext(context.Background(), "example.com:80"); !errors.Is(err, ErrRejected) {
		t.Fatalf("Reject.DialContext error = %v, want ErrRejected", err)
	}
	if _, err := NewReject().DialPacket(context.Background(), "example.com:53"); !errors.Is(err, ErrRejected) {
		t.Fatalf("Reject.DialPacket error = %v, want ErrRejected", err)
	}
	unsupported := &Unsupported{Protocol: "vmess"}
	if _, err := unsupported.DialContext(context.Background(), "example.com:80"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Unsupported.DialContext error = %v, want ErrUnsupported", err)
	}
	if _, err := unsupported.DialPacket(context.Background(), "example.com:53"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Unsupported.DialPacket error = %v, want ErrUnsupported", err)
	}
}
