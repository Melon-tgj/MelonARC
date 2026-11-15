package outbound

import "testing"

func TestUnusableProtocolsCoverTheKnownFailingOnes(t *testing.T) {
	got := map[string]bool{}
	for _, entry := range UnusableProtocols() {
		if entry.Protocol == "" {
			t.Fatal("an entry has no protocol")
		}
		if entry.Reason == "" {
			t.Fatalf("%s has no reason", entry.Protocol)
		}
		if entry.Protocol != "hysteria2" && entry.Protocol != "tuic" {
			t.Fatalf("unexpected protocol on the unusable list: %s", entry.Protocol)
		}
		got[entry.Protocol] = true
	}
	for _, want := range []string{"hysteria2", "tuic"} {
		if !got[want] {
			t.Fatalf("%s is missing from the unusable list", want)
		}
	}
}

func TestIsUnusableMatchesTheWayNewDoes(t *testing.T) {
	cases := []struct {
		typ  string
		want bool
	}{
		{"hysteria2", true},
		{"Hysteria2", true},
		{"  tuic  ", true},
		{"TUIC", true},
		{"vless", false},
		{"socks5", false},
		{"", false},
	}
	for _, c := range cases {
		entry, ok := IsUnusable(c.typ)
		if ok != c.want {
			t.Fatalf("IsUnusable(%q) = %v, want %v", c.typ, ok, c.want)
		}
		if ok && entry.Protocol == "" {
			t.Fatalf("IsUnusable(%q) returned an empty entry", c.typ)
		}
	}
}

func TestUnusableProtocolsReturnsACopy(t *testing.T) {
	first := UnusableProtocols()
	first[0].Protocol = "tampered"
	if again := UnusableProtocols(); again[0].Protocol == "tampered" {
		t.Fatal("the list is shared with the caller")
	}
}

// A protocol on the list is one this build implements: the warning says "known
// unusable", not "missing". If a type ever stops being implemented, the entry
// has to be reworded rather than left to describe the wrong problem.
func TestUnusableProtocolsAreImplemented(t *testing.T) {
	for _, entry := range UnusableProtocols() {
		spec := Spec{Type: entry.Protocol, Server: "203.0.113.1", Port: 443}
		dialer, err := New(spec)
		if err != nil {
			// A missing option is expected here; only the Unsupported path
			// means the type is unknown to this build, and that path does not
			// return an error.
			continue
		}
		if _, unsupported := dialer.(*Unsupported); unsupported {
			t.Fatalf("%s is on the unusable list but this build does not implement it", entry.Protocol)
		}
	}
}
