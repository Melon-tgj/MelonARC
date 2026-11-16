package outbound

import "testing"

// withUnusable installs entries for the duration of a test and puts the shipped
// list back afterwards. The shipped list is empty, so a test that exercises the
// mechanism has to supply the entries itself; leaving them installed would make
// the next test read a list this build does not ship.
func withUnusable(t *testing.T, entries ...Unusable) {
	t.Helper()
	shipped := unusableProtocols
	unusableProtocols = entries
	t.Cleanup(func() { unusableProtocols = shipped })
}

// implementedTypes is every type [New] accepts, spelled the way a configuration
// writes it.
func implementedTypes() []string {
	return []string{
		"socks5", "socks5-tls", "http", "https", "ss", "vmess", "trojan",
		"snell", "vless", "hysteria2", "tuic",
	}
}

// Nothing this build implements is on the list any more. hysteria2 and tuic
// left it when the interop gate passed in CI on 2026-11-16; an entry coming back
// means the README matrix row and this test have to change together.
func TestNoImplementedProtocolIsUnusable(t *testing.T) {
	if got := UnusableProtocols(); len(got) != 0 {
		t.Fatalf("the shipped list is not empty: %v", got)
	}
	for _, typ := range implementedTypes() {
		if entry, ok := IsUnusable(typ); ok {
			t.Fatalf("%s is reported unusable: %s", typ, entry.Reason)
		}
	}
}

func TestIsUnusableMatchesTheWayNewDoes(t *testing.T) {
	withUnusable(t, Unusable{Protocol: "hysteria2", Reason: "test entry"})
	cases := []struct {
		typ  string
		want bool
	}{
		{"hysteria2", true},
		{"Hysteria2", true},
		{"  hysteria2  ", true},
		{"HYSTERIA2", true},
		{"tuic", false},
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
	withUnusable(t, Unusable{Protocol: "hysteria2", Reason: "test entry"})
	first := UnusableProtocols()
	first[0].Protocol = "tampered"
	if again := UnusableProtocols(); again[0].Protocol == "tampered" {
		t.Fatal("the list is shared with the caller")
	}
}

// A protocol on the list is one this build implements: the warning says "known
// unusable", not "missing". If a type ever stops being implemented, the entry
// has to be reworded rather than left to describe the wrong problem.
//
// The entries are injected because the shipped list is empty; the guard matters
// the moment one returns.
func TestUnusableProtocolsAreImplemented(t *testing.T) {
	withUnusable(t,
		Unusable{Protocol: "hysteria2", Reason: "test entry"},
		Unusable{Protocol: "tuic", Reason: "test entry"},
	)
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
