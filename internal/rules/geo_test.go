package rules

import (
	"net"
	"strings"
	"testing"
)

func TestMemGeoIP(t *testing.T) {
	db, err := NewMemGeoIP(map[string][]string{
		"CN": {"1.0.1.0/24", "2001:db8:1::/48"},
		"US": {"8.8.8.0/24"},
	})
	if err != nil {
		t.Fatalf("NewMemGeoIP: %v", err)
	}
	tests := []struct {
		addr string
		want string
		ok   bool
	}{
		{"1.0.1.9", "CN", true},
		{"1.0.2.9", "", false},
		{"8.8.8.8", "US", true},
		{"2001:db8:1::5", "CN", true},
		{"2001:db8:2::5", "", false},
	}
	for _, tc := range tests {
		got, ok := db.Country(net.ParseIP(tc.addr))
		if ok != tc.ok || got != tc.want {
			t.Errorf("Country(%s) = %q, %v; want %q, %v", tc.addr, got, ok, tc.want, tc.ok)
		}
	}
	if _, ok := db.Country(nil); ok {
		t.Error("a nil address must not match")
	}
}

func TestMemGeoIPOverlapIsDeterministic(t *testing.T) {
	db, err := NewMemGeoIP(map[string][]string{
		"ZZ": {"10.1.0.0/16"},
		"AA": {"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("NewMemGeoIP: %v", err)
	}
	// Both codes cover 10.1.2.3; the alphabetically first code wins.
	if got, _ := db.Country(net.ParseIP("10.1.2.3")); got != "AA" {
		t.Fatalf("Country = %q, want AA", got)
	}
}

func TestMemGeoIPRejectsBadPrefix(t *testing.T) {
	if _, err := NewMemGeoIP(map[string][]string{"CN": {"not-a-prefix"}}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestMemASN(t *testing.T) {
	db, err := NewMemASN(map[uint32][]string{
		13335: {"1.1.1.0/24", "2606:4700::/32"},
		15169: {"8.8.8.0/24"},
	})
	if err != nil {
		t.Fatalf("NewMemASN: %v", err)
	}
	tests := []struct {
		addr string
		want uint32
		ok   bool
	}{
		{"1.1.1.1", 13335, true},
		{"8.8.8.8", 15169, true},
		{"2606:4700::1111", 13335, true},
		{"9.9.9.9", 0, false},
	}
	for _, tc := range tests {
		got, ok := db.ASN(net.ParseIP(tc.addr))
		if ok != tc.ok || got != tc.want {
			t.Errorf("ASN(%s) = %d, %v; want %d, %v", tc.addr, got, ok, tc.want, tc.ok)
		}
	}
}

func TestGeoIPAndASNRules(t *testing.T) {
	geo, err := NewMemGeoIP(map[string][]string{
		"CN": {"1.0.1.0/24"},
		"US": {"8.8.8.0/24"},
	})
	if err != nil {
		t.Fatalf("NewMemGeoIP: %v", err)
	}
	asn, err := NewMemASN(map[uint32][]string{15169: {"8.8.8.0/24"}})
	if err != nil {
		t.Fatalf("NewMemASN: %v", err)
	}
	p := compileLines(t, []string{
		"GEOIP,CN,DIRECT",
		"IP-ASN,15169,Proxy",
		"GEOIP,US,REJECT",
		"FINAL,Fallback",
	}, Options{GeoIP: geo, ASN: asn})

	tests := []struct {
		addr string
		want string
	}{
		{"1.0.1.5", "DIRECT"},
		{"8.8.8.8", "Proxy"}, // the ASN rule comes before the US geo rule
		{"9.9.9.9", "Fallback"},
	}
	for _, tc := range tests {
		got, _ := p.Match(Query{Addr: net.ParseIP(tc.addr)})
		if got.Target != tc.want {
			t.Errorf("%s: target = %q, want %q", tc.addr, got.Target, tc.want)
		}
	}

	e := p.Explain(Query{Addr: net.ParseIP("1.0.1.5")})
	if !strings.Contains(e.String(), "address is in CN") {
		t.Errorf("explanation should describe the geo lookup:\n%s", e.String())
	}
}

func TestAddressRulesSkipWithoutAddress(t *testing.T) {
	geo, err := NewMemGeoIP(map[string][]string{"CN": {"1.0.1.0/24"}})
	if err != nil {
		t.Fatalf("NewMemGeoIP: %v", err)
	}
	p := compileLines(t, []string{"GEOIP,CN,REJECT", "FINAL,DIRECT"}, Options{GeoIP: geo})
	e := p.Explain(Query{Name: "example.com"})
	if e.Decision.Target != "DIRECT" {
		t.Fatalf("target = %q", e.Decision.Target)
	}
	if !strings.Contains(e.String(), "skipped: query carries no address") {
		t.Errorf("explanation should record the skipped geo step:\n%s", e.String())
	}
}
