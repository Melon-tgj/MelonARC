package config

import (
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/dns"
)

// TestParseDNSSettings checks the four upstream settings: the server list keeps
// its order, the fallback keeps its word, the timeout accepts a duration and the
// two data set paths are kept as written.
func TestParseDNSSettings(t *testing.T) {
	in := `[General]
dns-nameserver = 1.1.1.1, 9.9.9.9:5353, [2001:db8::1]:53
dns-fallback = none
dns-timeout = 1500ms
geoip-db = ./data/country.mmdb
asn-db = /var/lib/melonarc/asn.mmdb

[Rule]
FINAL,DIRECT
`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"1.1.1.1", "9.9.9.9:5353", "[2001:db8::1]:53"}
	if len(cfg.General.NameServers) != len(want) {
		t.Fatalf("nameservers = %v, want %v", cfg.General.NameServers, want)
	}
	for i := range want {
		if cfg.General.NameServers[i] != want[i] {
			t.Fatalf("nameservers = %v, want %v", cfg.General.NameServers, want)
		}
	}
	if cfg.General.DNSFallback != DNSFallbackNone {
		t.Fatalf("dns-fallback = %q, want %q", cfg.General.DNSFallback, DNSFallbackNone)
	}
	if cfg.General.DNSTimeout != 1500*time.Millisecond {
		t.Fatalf("dns-timeout = %v, want 1.5s", cfg.General.DNSTimeout)
	}
	if cfg.General.GeoIPDB != "./data/country.mmdb" || cfg.General.ASNDB != "/var/lib/melonarc/asn.mmdb" {
		t.Fatalf("data sets = %q, %q", cfg.General.GeoIPDB, cfg.General.ASNDB)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestDefaultsOfTheDNSSettings keeps the parser from inventing an upstream: a
// configuration that says nothing keeps using the system resolver.
func TestDefaultsOfTheDNSSettings(t *testing.T) {
	cfg, err := Parse([]byte("[Rule]\nFINAL,DIRECT\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.General.NameServers) != 0 {
		t.Fatalf("nameservers = %v, want none", cfg.General.NameServers)
	}
	if cfg.General.DNSFallback != "" {
		t.Fatalf("dns-fallback = %q, want unset", cfg.General.DNSFallback)
	}
	if cfg.General.DNSTimeout != defaultDNSTimeout {
		t.Fatalf("dns-timeout = %v, want %v", cfg.General.DNSTimeout, defaultDNSTimeout)
	}
	if !cfg.General.FallbackToSystem() {
		t.Fatal("an unset dns-fallback must fall back to the system resolver")
	}
	if cfg.General.GeoIPDB != "" || cfg.General.ASNDB != "" {
		t.Fatalf("data sets = %q, %q, want both unset", cfg.General.GeoIPDB, cfg.General.ASNDB)
	}
}

// TestFallbackToSystem checks the two accepted words and the default.
func TestFallbackToSystem(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "", want: true},
		{value: "system", want: true},
		{value: "SYSTEM", want: true},
		{value: "none", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			cfg := &Config{General: General{DNSFallback: tc.value}}
			if got := cfg.General.FallbackToSystem(); got != tc.want {
				t.Fatalf("FallbackToSystem(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// TestDefaultUpstreamTimeoutLeavesRoomForTheFallback guards the arithmetic the
// default rests on. One question costs one datagram and one stream attempt per
// server, so two servers spend four attempts; if those attempts could fill the
// resolver's whole budget, a configured fallback to the system resolver would
// never be reached and the setting would be a promise the code cannot keep.
func TestDefaultUpstreamTimeoutLeavesRoomForTheFallback(t *testing.T) {
	const (
		servers    = 2
		transports = 2
	)
	spent := time.Duration(servers*transports) * defaultDNSTimeout
	if spent >= dns.DefaultTimeout {
		t.Fatalf("two servers on two transports spend %v of a %v budget, leaving nothing for the fallback",
			spent, dns.DefaultTimeout)
	}
}

// TestValidateRejectsUnusableDNSSettings covers every way the upstream settings
// can be wrong.
func TestValidateRejectsUnusableDNSSettings(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "server is a name", body: "dns-nameserver = dns.example", want: "IP address"},
		{name: "server port is zero", body: "dns-nameserver = 1.1.1.1:0", want: "invalid port"},
		{name: "fallback without servers", body: "dns-fallback = none", want: "has no effect"},
		{name: "unknown fallback", body: "dns-fallback = upstream\ndns-nameserver = 1.1.1.1", want: "not one of system, none"},
		{name: "zero timeout", body: "dns-timeout = 0", want: "must be positive"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte("[General]\n" + tc.body + "\n\n[Rule]\nFINAL,DIRECT\n"))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			err = cfg.Validate()
			if err == nil {
				t.Fatal("Validate accepted the setting")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestValidateRejectsUnusableDatasetPaths covers a path that cannot be meant as
// one, which is the only thing validation can say about it.
func TestValidateRejectsUnusableDatasetPaths(t *testing.T) {
	cfg, err := Parse([]byte("[Rule]\nFINAL,DIRECT\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.General.GeoIPDB = "data\x00country.mmdb"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "control characters") {
		t.Fatalf("error = %v, want a control character problem", err)
	}
}

// TestDataPathResolvesAgainstTheConfigurationDirectory checks the one rule both
// data sets and rule sets follow.
func TestDataPathResolvesAgainstTheConfigurationDirectory(t *testing.T) {
	cfg := &Config{BaseDir: "/etc/melonarc"}
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "./country.mmdb", want: "/etc/melonarc/country.mmdb"},
		{in: "data/asn.mmdb", want: "/etc/melonarc/data/asn.mmdb"},
		{in: "/var/lib/asn.mmdb", want: "/var/lib/asn.mmdb"},
	}
	for _, tc := range tests {
		if got := cfg.DataPath(tc.in); got != tc.want {
			t.Fatalf("DataPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// Without a base directory a relative path is left alone, which is what a
	// configuration parsed from memory looks like.
	if got := (&Config{}).DataPath("./country.mmdb"); got != "./country.mmdb" {
		t.Fatalf("DataPath without a base = %q, want it unchanged", got)
	}
}
