package geoip

import (
	"net"
	"testing"

	"github.com/melon-tgj/melonarc/internal/geoip/geoiptest"
	"github.com/melon-tgj/melonarc/internal/rules"
)

// TestGeoIPRuleRoutesFromTheDatabase checks the whole address path: a compiled
// program with a GEOIP rule reads the database and sends an address the database
// covers to the target the rule names, while an address it does not cover falls
// through to the next rule.
func TestGeoIPRuleRoutesFromTheDatabase(t *testing.T) {
	path := writeFixture(t, "country.mmdb", func() ([]byte, error) {
		return geoiptest.Country(map[string][]string{
			"ZZ": {"203.0.113.0/24"},
			"YY": {"198.51.100.0/24"},
		})
	})
	db, err := Open(path, KindCountry)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	compile := func(code string) *rules.Program {
		t.Helper()
		program, err := rules.Compile(rules.Options{
			Rules: []*rules.Rule{
				{Kind: rules.KindGeoIP, Payload: code, Target: "via", Source: "config"},
				{Kind: rules.KindFinal, Target: "DIRECT", Source: "config"},
			},
			GeoIP: db,
		})
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return program
	}

	tests := []struct {
		name string
		code string
		addr string
		want string
	}{
		{name: "covered", code: "ZZ", addr: "203.0.113.5", want: "via"},
		{name: "other country", code: "ZZ", addr: "198.51.100.5", want: "DIRECT"},
		{name: "unknown address", code: "ZZ", addr: "10.0.0.1", want: "DIRECT"},
		{name: "second code", code: "YY", addr: "198.51.100.5", want: "via"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			program := compile(tc.code)
			decision, ok := program.Match(rules.Query{Addr: net.ParseIP(tc.addr), Network: "tcp", Port: 443})
			if !ok {
				t.Fatalf("no decision for %s", tc.addr)
			}
			if decision.Target != tc.want {
				t.Fatalf("target = %q, want %q (rule %s)", decision.Target, tc.want, decision.Rule)
			}
		})
	}
}

// TestASNLogicalRuleRoutesFromTheDatabase is the same check for IP-ASN.
func TestASNLogicalRuleRoutesFromTheDatabase(t *testing.T) {
	path := writeFixture(t, "asn.mmdb", func() ([]byte, error) {
		return geoiptest.ASN(map[uint32][]string{64512: {"203.0.113.0/24"}})
	})
	db, err := Open(path, KindASN)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	program, err := rules.Compile(rules.Options{
		Rules: []*rules.Rule{
			{Kind: rules.KindIPASN, Payload: "64512", Target: "via", Source: "config"},
			{Kind: rules.KindFinal, Target: "DIRECT", Source: "config"},
		},
		ASN: db,
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	decision, ok := program.Match(rules.Query{Addr: net.ParseIP("203.0.113.5"), Network: "tcp"})
	if !ok || decision.Target != "via" {
		t.Fatalf("decision = %+v, want the asn rule to win", decision)
	}
	decision, ok = program.Match(rules.Query{Addr: net.ParseIP("203.0.114.5"), Network: "tcp"})
	if !ok || decision.Target != "DIRECT" {
		t.Fatalf("decision = %+v, want the final rule", decision)
	}
}

// TestNoResolveKeepsTheDatabaseOutOfThePath checks that no-resolve still applies
// to a database backed rule: a resolved address must not reach it.
func TestNoResolveKeepsTheDatabaseOutOfThePath(t *testing.T) {
	path := writeFixture(t, "country.mmdb", func() ([]byte, error) {
		return geoiptest.Country(map[string][]string{"ZZ": {"203.0.113.0/24"}})
	})
	db, err := Open(path, KindCountry)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	program, err := rules.Compile(rules.Options{
		Rules: []*rules.Rule{
			{Kind: rules.KindGeoIP, Payload: "ZZ", Target: "via", NoResolve: true, Source: "config"},
			{Kind: rules.KindFinal, Target: "DIRECT", Source: "config"},
		},
		GeoIP: db,
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	resolved := rules.Query{Addr: net.ParseIP("203.0.113.5"), Network: "tcp", Resolved: true}
	if decision, ok := program.Match(resolved); !ok || decision.Target != "DIRECT" {
		t.Fatalf("decision = %+v, want the no-resolve rule to be skipped", decision)
	}
	given := rules.Query{Addr: net.ParseIP("203.0.113.5"), Network: "tcp"}
	if decision, ok := program.Match(given); !ok || decision.Target != "via" {
		t.Fatalf("decision = %+v, want the rule to match an address the client gave", decision)
	}
}
