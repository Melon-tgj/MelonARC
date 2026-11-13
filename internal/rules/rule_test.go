package rules

import (
	"strings"
	"testing"
)

func TestParseRule(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantKind Kind
		wantPay  string
		wantTgt  string
		wantNoRe bool
	}{
		{name: "domain", line: "DOMAIN,API.Example.com,Proxy", wantKind: KindDomain, wantPay: "api.example.com", wantTgt: "Proxy"},
		{name: "domain suffix", line: "DOMAIN-SUFFIX, example.com , Proxy ", wantKind: KindDomainSuffix, wantPay: "example.com", wantTgt: "Proxy"},
		{name: "keyword", line: "domain-keyword,Analytics,DIRECT", wantKind: KindDomainKeyword, wantPay: "analytics", wantTgt: "DIRECT"},
		{name: "domain set", line: "DOMAIN-SET,ads,REJECT", wantKind: KindDomainSet, wantPay: "ads", wantTgt: "REJECT"},
		{name: "ip cidr", line: "IP-CIDR,10.1.2.3/8,DIRECT", wantKind: KindIPCIDR, wantPay: "10.0.0.0/8", wantTgt: "DIRECT"},
		{name: "ip cidr no resolve", line: "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", wantKind: KindIPCIDR, wantPay: "192.168.0.0/16", wantTgt: "DIRECT", wantNoRe: true},
		{name: "ip cidr6", line: "IP-CIDR6,2001:DB8::1/32,Proxy", wantKind: KindIPCIDR6, wantPay: "2001:db8::/32", wantTgt: "Proxy"},
		{name: "geoip", line: "GEOIP,cn,DIRECT", wantKind: KindGeoIP, wantPay: "CN", wantTgt: "DIRECT"},
		{name: "asn", line: "IP-ASN,AS13335,Proxy", wantKind: KindIPASN, wantPay: "13335", wantTgt: "Proxy"},
		{name: "rule set", line: "RULE-SET,ad_block,REJECT", wantKind: KindRuleSet, wantPay: "ad_block", wantTgt: "REJECT"},
		{name: "port", line: "DEST-PORT,443,Proxy", wantKind: KindDestPort, wantPay: "443", wantTgt: "Proxy"},
		{name: "port range", line: "DEST-PORT,8000-8100,Proxy", wantKind: KindDestPort, wantPay: "8000-8100", wantTgt: "Proxy"},
		{name: "protocol", line: "PROTOCOL,tcp,Proxy", wantKind: KindProtocol, wantPay: "tcp", wantTgt: "Proxy"},
		{name: "final", line: "FINAL,DIRECT", wantKind: KindFinal, wantTgt: "DIRECT"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ParseRule(tc.line)
			if err != nil {
				t.Fatalf("ParseRule(%q): %v", tc.line, err)
			}
			if r.Kind != tc.wantKind || r.Payload != tc.wantPay || r.Target != tc.wantTgt {
				t.Fatalf("got kind=%s payload=%q target=%q, want kind=%s payload=%q target=%q",
					r.Kind, r.Payload, r.Target, tc.wantKind, tc.wantPay, tc.wantTgt)
			}
			if r.NoResolve != tc.wantNoRe {
				t.Fatalf("NoResolve = %v, want %v", r.NoResolve, tc.wantNoRe)
			}
		})
	}
}

func TestParseRuleErrors(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "unknown kind", line: "DOMIAN,example.com,Proxy", want: "unknown rule type"},
		{name: "missing target", line: "DOMAIN,example.com", want: "no target"},
		{name: "empty field", line: "DOMAIN,,Proxy", want: "empty field"},
		{name: "extra fields", line: "DOMAIN,example.com,Proxy,extra", want: "too many fields"},
		{name: "final with payload", line: "FINAL,example.com,DIRECT", want: "only a target"},
		{name: "final missing target", line: "FINAL", want: "no target"},
		{name: "v6 in v4 rule", line: "IP-CIDR,2001:db8::/32,DIRECT", want: "IPv4"},
		{name: "v4 in v6 rule", line: "IP-CIDR6,10.0.0.0/8,DIRECT", want: "IPv6"},
		{name: "bad prefix", line: "IP-CIDR,10.0.0.0, DIRECT", want: "invalid prefix"},
		{name: "port zero", line: "DEST-PORT,0,Proxy", want: "invalid port"},
		{name: "port too large", line: "DEST-PORT,70000,Proxy", want: "invalid port"},
		{name: "port range reversed", line: "DEST-PORT,900-800,Proxy", want: "ends before it starts"},
		{name: "unknown protocol", line: "PROTOCOL,icmp,Proxy", want: "tcp and udp"},
		{name: "bad country", line: "GEOIP,CHN,DIRECT", want: "country code"},
		{name: "bad asn", line: "IP-ASN,AS-1,Proxy", want: "positive number"},
		{name: "no-resolve on domain", line: "DOMAIN,example.com,Proxy,no-resolve", want: "does not accept no-resolve"},
		{name: "bad target", line: "DOMAIN,example.com,Pro xy", want: "unsupported character"},
		{name: "empty domain", line: "DOMAIN,   ,Proxy", want: "empty field"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRule(tc.line)
			if err == nil {
				t.Fatalf("ParseRule(%q) succeeded, want an error", tc.line)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestRuleString(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"DOMAIN-SUFFIX,Example.COM,Proxy", "DOMAIN-SUFFIX,example.com,Proxy"},
		{"IP-CIDR,10.1.2.3/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"},
		{"FINAL,DIRECT", "FINAL,DIRECT"},
		{"DEST-PORT,8080-8080,Proxy", "DEST-PORT,8080,Proxy"},
	}
	for _, tc := range tests {
		r, err := ParseRule(tc.line)
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", tc.line, err)
		}
		if got := r.String(); got != tc.want {
			t.Errorf("ParseRule(%q).String() = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestKindHelpers(t *testing.T) {
	if _, ok := ParseKind("domain-suffix"); !ok {
		t.Error("ParseKind should be case insensitive")
	}
	if _, ok := ParseKind("bogus"); ok {
		t.Error("ParseKind accepted an unknown kind")
	}
	if KindDomain.Dimension() != DimensionName || KindIPCIDR.Dimension() != DimensionAddr {
		t.Error("dimension mapping is wrong")
	}
	if !KindRuleSet.IsSet() || KindDomain.IsSet() {
		t.Error("IsSet mapping is wrong")
	}
	if KindDomain.AllowsNoResolve() || !KindIPCIDR.AllowsNoResolve() {
		t.Error("AllowsNoResolve mapping is wrong")
	}
	if !KindFinal.Valid() {
		t.Error("FINAL should be valid")
	}
}
