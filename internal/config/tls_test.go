package config

import (
	"strings"
	"testing"
)

// TestTLSOptionsAreReportedWithSectionAndLine checks that the shared TLS
// options are validated during configuration validation, in the same
// aggregated "[Proxy] line N: ..." shape as every other problem.
func TestTLSOptionsAreReportedWithSectionAndLine(t *testing.T) {
	in := `[General]
log-level = info

[Proxy]
Node = socks5, 127.0.0.1, 1080, sni=proxy.example

[Rule]
FINAL,DIRECT
`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	verr := cfg.Validate()
	if verr == nil {
		t.Fatal("a TLS option on a plaintext proxy type was accepted")
	}
	want := "[Proxy] line 5:"
	if !strings.Contains(verr.Error(), want) {
		t.Fatalf("error does not carry the section and line:\n%v", verr)
	}
	if !strings.Contains(verr.Error(), "not accepted by proxy type") {
		t.Fatalf("error does not explain the TLS mode:\n%v", verr)
	}
}

func TestTLSOptionsAcceptValidEntries(t *testing.T) {
	in := `[General]
log-level = info

[Proxy]
Secure = trojan, 203.0.113.9, 443, password=secret, sni=proxy.example, alpn=h2|http/1.1
Flexible = vmess, 203.0.113.10, 443, uuid=b831381d-6324-4d53-ad4f-8cda48b30811, tls=true, skip-cert-verify=false

[Rule]
FINAL,DIRECT
`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestTLSOptionsRejectDuplicatesAndBadValues(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "duplicate", line: "Node = trojan, 203.0.113.9, 443, password=x, sni=a.example, sni=b.example",
			want: "given twice"},
		{name: "bad toggle", line: "Node = vmess, 203.0.113.9, 443, uuid=x, tls=perhaps",
			want: "neither true nor false"},
		{name: "bad server name", line: "Node = trojan, 203.0.113.9, 443, password=x, sni=..example",
			want: "empty label"},
		{name: "bad protocol list", line: "Node = https, 203.0.113.9, 443, alpn=h2|",
			want: "empty entry"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := "[General]\nlog-level = info\n\n[Proxy]\n" + tc.line + "\n\n[Rule]\nFINAL,DIRECT\n"
			cfg, err := Parse([]byte(in))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			verr := cfg.Validate()
			if verr == nil || !strings.Contains(verr.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", verr, tc.want)
			}
			if !strings.Contains(verr.Error(), "[Proxy] line 5:") {
				t.Fatalf("error lost its section and line:\n%v", verr)
			}
		})
	}
}

// TestTLSKeysOnQUICProxies covers the two types whose transport is TLS by
// definition: the certificate keys apply, and tls= is refused because there is
// nothing to switch off.
func TestTLSKeysOnQUICProxies(t *testing.T) {
	accepted := `[General]
log-level = info

[Proxy]
HY = hysteria2, 203.0.113.20, 443, password=secret, sni=hy.example, skip-cert-verify=false
TU = tuic, 203.0.113.21, 443, uuid=b831381d-6324-4d53-ad4f-8cda48b30811, password=secret, sni=tu.example

[Rule]
FINAL,DIRECT
`
	cfg, err := Parse([]byte(accepted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	for _, line := range []string{
		"HY = hysteria2, 203.0.113.20, 443, password=secret, tls=true",
		"TU = tuic, 203.0.113.21, 443, uuid=b831381d-6324-4d53-ad4f-8cda48b30811, password=secret, tls=false",
	} {
		in := "[General]\nlog-level = info\n\n[Proxy]\n" + line + "\n\n[Rule]\nFINAL,DIRECT\n"
		cfg, err := Parse([]byte(in))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		verr := cfg.Validate()
		if verr == nil || !strings.Contains(verr.Error(), "tls= is not accepted") {
			t.Errorf("%s: error = %v, want a refusal of tls=", line, verr)
		}
	}
}
