package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/rules"
)

const sampleConfig = `# MelonARC sample configuration
; both comment styles are accepted
[General]
log-level = debug
api-listen = 127.0.0.1:7946

[Proxy]
NodeA = ss, 203.0.113.10, 8388, aes-128-gcm, secret
NodeB = vmess, 203.0.113.11, 443, uuid=abc
NodeC = socks5, 127.0.0.1, 1080

[Proxy Group]
Proxy = select, NodeA, NodeB
Auto = url-test, NodeA, NodeB, url=http://example.com/probe, interval=120, tolerance=30
Backup = fallback, Auto, NodeC, url=https://example.com/probe

[Rule]
rule-set ads = ./rulesets/ads.txt
DOMAIN,api.example.com,Proxy
DOMAIN-SUFFIX,example.com,Proxy
RULE-SET,ads,REJECT
GEOIP,CN,DIRECT
DEST-PORT,8080,Proxy
FINAL,Proxy

[Host]
example.com = 203.0.113.5
cdn.example.com = 203.0.113.6, 203.0.113.7
`

func TestParseSample(t *testing.T) {
	cfg, err := Parse([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.General.LogLevel != "debug" || cfg.General.APIListen != "127.0.0.1:7946" {
		t.Fatalf("general = %+v", cfg.General)
	}
	if len(cfg.Proxies) != 3 {
		t.Fatalf("proxies = %d", len(cfg.Proxies))
	}
	a := cfg.Proxies[0]
	if a.Name != "NodeA" || a.Type != "ss" || a.Server != "203.0.113.10" || a.Port != 8388 {
		t.Fatalf("proxy A = %+v", a)
	}
	if len(a.Args) != 4 || a.Args[3] != "secret" {
		t.Fatalf("proxy A args = %v", a.Args)
	}
	if len(cfg.Groups) != 3 {
		t.Fatalf("groups = %d", len(cfg.Groups))
	}
	auto := cfg.Groups[1]
	if auto.Name != "Auto" || auto.Type != GroupURLTest {
		t.Fatalf("group = %+v", auto)
	}
	if auto.URL != "http://example.com/probe" || auto.Interval != 120*time.Second || auto.Tolerance != 30*time.Second {
		t.Fatalf("url-test settings = %+v", auto)
	}
	if auto.Timeout != defaultTimeout {
		t.Fatalf("timeout default = %v", auto.Timeout)
	}
	if len(cfg.RuleSets) != 1 || cfg.RuleSets[0].Name != "ads" || cfg.RuleSets[0].Path != "./rulesets/ads.txt" {
		t.Fatalf("rule sets = %+v", cfg.RuleSets)
	}
	if len(cfg.Rules) != 6 {
		t.Fatalf("rules = %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Kind != rules.KindDomain || cfg.Rules[5].Kind != rules.KindFinal {
		t.Fatalf("rule order = %v", cfg.Rules)
	}
	if cfg.Rules[5].Line != 24 {
		t.Fatalf("FINAL line = %d, want 24", cfg.Rules[5].Line)
	}
	if len(cfg.Hosts) != 2 || len(cfg.Hosts[1].Addrs) != 2 {
		t.Fatalf("hosts = %+v", cfg.Hosts)
	}
	if got, ok := cfg.HostByName("cdn.example.com"); !ok || !got[0].Equal(net.ParseIP("203.0.113.6")) {
		t.Fatalf("HostByName = %v, %v", got, ok)
	}
}

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse([]byte("[Rule]\nFINAL,DIRECT\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.General.LogLevel != defaultLogLevel || cfg.General.APIListen != defaultAPIListen {
		t.Fatalf("defaults = %+v", cfg.General)
	}
	if cfg.General.HTTPListen != defaultHTTPListen || cfg.General.SOCKS5Listen != defaultSOCKS5Listen {
		t.Fatalf("inbound defaults = %+v", cfg.General)
	}
	if cfg.General.SOCKS5Username != "" || cfg.General.SOCKS5Password != "" {
		t.Fatalf("authentication must be off by default: %+v", cfg.General)
	}
}

func TestParseInboundSettings(t *testing.T) {
	in := `[General]
http-listen = off
socks5-listen = 127.0.0.1:18081
socks5-username = alice
socks5-password = s3cret

[Rule]
FINAL,DIRECT
`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.General.HTTPListen != "" {
		t.Errorf("HTTPListen = %q, want the listener switched off", cfg.General.HTTPListen)
	}
	if cfg.General.SOCKS5Listen != "127.0.0.1:18081" {
		t.Errorf("SOCKS5Listen = %q", cfg.General.SOCKS5Listen)
	}
	if cfg.General.SOCKS5Username != "alice" || cfg.General.SOCKS5Password != "s3cret" {
		t.Errorf("credentials = %q, %q", cfg.General.SOCKS5Username, cfg.General.SOCKS5Password)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestParseSyntaxErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "entry before section", in: "log-level = info\n", want: "before any section"},
		{name: "unknown section", in: "[Bogus]\na = b\n", want: "unknown section"},
		{name: "malformed header", in: "[General\na = b\n", want: "malformed section header"},
		{name: "missing equals", in: "[General]\nlog-level info\n", want: "expected key = value"},
		{name: "unknown general key", in: "[General]\ncolour = red\n", want: "unknown setting"},
		{name: "duplicate general key", in: "[General]\nlog-level = info\nlog-level = debug\n", want: "already set"},
		{name: "duplicate proxy", in: "[Proxy]\nA = ss, 1.1.1.1, 80, x\nA = ss, 1.1.1.2, 80, x\n", want: "already defined"},
		{name: "duplicate group", in: "[Proxy Group]\nG = select, A\nG = select, A\n", want: "already defined"},
		{name: "bad rule", in: "[Rule]\nBOGUS,a,Proxy\n", want: "unknown rule type"},
		{name: "bad rule set declaration", in: "[Rule]\nrule-set ads\n", want: "expected rule-set"},
		{name: "bad host address", in: "[Host]\na.example.com = 300.1.1.1\n", want: "not an IP address"},
		{name: "missing host address", in: "[Host]\na.example.com =\n", want: "expected name = address"},
		{name: "unknown group option", in: "[Proxy Group]\nG = select, A, retries=3\n", want: "unknown option"},
		{name: "bad group interval", in: "[Proxy Group]\nG = url-test, A, url=http://x, interval=lots\n", want: "interval"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.in))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestParseAcceptsCarriageReturnsAndBOM(t *testing.T) {
	in := "\ufeff[General]\r\nlog-level = warn\r\n[Rule]\r\nFINAL,DIRECT\r\n"
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.General.LogLevel != "warn" || len(cfg.Rules) != 1 {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestParseQuotedValuesAndComments(t *testing.T) {
	in := "[Proxy]\nA = ss, 1.1.1.1, 80, \"pass word\" # trailing note\n" +
		"[Rule]\nFINAL,DIRECT ; trailing\n"
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.Proxies[0].Args[2]; got != "pass word" {
		t.Fatalf("quoted arg = %q", got)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].Target != "DIRECT" {
		t.Fatalf("rules = %v", cfg.Rules)
	}
}

func TestValidateSample(t *testing.T) {
	cfg, err := Parse([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if paths := cfg.RuleSetPaths(); paths["ads"] != "./rulesets/ads.txt" {
		t.Fatalf("RuleSetPaths = %v", paths)
	}
}

func TestValidateErrors(t *testing.T) {
	base := func(sections ...string) string { return strings.Join(sections, "\n\n") + "\n" }
	rule := func(lines ...string) string { return "[Rule]\n" + strings.Join(lines, "\n") }

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "no final",
			in:   rule("DOMAIN,a.example.com,DIRECT"),
			want: []string{"must end with FINAL"},
		},
		{
			name: "final not last",
			in:   rule("FINAL,DIRECT", "DOMAIN,a.example.com,DIRECT"),
			want: []string{"FINAL must be the last rule"},
		},
		{
			name: "duplicate final",
			in:   rule("FINAL,DIRECT", "FINAL,REJECT"),
			want: []string{"FINAL appears more than once"},
		},
		{
			name: "empty rule list",
			in:   "[General]\nlog-level = info\n",
			want: []string{"rule list is empty"},
		},
		{
			name: "unknown target",
			in:   rule("DOMAIN,a.example.com,NoSuchGroup", "FINAL,DIRECT"),
			want: []string{`unknown policy or outbound "NoSuchGroup"`},
		},
		{
			name: "undeclared rule set",
			in:   rule("RULE-SET,missing,REJECT", "FINAL,DIRECT"),
			want: []string{`undeclared rule set "missing"`},
		},
		{
			name: "api on all interfaces",
			in:   base("[General]\napi-listen = 0.0.0.0:7946", rule("FINAL,DIRECT")),
			want: []string{"not a loopback address"},
		},
		{
			name: "api without port",
			in:   base("[General]\napi-listen = 127.0.0.1", rule("FINAL,DIRECT")),
			want: []string{"must be host:port"},
		},
		{
			name: "api port zero",
			in:   base("[General]\napi-listen = 127.0.0.1:0", rule("FINAL,DIRECT")),
			want: []string{"fixed port"},
		},
		{
			name: "bad log level",
			in:   base("[General]\nlog-level = verbose", rule("FINAL,DIRECT")),
			want: []string{"not one of debug, info, warn, error"},
		},
		{
			name: "http inbound on all interfaces",
			in:   base("[General]\nhttp-listen = 0.0.0.0:7890", rule("FINAL,DIRECT")),
			want: []string{"http-listen", "not a loopback address"},
		},
		{
			name: "socks5 inbound on a lan address",
			in:   base("[General]\nsocks5-listen = 192.168.1.10:7891", rule("FINAL,DIRECT")),
			want: []string{"socks5-listen", "not a loopback address"},
		},
		{
			name: "inbound without port",
			in:   base("[General]\nhttp-listen = 127.0.0.1", rule("FINAL,DIRECT")),
			want: []string{"http-listen", "must be host:port"},
		},
		{
			name: "inbound port zero",
			in:   base("[General]\nsocks5-listen = 127.0.0.1:0", rule("FINAL,DIRECT")),
			want: []string{"socks5-listen", "fixed port"},
		},
		{
			name: "username without password",
			in:   base("[General]\nsocks5-username = alice", rule("FINAL,DIRECT")),
			want: []string{"socks5-username is set without socks5-password"},
		},
		{
			name: "password without username",
			in:   base("[General]\nsocks5-password = s3cret", rule("FINAL,DIRECT")),
			want: []string{"socks5-password is set without socks5-username"},
		},
		{
			name: "credentials with the listener off",
			in:   base("[General]\nsocks5-listen = off\nsocks5-username = alice\nsocks5-password = s3cret", rule("FINAL,DIRECT")),
			want: []string{"socks5-listen is off"},
		},
		{
			name: "credential longer than one byte of length",
			in: base("[General]\nsocks5-username = "+strings.Repeat("a", 256)+
				"\nsocks5-password = s3cret", rule("FINAL,DIRECT")),
			want: []string{"limited to 255 bytes"},
		},
		{
			name: "unknown proxy type",
			in:   base("[Proxy]\nA = wireguard, 1.1.1.1, 80", rule("FINAL,DIRECT")),
			want: []string{`unknown type "wireguard"`},
		},
		{
			name: "proxy without port",
			in:   base("[Proxy]\nA = ss, 1.1.1.1", rule("FINAL,DIRECT")),
			want: []string{"needs a port"},
		},
		{
			name: "proxy without server",
			in:   base("[Proxy]\nA = ss", rule("FINAL,DIRECT")),
			want: []string{"has no server"},
		},
		{
			name: "reserved name",
			in:   base("[Proxy]\nDIRECT = ss, 1.1.1.1, 80", rule("FINAL,DIRECT")),
			want: []string{"reserved target"},
		},
		{
			name: "group unknown member",
			in:   base("[Proxy Group]\nG = select, Nope", rule("FINAL,G")),
			want: []string{`unknown member "Nope"`},
		},
		{
			name: "group lists itself",
			in:   base("[Proxy Group]\nG = select, G", rule("FINAL,G")),
			want: []string{"lists itself"},
		},
		{
			name: "group cycle",
			in: base("[Proxy Group]\nA = select, B\nB = select, C\nC = select, A",
				rule("FINAL,DIRECT")),
			want: []string{"policy group cycle: A -> B -> C -> A"},
		},
		{
			name: "url-test without url",
			in:   base("[Proxy Group]\nG = url-test, DIRECT", rule("FINAL,G")),
			want: []string{"needs url="},
		},
		{
			name: "url-test with bad url",
			in:   base("[Proxy Group]\nG = url-test, DIRECT, url=example.com", rule("FINAL,G")),
			want: []string{"not an absolute URL"},
		},
		{
			name: "group duplicates a proxy name",
			in: base("[Proxy]\nA = ss, 1.1.1.1, 80",
				"[Proxy Group]\nA = select, DIRECT", rule("FINAL,A")),
			want: []string{"same name as a proxy"},
		},
		{
			name: "group without members",
			in:   base("[Proxy Group]\nG = select", rule("FINAL,G")),
			want: []string{"has no members"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tc.in))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			verr := cfg.Validate()
			if verr == nil {
				t.Fatal("expected a validation error")
			}
			for _, want := range tc.want {
				if !strings.Contains(verr.Error(), want) {
					t.Errorf("error does not mention %q:\n%v", want, verr)
				}
			}
		})
	}
}

func TestValidationCollectsEveryProblem(t *testing.T) {
	in := `[General]
api-listen = 0.0.0.0:7946
log-level = loud

[Proxy]
A = bogus, 1.1.1.1, 99999

[Rule]
DOMAIN,a.example.com,Nope
FINAL,DIRECT
`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected errors")
	}
	got := err.(*Errors).Issues
	if len(got) < 4 {
		t.Fatalf("expected at least 4 issues, got %d:\n%v", len(got), err)
	}
	text := err.Error()
	for _, want := range []string{"loopback", "log-level", "unknown type", "needs a port", `"Nope"`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
}

func TestBuiltinTargetsAreCaseInsensitive(t *testing.T) {
	in := "[Rule]\nDOMAIN,a.example.com,direct\nFINAL,reject\n"
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.Rules[0].Target != TargetDirect || cfg.Rules[1].Target != TargetReject {
		t.Fatalf("targets = %q, %q", cfg.Rules[0].Target, cfg.Rules[1].Target)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	if err := os.WriteFile(path, []byte(sampleConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Path != path {
		t.Errorf("Path = %q, want %q", cfg.Path, path)
	}
	if cfg.BaseDir != dir {
		t.Errorf("BaseDir = %q, want %q", cfg.BaseDir, dir)
	}
	if _, err := Load(filepath.Join(dir, "missing.conf")); err == nil {
		t.Error("Load should fail for a missing file")
	}
}

func TestLoadPropagatesValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	if err := os.WriteFile(path, []byte("[Rule]\nDOMAIN,a.example.com,DIRECT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err == nil {
		t.Fatal("expected a validation error for a missing FINAL")
	}
	if cfg == nil {
		t.Fatal("Load should return the parsed configuration alongside the error")
	}
}

func TestSectionNamesAreCaseInsensitive(t *testing.T) {
	cfg, err := Parse([]byte("[general]\nlog-level = error\n[PROXY GROUP]\nG = select, DIRECT\n[rule]\nFINAL,G\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.General.LogLevel != "error" || len(cfg.Groups) != 1 {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestGroupDefaults(t *testing.T) {
	cfg, err := Parse([]byte("[Proxy Group]\nG = select, DIRECT\n[Rule]\nFINAL,G\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	g := cfg.Groups[0]
	if g.Interval != defaultInterval || g.Timeout != defaultTimeout || g.Tolerance != defaultTolerance {
		t.Fatalf("defaults = %+v", g)
	}
}
