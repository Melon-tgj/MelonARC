package config

import (
	"strings"
	"testing"
	"time"
)

const tunTestBase = `[General]
log-level = info
[Rule]
FINAL,DIRECT
`

func TestTUNIsOffByDefault(t *testing.T) {
	cfg, err := Parse([]byte(tunTestBase))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.General.TUN.Enable {
		t.Fatal("TUN must stay off unless tun-enable says otherwise")
	}
	if cfg.General.TUN.Name != "" || cfg.General.TUN.Address != "" || cfg.General.TUN.MTU != 0 {
		t.Fatalf("an off device has settings: %+v", cfg.General.TUN)
	}
}

func TestTUNDefaultsAreFilledOnEnable(t *testing.T) {
	cfg, err := Parse([]byte(`[General]
tun-enable = on
[Rule]
FINAL,DIRECT
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got := cfg.General.TUN
	if !got.Enable || got.Name != defaultTUNName || got.Address != defaultTUNAddress ||
		got.MTU != defaultTUNMTU || got.UDPTimeout != defaultTUNUDPTimeout {
		t.Fatalf("defaults = %+v", got)
	}
}

func TestTUNSettingsAreParsed(t *testing.T) {
	cfg, err := Parse([]byte(`[General]
tun-enable = yes
tun-name = arc0
tun-address = 10.9.0.1/24
tun-mtu = 1400
tun-route = 10.9.0.0/24, 198.18.1.0/24
tun-udp-timeout = 45
[Rule]
FINAL,DIRECT
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got := cfg.General.TUN
	if !got.Enable || got.Name != "arc0" || got.Address != "10.9.0.1/24" || got.MTU != 1400 {
		t.Fatalf("settings = %+v", got)
	}
	if len(got.Routes) != 2 || got.Routes[0] != "10.9.0.0/24" {
		t.Fatalf("routes = %v", got.Routes)
	}
	if got.UDPTimeout != 45*time.Second {
		t.Fatalf("udp timeout = %s", got.UDPTimeout)
	}
}

func TestTUNValidationRejectsBadSettings(t *testing.T) {
	cases := []struct {
		name  string
		lines string
		want  string
	}{
		{"settings while off", "tun-name = arc0\n", "tun-enable is off"},
		{"unknown switch", "tun-enable = maybe\n", "neither on nor off"},
		{"bad name", "tun-enable = on\ntun-name = bad/name\n", "tun-name"},
		{"long name", "tun-enable = on\ntun-name = abcdefghijklmnop\n", "tun-name"},
		{"bad address", "tun-enable = on\ntun-address = 198.18.0.1\n", "tun-address"},
		{"ipv6 address", "tun-enable = on\ntun-address = 2001:db8::1/64\n", "not IPv4"},
		{"loopback address", "tun-enable = on\ntun-address = 127.0.0.1/8\n", "tun-address"},
		{"mtu too small", "tun-enable = on\ntun-mtu = 100\n", "tun-mtu"},
		{"mtu too large", "tun-enable = on\ntun-mtu = 70000\n", "tun-mtu"},
		{"bad route", "tun-enable = on\ntun-route = not-a-route\n", "tun-route"},
		{"too many routes", "tun-enable = on\ntun-route = " + strings.Repeat("10.0.0.0/24,", maxTUNRoutes+1) + "\n", "more than"},
		{"zero timeout", "tun-enable = on\ntun-udp-timeout = 0\n", "tun-udp-timeout"},
		{"huge timeout", "tun-enable = on\ntun-udp-timeout = 48h\n", "tun-udp-timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := "[General]\n" + tc.lines + "[Rule]\nFINAL,DIRECT\n"
			cfg, err := Parse([]byte(text))
			if err != nil {
				return // a syntax error is already a rejection
			}
			err = cfg.Validate()
			if err == nil {
				t.Fatal("a bad TUN setting was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestTUNDefaultsAreIdempotent(t *testing.T) {
	cfg, err := Parse([]byte("[General]\ntun-enable = on\n[Rule]\nFINAL,DIRECT\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	first := cfg.General.TUN
	if err := cfg.Validate(); err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	again := cfg.General.TUN
	if first.Enable != again.Enable || first.Name != again.Name || first.Address != again.Address ||
		first.MTU != again.MTU || first.UDPTimeout != again.UDPTimeout || len(first.Routes) != len(again.Routes) {
		t.Fatalf("Validate changed the settings on a second run: %+v then %+v", first, again)
	}
}
