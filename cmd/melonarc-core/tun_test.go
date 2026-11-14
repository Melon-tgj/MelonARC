package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/config"
)

func tunConfig(t *testing.T, lines string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte("[General]\n" + lines + "[Rule]\nFINAL,DIRECT\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return cfg
}

// TestStartTUNStaysOffByDefault proves that a configuration from an earlier
// stage never opens a device (and never needs the capabilities to do so).
func TestStartTUNStaysOffByDefault(t *testing.T) {
	cfg := tunConfig(t, "")
	srv, err := startTUN(cfg.General, nil, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("startTUN with the device off: %v", err)
	}
	if srv != nil {
		t.Cleanup(func() { _ = srv.Close(context.Background()) })
		t.Fatal("startTUN opened a device although tun-enable is off")
	}
}

func TestConfigViewReportsTUNSettings(t *testing.T) {
	off := tunConfig(t, "")
	view := (&daemonState{cfg: off}).Config(context.Background())
	if view.TUNEnable || view.TUNName != "" || view.TUNAddress != "" || view.TUNMTU != 0 {
		t.Fatalf("an off device is reported as %+v", view)
	}

	on := tunConfig(t, "tun-enable = on\ntun-name = arc0\ntun-route = 10.9.0.0/24, 198.18.1.0/24\n")
	view = (&daemonState{cfg: on}).Config(context.Background())
	if !view.TUNEnable || view.TUNName != "arc0" || view.TUNAddress != "198.18.0.1/24" ||
		view.TUNMTU != 1500 || len(view.TUNRoutes) != 2 {
		t.Fatalf("a configured device is reported as %+v", view)
	}
}

func TestRestartRequiredNamesEveryTUNSetting(t *testing.T) {
	previous := tunConfig(t, "").General
	next := tunConfig(t, "tun-enable = on\n").General
	next.TUN.Name = "other0"
	next.TUN.Address = "10.9.0.1/24"
	next.TUN.MTU = 1400
	next.TUN.Routes = []string{"10.9.0.0/24"}
	next.TUN.UDPTimeout = 45 * time.Second

	got := strings.Join(restartRequired(previous, next), ",")
	for _, setting := range []string{
		"tun-enable", "tun-name", "tun-address", "tun-mtu", "tun-route", "tun-udp-timeout",
	} {
		if !strings.Contains(got, setting) {
			t.Fatalf("restartRequired = %q, missing %q", got, setting)
		}
	}
	if unchanged := restartRequired(next, next); len(unchanged) != 0 {
		t.Fatalf("an unchanged configuration needs a restart: %v", unchanged)
	}
}

func TestTUNSummaryReportsTheDevice(t *testing.T) {
	cfg := tunConfig(t, "tun-enable = on\n")
	if note := tunNote(cfg.General); !strings.Contains(note, "melonarc0") ||
		!strings.Contains(note, "198.18.0.1/24") || !strings.Contains(note, "mtu 1500") {
		t.Fatalf("tunNote = %q", note)
	}
	if note := tunNote(tunConfig(t, "").General); note != "off" {
		t.Fatalf("tunNote for an off device = %q", note)
	}
}
