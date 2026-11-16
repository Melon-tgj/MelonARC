package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/outbound"
)

// captureLogger records what the assembly layer logs, so "a warning was
// emitted" is a fact a test can read rather than a claim about a line of code.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	buf := new(bytes.Buffer)
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

// No protocol this build implements is on the unusable list any more, so no
// configuration produces the warning — including the two types that carried it
// until the 2026-11-16 CI re-run. The warning is a statement about the support
// matrix; with nothing in the Unusable row, there is nothing to say.
func TestUnusableProtocolsWarnAtLoad(t *testing.T) {
	cases := []struct {
		name    string
		proxies []config.Proxy
	}{
		{
			name: "the two formerly listed protocols",
			proxies: []config.Proxy{
				{Name: "a1", Type: "hysteria2", Server: "203.0.113.10", Port: 443},
				{Name: "a2", Type: "tuic", Server: "203.0.113.10", Port: 443},
			},
		},
		{
			name: "one of them in mixed case",
			proxies: []config.Proxy{
				{Name: "b1", Type: "Hysteria2", Server: "203.0.113.10", Port: 443},
			},
		},
		{
			name: "protocols that were never listed",
			proxies: []config.Proxy{
				{Name: "c1", Type: "ss", Server: "203.0.113.10", Port: 8388},
				{Name: "c2", Type: "vless", Server: "203.0.113.10", Port: 443},
				{Name: "c3", Type: "socks5", Server: "203.0.113.10", Port: 1080},
			},
		},
		{
			name: "an empty configuration",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logger, buf := captureLogger()
			warnUnusableProtocols(&config.Config{Proxies: c.proxies}, logger)

			if warnings := strings.Count(buf.String(), "level=WARN"); warnings != 0 {
				t.Fatalf("got %d warnings with an empty unusable list: %s", warnings, buf.String())
			}
			if buf.Len() != 0 {
				t.Fatalf("the load path logged something: %s", buf.String())
			}
		})
	}
}

// The mechanism is kept, and it is kept honest: it names the node, the protocol
// and the reason, and it never repeats an argument of that node. Args carry the
// credentials of a real configuration, and a daemon log is routinely pasted into
// a report.
//
// The entry is handed in because the shipped list is empty; "hysteria2" here is
// the entry that list carried until the 2026-11-16 CI re-run, not a claim about
// this build.
func TestUnusableProtocolWarningCarriesOnlyTheNodeAndTheReason(t *testing.T) {
	const sentinel = "argument-must-not-be-logged"

	logger, buf := captureLogger()
	warnUnusable(&config.Config{Proxies: []config.Proxy{
		{
			Name:   "listed",
			Type:   "Hysteria2",
			Server: "203.0.113.10",
			Port:   443,
			Args:   []string{"obfs", sentinel},
		},
		{Name: "not-listed", Type: "vless", Server: "203.0.113.11", Port: 443},
	}}, logger, func(typ string) (outbound.Unusable, bool) {
		if !strings.EqualFold(strings.TrimSpace(typ), "hysteria2") {
			return outbound.Unusable{}, false
		}
		return outbound.Unusable{Protocol: "hysteria2", Reason: "test entry"}, true
	})

	if warnings := strings.Count(buf.String(), "level=WARN"); warnings != 1 {
		t.Fatalf("got %d warnings, want 1: %s", warnings, buf.String())
	}
	out := buf.String()
	for _, want := range []string{"proxy=listed", "type=hysteria2", "test entry"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the warning does not carry %q: %s", want, out)
		}
	}
	if strings.Contains(out, "proxy=not-listed") {
		t.Fatalf("a protocol that is not on the list was reported: %s", out)
	}
	if strings.Contains(out, sentinel) {
		t.Fatalf("the warning repeated a node argument: %s", out)
	}
}
