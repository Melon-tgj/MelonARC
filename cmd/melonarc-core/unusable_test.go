package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/melon-tgj/melonarc/internal/config"
)

// captureLogger records what the assembly layer logs, so "the daemon warns" is
// a fact a test can read rather than a claim about a line of code.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	buf := new(bytes.Buffer)
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func TestUnusableProtocolsWarnAtLoad(t *testing.T) {
	cases := []struct {
		name     string
		proxies  []config.Proxy
		warns    int
		wantText []string
	}{
		{
			name: "hysteria2 and tuic both warn",
			proxies: []config.Proxy{
				{Name: "Hy", Type: "hysteria2", Server: "203.0.113.10", Port: 443},
				{Name: "Tu", Type: "tuic", Server: "203.0.113.11", Port: 443},
			},
			warns:    2,
			wantText: []string{"proxy=Hy", "type=hysteria2", "proxy=Tu", "type=tuic", "not been re-verified"},
		},
		{
			name: "the type is matched like New matches it",
			proxies: []config.Proxy{
				{Name: "Hy", Type: " Hysteria2 ", Server: "203.0.113.10", Port: 443},
			},
			warns:    1,
			wantText: []string{"proxy=Hy", "type=hysteria2"},
		},
		{
			name: "a supported protocol does not warn",
			proxies: []config.Proxy{
				{Name: "NodeA", Type: "ss", Server: "203.0.113.10", Port: 8388},
				{Name: "NodeB", Type: "vless", Server: "203.0.113.11", Port: 443},
				{Name: "NodeC", Type: "socks5", Server: "127.0.0.1", Port: 1080},
			},
			warns: 0,
		},
		{
			name:  "no proxies at all",
			warns: 0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logger, buf := captureLogger()
			warnUnusableProtocols(&config.Config{Proxies: c.proxies}, logger)

			lines := strings.Count(buf.String(), "level=WARN")
			if lines != c.warns {
				t.Fatalf("warnings = %d, want %d; log:\n%s", lines, c.warns, buf.String())
			}
			for _, want := range c.wantText {
				if !strings.Contains(buf.String(), want) {
					t.Fatalf("log does not mention %q:\n%s", want, buf.String())
				}
			}
		})
	}
}

// The warning is a message about a node, not about a credential: the log of a
// daemon is routinely pasted into a report.
func TestUnusableProtocolWarningCarriesNoCredentials(t *testing.T) {
	logger, buf := captureLogger()
	warnUnusableProtocols(&config.Config{Proxies: []config.Proxy{
		{
			Name:   "Hy",
			Type:   "hysteria2",
			Server: "203.0.113.10",
			Port:   443,
			Args:   []string{"203.0.113.10", "443", "password=hunter2"},
		},
	}}, logger)

	if strings.Contains(buf.String(), "hunter2") {
		t.Fatalf("the warning repeats a credential:\n%s", buf.String())
	}
}
