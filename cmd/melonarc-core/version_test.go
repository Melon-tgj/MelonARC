package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melon-tgj/melonarc/internal/version"
)

// The version a build reports lives in one place. This drives the real -check
// path (the cheapest way to observe it without starting a daemon) after putting
// a known value there, which is what a release build does with -X.
func TestCheckReportsTheSharedVersion(t *testing.T) {
	original := version.Version
	version.Version = "9.9.9-test"
	t.Cleanup(func() { version.Version = original })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "melonarc.ini")
	raw := `[General]
log-level = error
http-listen = off
socks5-listen = off
data-dir = ./state

[Rule]
FINAL,DIRECT
`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}

	var runErr error
	out := captureStdout(t, func() { runErr = run([]string{"-config", cfgPath, "-check"}) })
	if runErr != nil {
		t.Fatalf("-check: %v", runErr)
	}
	if !strings.Contains(out, "melonarc-core 9.9.9-test") {
		t.Fatalf("-check does not report the shared version:\n%s", out)
	}
}
