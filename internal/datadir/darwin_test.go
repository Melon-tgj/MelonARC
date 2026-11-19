//go:build darwin

package datadir

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultMatchesTheShellOnMacOS checks the path both sides compute for
// themselves: the window derives its data directory from the settings file's
// parent under `~/Library/Application Support`, and the core asks the standard
// library for the same directory. The two only meet if this holds.
//
// It is a darwin test because the answer comes from the platform, so it cannot
// run in the Linux build of the suite. The stage that added it cross-compiled
// the test binary and could not run it; the first run on a Mac is the real
// check.
func TestDefaultMatchesTheShellOnMacOS(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("this environment has no home directory: %v", err)
	}
	got, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	want := filepath.Join(home, "Library", "Application Support", DefaultDirName)
	if got != want {
		t.Errorf("Default() = %q, want %q", got, want)
	}
}
