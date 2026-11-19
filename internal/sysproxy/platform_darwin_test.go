//go:build darwin

package sysproxy

import "testing"

// TestPlatformIsTheNetworkSetupBackend checks the wiring of a darwin build: the
// controller must not fall back to the backend that refuses every write, which
// is what the machine had before this stage.
//
// It runs on macOS only. The build that added the backend cross-compiled the
// test binary instead, so the first run on a Mac is the real check.
func TestPlatformIsTheNetworkSetupBackend(t *testing.T) {
	if got := platform().Name(); got != "networksetup" {
		t.Errorf("platform() is %q, want networksetup", got)
	}
}
