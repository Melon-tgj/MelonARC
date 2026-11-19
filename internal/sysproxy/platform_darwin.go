//go:build darwin

package sysproxy

// platform returns the proxy setting of this desktop, one per network service.
//
// It is written through /usr/sbin/networksetup with the privileges the process
// already has. The daemon and the window are never root and never install a
// privileged helper: a machine that requires authorisation for a change shows
// its own dialog, and a refused change is reported rather than retried.
func platform() Backend { return newNetworkSetup(osRunner) }
