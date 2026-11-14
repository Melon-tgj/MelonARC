//go:build windows

package sysproxy

// platform returns the proxy setting of this machine.
func platform() Backend { return newRegistry(osRunner) }
