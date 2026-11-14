//go:build linux

package sysproxy

// platform returns the proxy setting of this desktop. A desktop that does not
// answer to gsettings reports the failure when the setting is applied, which is
// where the reason can be reported with the rest of the startup problems.
func platform() Backend { return newGSettings(osRunner) }
