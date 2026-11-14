//go:build !linux && !windows

package inbound

import "errors"

// openDevice is the fallback for platforms this stage does not implement. The
// TUN inbound is off by default, and a configuration that turns it on gets a
// clear startup error instead of a silent no-op.
func openDevice(deviceConfig) (tunDevice, error) {
	return nil, errors.New("inbound: a TUN device is only implemented for Linux and Windows builds")
}
