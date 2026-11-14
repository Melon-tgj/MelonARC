//go:build windows

package inbound

import (
	"errors"
	"fmt"
	"syscall"
)

// The Windows route is a driver-backed adapter: packets are exchanged through
// ring buffers owned by the driver instead of a file descriptor. The procedure
// names below are the documented entry points of that driver; they are declared
// here, behind the windows build tag, so the rest of the package stays free of
// platform conditionals and a Windows build links cleanly.
//
// This build does not start a session yet: opening an adapter needs the driver
// installed and administrator rights, and neither can be verified in a Linux
// build environment. openDevice therefore reports exactly what is missing when
// the driver is unavailable. See DEVLOG stage 8: the Windows path is compiled,
// not validated on a real machine.
var wintunDLL = syscall.NewLazyDLL("wintun.dll")

var wintunProcs = [...]string{
	"WintunCreateAdapter",
	"WintunOpenAdapter",
	"WintunCloseAdapter",
	"WintunStartSession",
	"WintunEndSession",
	"WintunGetReadWaitEvent",
	"WintunReceivePacket",
	"WintunReleaseReceivePacket",
	"WintunAllocateSendPacket",
	"WintunSendPacket",
}

// errWintunUnavailable is the honest runtime answer on a machine without the
// driver. It is returned before any device state is created, so failing to open
// the TUN inbound leaves no adapter and no route behind.
var errWintunUnavailable = errors.New("inbound: the Windows TUN driver is not installed or this build cannot start a session")

func openDevice(cfg deviceConfig) (tunDevice, error) {
	if err := wintunDLL.Load(); err != nil {
		return nil, fmt.Errorf("%w: %v", errWintunUnavailable, err)
	}
	for _, name := range wintunProcs {
		if err := wintunDLL.NewProc(name).Find(); err != nil {
			return nil, fmt.Errorf("%w: %s is missing: %v", errWintunUnavailable, name, err)
		}
	}
	_ = cfg
	return nil, fmt.Errorf("%w: adapter sessions are not implemented in this build", errWintunUnavailable)
}
