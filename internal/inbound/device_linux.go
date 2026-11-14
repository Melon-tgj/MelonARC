//go:build linux

package inbound

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// linuxDevice is a /dev/net/tun file descriptor. Reads use a short poll rather
// than a blocking read so Close can interrupt the packet loop without waiting
// for the next packet; a 200ms idle tick returns (0, nil), which the loop treats
// as "nothing arrived".
type linuxDevice struct {
	mu     sync.Mutex
	fd     int
	name   string
	mtu    int
	closed bool
}

const devicePollWaitMS = 200

func openDevice(cfg deviceConfig) (tunDevice, error) {
	if cfg.Name == "" {
		return nil, errors.New("inbound: a TUN device name is required")
	}
	if len(cfg.Name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("inbound: TUN device name %q is longer than %d bytes", cfg.Name, unix.IFNAMSIZ-1)
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("inbound: open the TUN device: %w (CAP_NET_ADMIN is required)", err)
	}
	dev := &linuxDevice{fd: fd, name: cfg.Name, mtu: cfg.MTU}
	ok := false
	defer func() {
		if !ok {
			_ = dev.Close()
		}
	}()

	var ifr struct {
		Name  [unix.IFNAMSIZ]byte
		Flags uint16
		_     [22]byte
	}
	copy(ifr.Name[:], cfg.Name)
	ifr.Flags = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return nil, fmt.Errorf("inbound: create %s: %w (CAP_NET_ADMIN is required)", cfg.Name, errno)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("inbound: make %s non-blocking: %w", cfg.Name, err)
	}

	ifi, err := net.InterfaceByName(cfg.Name)
	if err != nil {
		return nil, fmt.Errorf("inbound: look up %s: %w", cfg.Name, err)
	}
	addr, network, err := net.ParseCIDR(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("inbound: TUN address %q: %w", cfg.Address, err)
	}
	if addr.To4() == nil {
		return nil, fmt.Errorf("inbound: TUN address %q is not IPv4", cfg.Address)
	}
	prefix, _ := network.Mask.Size()

	if err := addIPv4Address(ifi.Index, addr.To4(), uint8(prefix)); err != nil {
		return nil, fmt.Errorf("inbound: assign %s: %w", cfg.Address, err)
	}
	if err := setLinkUp(ifi.Index, cfg.MTU); err != nil {
		return nil, fmt.Errorf("inbound: bring up %s: %w", cfg.Name, err)
	}
	for _, route := range cfg.Routes {
		ip, netw, err := net.ParseCIDR(route)
		if err != nil {
			return nil, fmt.Errorf("inbound: TUN route %q: %w", route, err)
		}
		if ip.To4() == nil {
			return nil, fmt.Errorf("inbound: TUN route %q is not IPv4", route)
		}
		bits, _ := netw.Mask.Size()
		if err := addRoute(ifi.Index, netw.IP.To4(), uint8(bits)); err != nil {
			return nil, fmt.Errorf("inbound: install route %s: %w", route, err)
		}
	}
	ok = true
	return dev, nil
}

func (d *linuxDevice) Name() string { return d.name }
func (d *linuxDevice) MTU() int     { return d.mtu }

func (d *linuxDevice) Read(p []byte) (int, error) {
	for {
		d.mu.Lock()
		fd, closed := d.fd, d.closed
		d.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfd, devicePollWaitMS)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, nil
		}
		rn, err := unix.Read(fd, p)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			return 0, nil
		}
		return rn, err
	}
}

func (d *linuxDevice) Write(p []byte) (int, error) {
	for {
		d.mu.Lock()
		fd, closed := d.fd, d.closed
		d.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		n, err := unix.Write(fd, p)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
			_, _ = unix.Poll(pfd, devicePollWaitMS)
			continue
		}
		return n, err
	}
}

func (d *linuxDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return unix.Close(d.fd)
}

// addIPv4Address assigns the device address over rtnetlink.
func addIPv4Address(index int, addr net.IP, prefix uint8) error {
	payload := make([]byte, unix.SizeofIfAddrmsg)
	msg := (*unix.IfAddrmsg)(unsafe.Pointer(&payload[0]))
	msg.Family = unix.AF_INET
	msg.Prefixlen = prefix
	msg.Scope = unix.RT_SCOPE_UNIVERSE
	msg.Index = uint32(index)
	payload = appendAttr(payload, unix.IFA_LOCAL, addr)
	payload = appendAttr(payload, unix.IFA_ADDRESS, addr)
	return nlRequest(unix.RTM_NEWADDR,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL, payload)
}

// setLinkUp sets IFF_UP and the MTU in one netlink request.
func setLinkUp(index, mtu int) error {
	payload := make([]byte, unix.SizeofIfInfomsg)
	msg := (*unix.IfInfomsg)(unsafe.Pointer(&payload[0]))
	msg.Family = unix.AF_UNSPEC
	msg.Index = int32(index)
	msg.Flags = unix.IFF_UP
	msg.Change = unix.IFF_UP

	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(mtu))
	payload = appendAttr(payload, unix.IFLA_MTU, buf[:])
	return nlRequest(unix.RTM_NEWLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK, payload)
}

// addRoute installs an on-link route for one prefix. The destination is masked
// to the prefix length because the kernel rejects a host address in a prefix
// route with EINVAL.
func addRoute(index int, network net.IP, prefix uint8) error {
	payload := make([]byte, unix.SizeofRtMsg)
	msg := (*unix.RtMsg)(unsafe.Pointer(&payload[0]))
	msg.Family = unix.AF_INET
	msg.Dst_len = prefix
	msg.Table = unix.RT_TABLE_MAIN
	msg.Protocol = unix.RTPROT_BOOT
	msg.Scope = unix.RT_SCOPE_LINK
	msg.Type = unix.RTN_UNICAST

	dst := network.To4()
	if masked := dst.Mask(net.CIDRMask(int(prefix), 32)); masked != nil {
		dst = masked.To4()
	}
	payload = appendAttr(payload, unix.RTA_DST, dst)
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(index))
	payload = appendAttr(payload, unix.RTA_OIF, buf[:])
	return nlRequest(unix.RTM_NEWROUTE,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE, payload)
}

// appendAttr appends one rtattr with four-byte alignment. The layout is spelled
// out because the x/sys/unix package does not export an encoder for it.
func appendAttr(buf []byte, typ uint16, data []byte) []byte {
	length := 4 + len(data)
	attr := make([]byte, (length+3)&^3)
	binary.LittleEndian.PutUint16(attr[0:2], uint16(length))
	binary.LittleEndian.PutUint16(attr[2:4], typ)
	copy(attr[4:], data)
	return append(buf, attr...)
}

// nlRequest sends one rtnetlink message and waits for its acknowledgement. A
// fresh socket per request keeps the sequence number and the reply simple.
func nlRequest(msgType, flags uint16, payload []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
		return err
	}

	total := unix.NLMSG_HDRLEN + len(payload)
	msg := make([]byte, total)
	hdr := (*unix.NlMsghdr)(unsafe.Pointer(&msg[0]))
	hdr.Len = uint32(total)
	hdr.Type = msgType
	hdr.Flags = flags
	hdr.Seq = 1
	copy(msg[unix.NLMSG_HDRLEN:], payload)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	for off := 0; off+unix.NLMSG_HDRLEN <= n; {
		hdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[off]))
		if hdr.Len < unix.NLMSG_HDRLEN || off+int(hdr.Len) > n {
			break
		}
		data := buf[off+unix.NLMSG_HDRLEN : off+int(hdr.Len)]
		off += (int(hdr.Len) + 3) &^ 3
		if hdr.Type != unix.NLMSG_ERROR {
			continue
		}
		if len(data) < 4 {
			return errors.New("inbound: truncated netlink error message")
		}
		if code := int32(binary.LittleEndian.Uint32(data[:4])); code != 0 {
			return unix.Errno(-code)
		}
		return nil
	}
	return errors.New("inbound: netlink request got no acknowledgement")
}
