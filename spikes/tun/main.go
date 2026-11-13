// Command tunspike validates the TUN data path end to end: open /dev/net/tun,
// create a TUN device, give it a test address, send a UDP datagram that the
// kernel routes into the device, then read it back and print an IP header
// summary.
//
// Two probe modes exist because the probe needs an egress path through the
// kernel's routing table:
//
//	default     send to 198.18.0.9, on-link for the device address
//	-loopback   route 127.0.0.9 out the device and send there
//
// The loopback mode rewrites the local 127.0.0.0/8 route and restores it on
// exit, so it must only be used inside a private network namespace. It exists
// for sandboxes that refuse to connect to anything outside 127.0.0.0/8.
//
// Creating a TUN device needs CAP_NET_ADMIN. On a normal host, run as root:
//
//	sudo ./tunspike
//
// In a container that keeps /dev/net/tun but drops CAP_NET_ADMIN from the
// bounding set, run it in a user plus network namespace instead:
//
//	unshare -Urn ./tunspike
//	unshare -Urn ./tunspike -loopback
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	devName   = "melonarc0"
	devAddr   = "198.18.0.1"
	devPrefix = 24
	probePort = 5300
	readWait  = 3 * time.Second

	naturalDst  = "198.18.0.9"
	loopbackDst = "127.0.0.9"
	loopbackNet = "127.0.0.0"
)

var loopbackProbe = flag.Bool("loopback", false,
	"route 127.0.0.9 into the device instead of 198.18.0.9 (rewrites the local 127.0.0.0/8 route; use only in a private netns)")

func main() {
	log.SetFlags(0)
	log.SetPrefix("tunspike: ")
	flag.Parse()
	if err := run(); err != nil {
		log.Fatalf("FAIL: %v", err)
	}
}

func run() error {
	fd, err := openTun(devName)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return fmt.Errorf("create %s: %w (CAP_NET_ADMIN required, try: unshare -Urn ./tunspike)", devName, err)
		}
		return fmt.Errorf("create %s: %w", devName, err)
	}
	defer unix.Close(fd)
	log.Printf("device %s created, fd=%d", devName, fd)

	ifi, err := net.InterfaceByName(devName)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", devName, err)
	}
	log.Printf("ifindex=%d mtu=%d", ifi.Index, ifi.MTU)

	if err := addAddr(ifi.Index, devAddr, devPrefix); err != nil {
		return fmt.Errorf("assign %s/%d: %w", devAddr, devPrefix, err)
	}
	if err := linkUp(ifi.Index); err != nil {
		return fmt.Errorf("bring up: %w", err)
	}
	log.Printf("address %s/%d assigned, link up", devAddr, devPrefix)

	// Install the on-link route for the probe explicitly instead of relying on
	// the one the kernel creates while assigning the address: on a
	// point-to-point interface that route is not always the prefix route.
	var dst string
	if *loopbackProbe {
		dst = loopbackDst
		restore, err := routeLoopbackInto(ifi.Index, dst)
		if err != nil {
			return fmt.Errorf("route %s into %s: %w", dst, devName, err)
		}
		defer restore()
		log.Printf("route %s/32 dev %s installed, local 127.0.0.0/8 route removed", dst, devName)
	} else {
		dst = naturalDst
		if err := addRoute(ifi.Index, devAddr, devPrefix); err != nil {
			return fmt.Errorf("add prefix route: %w", err)
		}
		log.Printf("route %s/%d dev %s installed", devAddr, devPrefix, devName)
	}

	if err := sendProbe(dst, probePort); err != nil {
		if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EPERM) {
			return fmt.Errorf("send probe to %s: %w (no usable egress path; retry with -loopback inside unshare -Urn)", dst, err)
		}
		return fmt.Errorf("send probe to %s: %w", dst, err)
	}
	log.Printf("probe datagram sent to %s:%d", dst, probePort)

	pkt, err := readPacket(fd, readWait)
	if err != nil {
		return err
	}
	return printHeader(pkt)
}

// openTun attaches to (and implicitly creates) a TUN interface and returns the
// file descriptor carrying raw IP packets. IFF_NO_PI keeps the 4-byte packet
// information prefix out of the way.
func openTun(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}

	var ifr struct {
		Name  [unix.IFNAMSIZ]byte
		Flags uint16
		_     [22]byte
	}
	copy(ifr.Name[:], name)
	ifr.Flags = unix.IFF_TUN | unix.IFF_NO_PI

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		unix.Close(fd)
		return -1, errno
	}
	return fd, nil
}

// addAddr adds an IPv4 address to the interface through rtnetlink.
func addAddr(index int, addr string, prefix uint8) error {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return fmt.Errorf("bad IPv4 address %q", addr)
	}

	payload := make([]byte, unix.SizeofIfAddrmsg)
	iva := (*unix.IfAddrmsg)(unsafe.Pointer(&payload[0]))
	iva.Family = unix.AF_INET
	iva.Prefixlen = prefix
	iva.Scope = unix.RT_SCOPE_UNIVERSE
	iva.Index = uint32(index)

	payload = appendAttr(payload, unix.IFA_LOCAL, ip)
	payload = appendAttr(payload, unix.IFA_ADDRESS, ip)

	return nlRequest(unix.RTM_NEWADDR,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL, payload)
}

// linkUp sets IFF_UP on the interface.
func linkUp(index int) error {
	payload := make([]byte, unix.SizeofIfInfomsg)
	ifi := (*unix.IfInfomsg)(unsafe.Pointer(&payload[0]))
	ifi.Family = unix.AF_UNSPEC
	ifi.Index = int32(index)
	ifi.Flags = unix.IFF_UP
	ifi.Change = unix.IFF_UP

	return nlRequest(unix.RTM_NEWLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK, payload)
}

// addRoute installs an on-link route for the device prefix.
func addRoute(index int, network string, prefix uint8) error {
	payload := routeMsg(net.ParseIP(network).To4(), prefix, unix.RT_TABLE_MAIN,
		unix.RT_SCOPE_LINK, unix.RTN_UNICAST, unix.RTPROT_BOOT, index)
	return nlRequest(unix.RTM_NEWROUTE,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE, payload)
}

// routeLoopbackInto points a single loopback address at the device. Because the
// kernel's local table owns all of 127.0.0.0/8, that route is removed first;
// the returned function puts it back.
func routeLoopbackInto(index int, addr string) (func(), error) {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return nil, fmt.Errorf("bad IPv4 address %q", addr)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return nil, err
	}
	// In a fresh network namespace the loopback interface is still down and
	// therefore has no 127.0.0.0/8 route; bring it up first.
	if err := linkUp(lo.Index); err != nil {
		return nil, fmt.Errorf("bring up lo: %w", err)
	}

	// Host route for the probe destination through the device.
	if err := nlRequest(unix.RTM_NEWROUTE,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE,
		routeMsg(ip, 32, unix.RT_TABLE_MAIN, unix.RT_SCOPE_LINK, unix.RTN_UNICAST, unix.RTPROT_BOOT, index)); err != nil {
		return func() {}, fmt.Errorf("add host route: %w", err)
	}

	// Release 127.0.0.0/8 from the local table so the lookup above can win.
	// A delete matches on the destination and table only, so scope, type and
	// protocol are left unspecified. A missing route is not an error.
	deleted := true
	err = nlRequest(unix.RTM_DELROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK,
		routeMsg(net.ParseIP(loopbackNet).To4(), 8, unix.RT_TABLE_LOCAL,
			unix.RT_SCOPE_NOWHERE, unix.RTN_UNSPEC, unix.RTPROT_UNSPEC, lo.Index))
	switch {
	case err == nil:
	case errors.Is(err, unix.ESRCH):
		deleted = false
	default:
		return func() {}, fmt.Errorf("remove local loopback route: %w", err)
	}

	restore := func() {
		if !deleted {
			return
		}
		err := nlRequest(unix.RTM_NEWROUTE,
			unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE,
			routeMsg(net.ParseIP(loopbackNet).To4(), 8, unix.RT_TABLE_LOCAL,
				unix.RT_SCOPE_HOST, unix.RTN_LOCAL, unix.RTPROT_BOOT, lo.Index))
		if err != nil {
			log.Printf("warning: restoring the local 127.0.0.0/8 route failed: %v", err)
		}
	}
	return restore, nil
}

// routeMsg builds an rtmsg with a destination and an optional output interface.
// The destination is masked to the prefix length, which the kernel requires.
// A protocol of RTPROT_UNSPEC makes the message a wildcard, which is what a
// delete needs.
func routeMsg(dst net.IP, prefix, table, scope, routeType, protocol uint8, oif int) []byte {
	payload := make([]byte, unix.SizeofRtMsg)
	rtm := (*unix.RtMsg)(unsafe.Pointer(&payload[0]))
	rtm.Family = unix.AF_INET
	rtm.Dst_len = prefix
	rtm.Table = table
	rtm.Protocol = protocol
	rtm.Scope = scope
	rtm.Type = routeType

	d4 := dst.To4()
	if d4 == nil {
		d4 = net.IPv4zero.To4()
	}
	if masked := d4.Mask(net.CIDRMask(int(prefix), 32)); masked != nil {
		d4 = masked.To4()
	}
	payload = appendAttr(payload, unix.RTA_DST, d4)

	if oif > 0 {
		var buf [4]byte
		*(*uint32)(unsafe.Pointer(&buf[0])) = uint32(oif)
		payload = appendAttr(payload, unix.RTA_OIF, buf[:])
	}
	return payload
}

// appendAttr appends one rtattr with 4-byte alignment. rtattr helpers are not
// exported by x/sys/unix, so the layout is spelled out here: u16 length,
// u16 type, then the payload, padded to a multiple of four bytes.
func appendAttr(buf []byte, typ uint16, data []byte) []byte {
	length := rtaLength(len(data))
	attr := make([]byte, rtaAlign(length))
	*(*uint16)(unsafe.Pointer(&attr[0])) = uint16(length)
	*(*uint16)(unsafe.Pointer(&attr[2])) = typ
	copy(attr[4:], data)
	return append(buf, attr...)
}

func rtaAlign(length int) int   { return (length + 3) &^ 3 }
func rtaLength(payload int) int { return 4 + payload }

// nlRequest sends one rtnetlink message and waits for its acknowledgement.
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
		off += rtaAlign(int(hdr.Len))

		if hdr.Type != unix.NLMSG_ERROR {
			continue
		}
		if len(data) < 4 {
			return errors.New("truncated netlink error message")
		}
		if code := int32(binary.LittleEndian.Uint32(data[:4])); code != 0 {
			return unix.Errno(-code)
		}
		return nil
	}
	return errors.New("netlink request got no acknowledgement")
}

// sendProbe emits one UDP datagram towards the probe destination. The socket is
// connected first and written to, rather than using sendto, because some
// sandboxes refuse unconnected sendto/sendmsg calls with EPERM.
func sendProbe(dst string, port int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var sa unix.SockaddrInet4
	sa.Port = port
	copy(sa.Addr[:], net.ParseIP(dst).To4())

	if err := unix.Connect(fd, &sa); err != nil {
		return err
	}
	_, err = unix.Write(fd, []byte("melonarc-tun-probe"))
	return err
}

// readPacket waits up to timeout for the first IPv4 packet on the TUN fd.
// Bringing a link up makes the kernel emit IPv6 auto-configuration traffic
// (MLD reports, router solicitations) on it, so non-IPv4 packets are skipped.
func readPacket(fd int, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65535)

	for {
		left := time.Until(deadline)
		if left <= 0 {
			return nil, fmt.Errorf("no packet read from %s within %s", devName, timeout)
		}
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfd, int(left.Milliseconds()))
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if n == 0 {
			continue
		}
		rn, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) {
				continue
			}
			return nil, err
		}
		if rn == 0 {
			continue
		}
		pkt := buf[:rn]
		if v := pkt[0] >> 4; v != 4 {
			log.Printf("skipped a non-IPv4 packet (version %d, %d bytes)", v, rn)
			continue
		}
		return pkt, nil
	}
}

// printHeader decodes the IPv4 header and prints the fields that matter for
// routing: source, destination and protocol number.
func printHeader(pkt []byte) error {
	if len(pkt) < 20 {
		return fmt.Errorf("short packet: %d bytes", len(pkt))
	}
	if version := pkt[0] >> 4; version != 4 {
		return fmt.Errorf("unexpected IP version %d", version)
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl {
		return fmt.Errorf("truncated IPv4 header: %d < %d", len(pkt), ihl)
	}

	fmt.Printf("packet: %d bytes captured (ip total length %d, ihl %d)\n",
		len(pkt), binary.BigEndian.Uint16(pkt[2:4]), ihl)
	fmt.Printf("  src=%s dst=%s proto=%d (%s)\n",
		net.IP(pkt[12:16]), net.IP(pkt[16:20]), pkt[9], protoName(pkt[9]))
	if pkt[9] == unix.IPPROTO_UDP && len(pkt) >= ihl+8 {
		fmt.Printf("  udp src=%d dst=%d payload=%q\n",
			binary.BigEndian.Uint16(pkt[ihl:ihl+2]),
			binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]),
			string(pkt[ihl+8:]))
	}
	fmt.Println("OK: read one packet from the TUN device")
	return nil
}

func protoName(p byte) string {
	switch p {
	case unix.IPPROTO_ICMP:
		return "icmp"
	case unix.IPPROTO_TCP:
		return "tcp"
	case unix.IPPROTO_UDP:
		return "udp"
	case unix.IPPROTO_ICMPV6:
		return "icmpv6"
	default:
		return "other"
	}
}
